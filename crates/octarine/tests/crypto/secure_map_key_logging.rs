//! `SecureMap` must never emit map keys in cleartext (issue #735).
//!
//! `SecureMap` zeroizes and redacts stored *values*, which leads operators to
//! treat it as safe for compliance logging. Before this test, `insert`,
//! `remove`, and `Drop::drop` interpolated the raw *key* into `observe::debug`
//! messages, so any context carried in a key name (tenant, user ID, hostname)
//! reached every configured writer at DEBUG.
//!
//! This test drives real operations through the live observe pipeline and
//! asserts on what actually reaches a registered writer. Three details make it
//! a real test rather than a vacuous one:
//!
//! 1. `CaptureWriter::severity_filter` returns `SeverityFilter::all()`. The
//!    `Writer` default is `SeverityFilter::production()`, which **drops Debug
//!    events** — without this override the capture is empty and every
//!    "raw key absent" assertion would pass for the wrong reason.
//! 2. Assertions check the digest is **present** as well as the raw key being
//!    **absent**. Absence alone would still hold if the logging were deleted
//!    outright, or if capture silently broke.
//! 3. The marker key is deliberately opaque (not PII-shaped). Every message
//!    runs through `scan_and_redact`, so a PII-shaped key would be redacted by
//!    the pipeline and the absence assertion would again pass for the wrong
//!    reason.
//!
//! Delivery is asynchronous (the global dispatcher forwards to writers), so
//! assertions poll rather than sleep a fixed amount — see
//! `octarine-test-resilience`. Events are filtered by a unique per-test marker
//! so the test is correct whether run process-per-test (nextest) or
//! many-per-process (`cargo test`).

#![allow(clippy::panic, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use octarine::crypto::secrets::SecureMap;
use octarine::observe::Event;
use octarine::observe::writers::{
    DispatcherConfig, MemoryWriter, SeverityFilter, Writer, WriterError, WriterHealthStatus,
    configure_dispatcher, register_writer, unregister_writer,
};

const POLL_DEADLINE: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Opaque, non-PII key fragment unique to this test. Must not look like an
/// email/SSN/etc, or the PII redactor would strip it from messages and the
/// absence assertion below would pass regardless of the fix.
const MARKER_KEY: &str = "zzkey735c0ffee";

/// Hex length the implementation truncates key digests to. Mirrors
/// `KEY_DIGEST_HEX_LEN` in `crypto/secrets/map.rs`.
const DIGEST_HEX_LEN: usize = 12;

/// First `DIGEST_HEX_LEN` hex chars of `blake3(MARKER_KEY)` — the digest the
/// implementation is expected to log in place of the raw key. Recomputed here
/// rather than hardcoded, so the test tracks the helper.
fn expected_digest() -> String {
    let mut hex = blake3::hash(MARKER_KEY.as_bytes()).to_hex().to_string();
    hex.truncate(DIGEST_HEX_LEN);
    hex
}

fn poll_until<F: FnMut() -> bool>(mut probe: F) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < POLL_DEADLINE {
        if probe() {
            return true;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    probe()
}

/// Named proxy around a shared `MemoryWriter` so concurrent tests register
/// distinct writers against the process-global registry yet still read their
/// own captured events back.
struct CaptureWriter {
    inner: Arc<MemoryWriter>,
    name: &'static str,
}

#[async_trait]
impl Writer for CaptureWriter {
    async fn write(&self, event: &Event) -> Result<(), WriterError> {
        self.inner.write(event).await
    }

    async fn flush(&self) -> Result<(), WriterError> {
        self.inner.flush().await
    }

    fn health_check(&self) -> WriterHealthStatus {
        self.inner.health_check()
    }

    fn name(&self) -> &'static str {
        self.name
    }

    /// Accept everything. The default `production()` filter drops Debug, which
    /// is exactly the severity under test — see the module docs.
    fn severity_filter(&self) -> SeverityFilter {
        SeverityFilter::all()
    }
}

/// RAII guard that unregisters the writer on drop, so a panicking assertion
/// cannot leak a writer into the process-global registry and change behavior
/// for whatever test runs next in the same process.
struct WriterGuard {
    name: &'static str,
}

impl Drop for WriterGuard {
    fn drop(&mut self) {
        unregister_writer(self.name);
    }
}

fn register_capture(name: &'static str, capture: &Arc<MemoryWriter>) -> WriterGuard {
    register_writer(Box::new(CaptureWriter {
        inner: Arc::clone(capture),
        name,
    }));
    WriterGuard { name }
}

fn messages(writer: &MemoryWriter) -> Vec<String> {
    writer.all_events().into_iter().map(|e| e.message).collect()
}

/// `insert`, `remove`, and `drop` must log a key digest, never the raw key.
///
/// Inversion check: restoring any of the original
/// `format!("...: {}", key)` lines makes the "raw key absent" assertion fail.
#[test]
fn secure_map_never_logs_raw_keys() {
    let _ = configure_dispatcher(DispatcherConfig::testing());

    let name = "secure_map_key_logging_735";
    let capture = Arc::new(MemoryWriter::with_capacity(256));
    let _guard = register_capture(name, &capture);

    let digest = expected_digest();

    // Exercise all three leaking sites. The key carries the marker; the value
    // is irrelevant (values were never the leak).
    {
        let mut map = SecureMap::new();
        map.insert(MARKER_KEY, "sk-not-the-point");
        map.remove(MARKER_KEY);

        // Re-insert two entries so the Drop path has a count > 1 to report —
        // this is what distinguishes "one counted event" from "one per key".
        map.insert(MARKER_KEY, "sk-not-the-point");
        map.insert(format!("{}-second", MARKER_KEY), "sk-also-not-the-point");
    } // drop happens here

    // Wait for the drop event specifically: it is dispatched last, so seeing it
    // means insert/remove have already been flushed.
    let flushed = poll_until(|| {
        messages(&capture)
            .iter()
            .any(|m| m.contains("Dropping SecureMap"))
    });
    assert!(
        flushed,
        "drop event never reached the writer — capture is broken, so the \
         assertions below would be vacuous"
    );

    let captured = messages(&capture);

    // AC1/AC3: the raw key must appear in no message at all.
    let leaked: Vec<&String> = captured.iter().filter(|m| m.contains(MARKER_KEY)).collect();
    assert!(
        leaked.is_empty(),
        "SecureMap leaked raw key {:?} into observe output: {:?}",
        MARKER_KEY,
        leaked
    );

    // The digest must be present — otherwise "no raw key" would also hold for
    // an implementation that simply stopped logging, and this test would not
    // detect a regression that reintroduced logging in a different form.
    let insert_logged = captured
        .iter()
        .any(|m| m.contains("SecureMap insert") && m.contains(&digest));
    let remove_logged = captured
        .iter()
        .any(|m| m.contains("SecureMap remove") && m.contains(&digest));
    assert!(
        insert_logged,
        "insert must log the key digest {:?}; captured: {:?}",
        digest, captured
    );
    assert!(
        remove_logged,
        "remove must log the key digest {:?}; captured: {:?}",
        digest, captured
    );

    // AC2: Drop emits exactly one event carrying a count, not one per key.
    let drop_events: Vec<&String> = captured
        .iter()
        .filter(|m| m.contains("Dropping SecureMap"))
        .collect();
    assert_eq!(
        drop_events.len(),
        1,
        "Drop must emit exactly one counted event, got: {:?}",
        drop_events
    );
    assert!(
        drop_events.first().is_some_and(|m| m.contains("2 secrets")),
        "drop event must report the entry count (2), got: {:?}",
        drop_events
    );
}

/// The logged message must survive PII redaction with its digest intact, and
/// must carry no raw key even under the profile that redacts nothing.
///
/// This locks in the finding that motivated the message wording. The redactor
/// masks everything after a `secret:`-style prefix, so the original
/// `"Inserting secret: {key}"` had two consequences:
///
/// - it *incidentally* hid the raw key under non-`Testing` profiles (which is
///   why the leak reproduced only under `Testing`), and
/// - it would equally have masked a digest placed in that position, defeating
///   the correlation the digest exists to provide.
///
/// Both directions are asserted here so a future reword back to
/// `"Inserting secret: …"` fails loudly instead of silently destroying the
/// digest.
#[test]
fn logged_message_keeps_digest_and_omits_key_under_every_profile() {
    use octarine::observe::pii::{RedactionProfile, redact_pii_with_profile};

    let digest = expected_digest();
    // The exact shape the implementation emits.
    let message = format!("SecureMap insert (key={})", digest);

    for profile in [
        RedactionProfile::ProductionStrict,
        RedactionProfile::ProductionLenient,
        RedactionProfile::Development,
        RedactionProfile::Testing,
    ] {
        let redacted = redact_pii_with_profile(&message, profile);

        assert!(
            redacted.contains(&digest),
            "digest must survive redaction under {:?} (a `secret:`-style \
             prefix would mask it): {:?}",
            profile,
            redacted
        );
        assert!(
            !redacted.contains(MARKER_KEY),
            "raw key must never appear under {:?}: {:?}",
            profile,
            redacted
        );
    }

    // The converse, direction 1: the OLD `secret:` wording masks the digest.
    let old_style = format!("Inserting secret: key={}", digest);
    let old_redacted = redact_pii_with_profile(&old_style, RedactionProfile::ProductionStrict);
    assert!(
        !old_redacted.contains(&digest),
        "expected the `secret:` prefix to mask the digest — if it no longer \
         does, the wording rationale in map.rs is stale: {:?}",
        old_redacted
    );

    // The converse, direction 2: a LONGER digest trips the session-ID
    // heuristic, which masks any high-entropy whitespace token of 20+ chars.
    // This is why KEY_DIGEST_HEX_LEN is 12 and not 16 — the rendered
    // `(key=…)` token must stay under 20 characters.
    let long_digest = {
        let mut hex = blake3::hash(MARKER_KEY.as_bytes()).to_hex().to_string();
        hex.truncate(16);
        hex
    };
    let too_long = format!("SecureMap insert (key={})", long_digest);
    assert!(
        too_long.split_whitespace().any(|t| t.len() >= 20),
        "precondition: the 16-hex form should exceed the 20-char token bound"
    );
    let long_redacted = redact_pii_with_profile(&too_long, RedactionProfile::ProductionStrict);
    assert!(
        !long_redacted.contains(&long_digest),
        "expected a 16-hex digest to be masked as a session ID — if it no \
         longer is, the KEY_DIGEST_HEX_LEN rationale in map.rs is stale: {:?}",
        long_redacted
    );
}

/// Dropping an empty map stays silent, matching the behavior of the per-key
/// loop this replaced (an empty map had nothing to iterate).
#[test]
fn dropping_empty_secure_map_emits_no_event() {
    let _ = configure_dispatcher(DispatcherConfig::testing());

    let name = "secure_map_key_logging_735_empty";
    let capture = Arc::new(MemoryWriter::with_capacity(64));
    let _guard = register_capture(name, &capture);

    drop(SecureMap::new());

    // Dispatch a probe through the same path and wait for it, so "no drop
    // event" is a real observation rather than a race with the dispatcher.
    {
        let mut probe = SecureMap::new();
        probe.insert("zzprobe735", "v");
    } // probe's drop emits "Dropping SecureMap with 1 secrets"

    let flushed = poll_until(|| messages(&capture).iter().any(|m| m.contains("1 secrets")));
    assert!(
        flushed,
        "probe drop event never arrived — capture is broken"
    );

    let zero_counted = messages(&capture)
        .iter()
        .filter(|m| m.contains("0 secrets"))
        .count();
    assert_eq!(
        zero_counted, 0,
        "dropping an empty SecureMap must emit no event"
    );
}

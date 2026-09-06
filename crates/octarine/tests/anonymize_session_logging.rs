//! The vault must never emit a raw `SessionId` into observe output (issue #629).
//!
//! `SessionId::new` accepts any string and applies no validation — it is
//! documented as an opaque routing label, not a credential. A caller who
//! constructs one from a user's email or a JWT `sub` claim would, before this
//! fix, see that value flow verbatim into every audit writer at DEBUG from six
//! sites (`put`/`flush`/`get_or_put` in the in-memory store, `open`/`close`/
//! expiry in the session manager), defeating the vault's
//! redaction-by-construction guarantee for everything except the handle.
//!
//! This test drives real operations through the live observe pipeline and
//! asserts on what actually reaches a registered writer. Four details make it a
//! real test rather than a vacuous one — the first three carried over from the
//! equivalent `SecureMap` test (`tests/crypto/secure_map_key_logging.rs`),
//! whose fix this mirrors:
//!
//! 1. `CaptureWriter::severity_filter` returns `SeverityFilter::all()`. The
//!    `Writer` default is `SeverityFilter::production()`, which **drops Debug
//!    events** — without this override the capture is empty and every
//!    "raw handle absent" assertion would pass for the wrong reason.
//! 2. Assertions check the digest is **present** as well as the raw handle
//!    being **absent**. Absence alone would still hold if the logging were
//!    deleted outright, or if capture silently broke.
//! 3. The marker handle is deliberately opaque (not PII-shaped). Every message
//!    runs through `scan_and_redact`, so a PII-shaped handle would be redacted
//!    by the pipeline and the absence assertion would again pass for the wrong
//!    reason. (`session_id_digest_is_stable_and_hides_the_handle` in
//!    `vault/types.rs` covers the PII-shaped input directly, where no pipeline
//!    stands between the handle and the assertion.)
//! 4. The expected digest is recomputed here from `blake3` rather than by
//!    calling `SessionId::digest()`. Asserting against the implementation's own
//!    output would hold even if `digest()` regressed to returning the handle.
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

use octarine::anonymize::{
    EntityKey, InMemoryStore, SessionId, SessionManager, SessionOptions, StateStore,
};
use octarine::observe::Event;
use octarine::observe::pii::{RedactionProfile, redact_pii_with_profile};
use octarine::observe::writers::{
    DispatcherConfig, MemoryWriter, SeverityFilter, Writer, WriterError, WriterHealthStatus,
    configure_dispatcher, register_writer, unregister_writer,
};

const POLL_DEADLINE: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Opaque, non-PII handle unique to this test. Must not look like an
/// email/SSN/etc, or the PII redactor would strip it from messages and the
/// absence assertions below would pass regardless of the fix.
const MARKER_SESSION: &str = "zzsess629c0ffee";

/// Hex length the implementation truncates session digests to. Mirrors
/// `SESSION_DIGEST_BYTES` in `anonymize/vault/types.rs`. Each byte renders as
/// two characters, so the digest is twice this long.
const DIGEST_BYTES: usize = 6;

/// The digest the implementation is expected to log in place of the handle:
/// the leading `DIGEST_BYTES` of `blake3(handle)`, each byte rendered as two
/// letters in `a`..=`p` (high nibble first).
///
/// Computed from `blake3` directly rather than via `SessionId::digest()`: an
/// assertion against the implementation's own output would still pass if
/// `digest()` regressed to returning the raw handle.
///
/// The all-letter alphabet is deliberate — see rule 3 on `SessionId::digest`:
/// a hex rendering trips the redactor's phone-number detector for a fraction
/// of handles.
fn expected_digest(handle: &str) -> String {
    blake3::hash(handle.as_bytes())
        .as_bytes()
        .iter()
        .take(DIGEST_BYTES)
        .flat_map(|b| {
            // Both nibbles are < 16, so these land in `a`..=`p`; saturating_add
            // satisfies the crate's denied `arithmetic_side_effects` lint.
            [
                char::from(b'a'.saturating_add(b >> 4)),
                char::from(b'a'.saturating_add(b & 0x0f)),
            ]
        })
        .collect()
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

/// Fails with the captured messages attached when `handle` appears in any of
/// them.
fn assert_no_leak(captured: &[String], handle: &str) {
    let leaked: Vec<&String> = captured.iter().filter(|m| m.contains(handle)).collect();
    assert!(
        leaked.is_empty(),
        "leaked raw session handle {handle:?} into observe output: {leaked:?}"
    );
}

/// `InMemoryStore::put`, `get_or_put`, and `flush` must log a session digest,
/// never the raw handle.
///
/// Inversion check: restoring any of the original `format!("… session {}",
/// session)` lines makes the "raw handle absent" assertion fail.
#[tokio::test]
async fn in_memory_store_never_logs_raw_session_handle() {
    let _ = configure_dispatcher(DispatcherConfig::testing());

    let name = "anonymize_session_logging_629_store";
    let capture = Arc::new(MemoryWriter::with_capacity(256));
    let _guard = register_capture(name, &capture);

    let handle = format!("{MARKER_SESSION}-store");
    let digest = expected_digest(&handle);
    let session = SessionId::new(handle.clone());

    // `new()` (not `silent()`) — the emitting variant is the one under test.
    let store = InMemoryStore::new();

    // Exercise all three leaking sites.
    store
        .put(
            &session,
            &EntityKey::new("PERSON", "Jane Doe"),
            "<PERSON_0>".to_string(),
        )
        .await
        .expect("put");
    store
        .get_or_put(
            &session,
            &EntityKey::new("EMAIL", "jane@example.com"),
            "<EMAIL_0>".to_string(),
        )
        .await
        .expect("get_or_put");
    store.flush(&session).await.expect("flush");

    // Wait for *this* test's flush event: it is dispatched last, so seeing it
    // means put/get_or_put have already been delivered too.
    //
    // The digest in the predicate is load-bearing. Writers are registered
    // against a process-global dispatcher that fans every event to all of
    // them, so a bare `contains("flushed session")` is satisfied by a
    // concurrently-running test's flush — the gate opens early and the
    // snapshot below is taken before this test's own events arrive.
    let flushed = poll_until(|| {
        messages(&capture)
            .iter()
            .any(|m| m.contains("flushed session") && m.contains(&digest))
    });
    assert!(
        flushed,
        "flush event never reached the writer — capture is broken, so the \
         assertions below would be vacuous"
    );

    let captured = messages(&capture);
    assert_no_leak(&captured, &handle);

    // The digest must be present on each site — otherwise "no raw handle"
    // would also hold for an implementation that simply stopped logging, and
    // this test would not detect a regression that reintroduced logging in a
    // different form.
    for (label, needle) in [
        ("put", "stored PERSON mapping"),
        ("get_or_put", "minted EMAIL mapping"),
        ("flush", "flushed session"),
    ] {
        assert!(
            captured
                .iter()
                .any(|m| m.contains(needle) && m.contains(&digest)),
            "{label} must log the session digest {digest:?}; captured: {captured:?}"
        );
    }
}

/// `SessionManager::open`, `close`, and the expiry sweep must log a session
/// digest, never the raw handle.
#[tokio::test]
async fn session_manager_never_logs_raw_session_handle() {
    let _ = configure_dispatcher(DispatcherConfig::testing());

    let name = "anonymize_session_logging_629_manager";
    let capture = Arc::new(MemoryWriter::with_capacity(256));
    let _guard = register_capture(name, &capture);

    let opened = format!("{MARKER_SESSION}-open");
    let expired = format!("{MARKER_SESSION}-expire");

    // `new()` (not `.silent()`) — the emitting variant is the one under test.
    let manager = SessionManager::new(Arc::new(InMemoryStore::silent()));

    // open + close.
    let id = manager.open(SessionOptions::default().id_hint(opened.clone()));
    manager.close(&id).await.expect("close");

    // Expiry: a zero TTL is already elapsed, so one forced sweep reclaims it
    // without waiting on wall-clock time.
    let doomed =
        manager.open(SessionOptions::with_ttl(Duration::from_millis(0)).id_hint(expired.clone()));
    assert_eq!(doomed.as_str(), expired);
    let reclaimed = manager.sweep_now().await.expect("sweep");
    assert_eq!(reclaimed, 1, "the zero-TTL session should have been swept");

    // The expiry event is dispatched last of the three. Keyed on this test's
    // own digest — see the note in the store test: a shared dispatcher makes a
    // bare message match satisfiable by another test's event.
    let expired_digest = expected_digest(&expired);
    let swept = poll_until(|| {
        messages(&capture)
            .iter()
            .any(|m| m.contains("expired session") && m.contains(&expired_digest))
    });
    assert!(
        swept,
        "expiry event never reached the writer — capture is broken, so the \
         assertions below would be vacuous"
    );

    let captured = messages(&capture);
    assert_no_leak(&captured, &opened);
    assert_no_leak(&captured, &expired);

    for (label, needle, handle) in [
        ("open", "opened session", &opened),
        ("close", "closed session", &opened),
        ("expire", "expired session", &expired),
    ] {
        let digest = expected_digest(handle);
        assert!(
            captured
                .iter()
                .any(|m| m.contains(needle) && m.contains(&digest)),
            "{label} must log the session digest {digest:?}; captured: {captured:?}"
        );
    }
}

/// The digest must survive the PII redactor under **every** profile.
///
/// This is the check that `DispatcherConfig::testing()` cannot make.
/// `RedactionProfile::Testing` redacts nothing, so the live-pipeline tests
/// above prove the digest is *emitted* but say nothing about what a production
/// writer receives. Two redactor rules will silently eat it:
///
/// - **Keyword masking** replaces everything after a `secret:`/`password:`
///   style prefix — it would replace the digest with `[PASSWORD]`.
/// - **Entropy masking** replaces any whitespace-delimited token of 20+ chars
///   with >50% unique characters with `[SESSION]`. `(session=<12 hex>)` is one
///   22-char token and *was* replaced wholesale under both production profiles
///   during development; the space-separated form splits it into two short
///   tokens and survives.
///
/// Either failure is silent: the handle stays protected and only the
/// correlation vanishes, in production, while `Testing` shows it working. So
/// assert on the post-redaction text, not the format string.
///
/// The messages are **captured from real operations**, not hand-copied from
/// the source. Re-typing the format strings here would decouple the test from
/// the call sites: a later reformat (a reordered field, an added value,
/// different punctuation) could re-trip the entropy rule while this test kept
/// passing against its own stale copy — which is precisely the silent failure
/// it exists to prevent.
///
/// Inversion check: restoring `(session={})` in place of `(session {})` at the
/// emitting sites makes this fail under both production profiles.
#[tokio::test]
async fn session_digest_survives_every_redaction_profile() {
    let _ = configure_dispatcher(DispatcherConfig::testing());

    let name = "anonymize_session_logging_629_redaction";
    let capture = Arc::new(MemoryWriter::with_capacity(256));
    let _guard = register_capture(name, &capture);

    let handle = format!("{MARKER_SESSION}-redact");
    let digest = expected_digest(&handle);
    let session = SessionId::new(handle.clone());

    // Drive every emitting site so the captured text is whatever the code
    // actually produces today.
    let store = Arc::new(InMemoryStore::new());
    store
        .put(
            &session,
            &EntityKey::new("PERSON", "Jane Doe"),
            "<PERSON_0>".to_string(),
        )
        .await
        .expect("put");
    store
        .get_or_put(
            &session,
            &EntityKey::new("EMAIL", "jane@example.com"),
            "<EMAIL_0>".to_string(),
        )
        .await
        .expect("get_or_put");
    store.flush(&session).await.expect("flush");

    let manager = SessionManager::new(Arc::clone(&store));
    let id = manager.open(SessionOptions::default().id_hint(handle.clone()));
    manager.close(&id).await.expect("close");

    let flushed = poll_until(|| {
        messages(&capture)
            .iter()
            .any(|m| m.contains("closed session") && m.contains(&digest))
    });
    assert!(
        flushed,
        "events never reached the writer — capture is broken, so the \
         assertions below would be vacuous"
    );

    // `touch` reports through a Problem rather than an observe event, so it is
    // not in the capture; add its real message text explicitly.
    let touch_err = manager
        .touch(&SessionId::new(format!("{handle}-unknown")))
        .await
        .expect_err("touch must fail for an unknown session");
    let touch_message = touch_err.to_string();

    let mut captured: Vec<String> = messages(&capture)
        .into_iter()
        .filter(|m| m.contains(&digest))
        .collect();
    captured.push(touch_message);

    // Guard against the capture silently narrowing: five observe sites plus
    // touch. Without this a filter that matched nothing would make the loop
    // below iterate zero times and pass.
    assert!(
        captured.len() >= 6,
        "expected every emitting site to be represented; got {captured:?}"
    );

    for profile in [
        RedactionProfile::ProductionStrict,
        RedactionProfile::ProductionLenient,
        RedactionProfile::Development,
        RedactionProfile::Testing,
    ] {
        for message in &captured {
            // The touch message carries its own session's digest, not this
            // one's; assert each message keeps whatever digest it contains.
            let expected = if message.contains(&digest) {
                digest.clone()
            } else {
                expected_digest(&format!("{handle}-unknown"))
            };
            let redacted = redact_pii_with_profile(message, profile);
            assert!(
                redacted.contains(&expected),
                "{profile:?} destroyed the session digest — correlation is lost \
                 in this profile.\n  before: {message}\n  after:  {redacted}"
            );
        }
    }

    // The captured messages above all carry ONE session's digest, so they can
    // only catch a failure that is independent of the digest's value. The
    // redactor's digit-run detectors are not: a hex digest tripped `[PHONE]`
    // for ~0.5% of handles. Sweep many digests through the same message shapes
    // so a low-rate, value-dependent regression is caught rather than sampled.
    for i in 0..500 {
        let swept = SessionId::new(format!("sweep-{i}")).digest();
        for shape in [
            format!("stored PERSON mapping (session {swept})"),
            format!("flushed session (session {swept}, 2 mapping(s) dropped)"),
            format!("session (session {swept}) is not open"),
        ] {
            for profile in [
                RedactionProfile::ProductionStrict,
                RedactionProfile::ProductionLenient,
            ] {
                let redacted = redact_pii_with_profile(&shape, profile);
                assert!(
                    redacted.contains(&swept),
                    "{profile:?} destroyed the digest for handle sweep-{i} — a \
                     value-dependent redaction failure.\n  before: {shape}\n  \
                     after:  {redacted}"
                );
            }
        }
    }
}

/// A `SessionId` built from PII must not reach a writer verbatim — the actual
/// scenario #629 describes.
///
/// This is the complement to the opaque-marker tests above: those keep the PII
/// redactor out of the picture so absence is attributable to the fix, while
/// this one confirms the realistic input is covered end to end. The digest
/// assertion is what keeps it honest — the redactor might mask an email
/// incidentally, but it cannot manufacture the digest.
#[tokio::test]
async fn pii_shaped_session_handle_is_not_logged_verbatim() {
    let _ = configure_dispatcher(DispatcherConfig::testing());

    let name = "anonymize_session_logging_629_pii";
    let capture = Arc::new(MemoryWriter::with_capacity(256));
    let _guard = register_capture(name, &capture);

    // The accidental-misuse case from the issue: an email as a session handle.
    let handle = "jane.doe.629@example.com";
    let digest = expected_digest(handle);
    let session = SessionId::new(handle);

    let store = InMemoryStore::new();
    store
        .put(
            &session,
            &EntityKey::new("PERSON", "Jane Doe"),
            "<PERSON_0>".to_string(),
        )
        .await
        .expect("put");
    store.flush(&session).await.expect("flush");

    let flushed = poll_until(|| {
        messages(&capture)
            .iter()
            .any(|m| m.contains("flushed session") && m.contains(&digest))
    });
    assert!(
        flushed,
        "flush event carrying the digest never reached the writer — capture is \
         broken, so the assertion below would be vacuous"
    );

    let captured = messages(&capture);
    assert_no_leak(&captured, handle);
    // Not just the whole address: the local part alone identifies the person.
    assert_no_leak(&captured, "jane.doe.629");
}

//! Behavioral regression tests for the Layer 1 ↔ Layer 2 event-dispatch
//! boundary that issue #409 established.
//!
//! The refactor made `crate::primitives::types::ProblemExt` (the Layer-1
//! constructor trait) resolve to the **event-free**
//! `octarine_problem::ProblemConstructors` instead of observe's
//! event-dispatching `ProblemExt`. These tests lock in two guarantees that the
//! `matches!`-only unit tests in `octarine-problem` cannot express (that crate
//! has no dependency on `observe`):
//!
//! 1. Constructing a `Problem` through the Layer-1 trait dispatches **zero**
//!    observability events — a future edit that re-points the re-export back at
//!    `observe::ProblemExt` (reintroducing the #409 leak) fails here.
//! 2. The Layer-3 identifier builders re-emit the CRITICAL security audit event
//!    that the primitive side effect used to provide, gated on `emit_events`,
//!    so injection detection still lands in the audit trail.
//!
//! The dispatcher and writer registry are process-global singletons; following
//! the convention in `tests/observe/writer_dispatch.rs`, every event carries a
//! unique marker and assertions filter by marker (never absolute counts) so the
//! suite is robust whether run process-per-test (nextest) or many-per-process.
//! A shared `MemoryWriter` is wrapped in a named `CaptureWriter` so concurrent
//! tests register distinct writers against the global registry yet still read
//! their own captured events back.

#![allow(clippy::panic, clippy::expect_used)]

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;

use crate::observe::writers::{
    DispatcherConfig, MemoryWriter, Writer, WriterError, WriterHealthStatus, configure_dispatcher,
    dispatch, register_writer, unregister_writer,
};
use crate::observe::{Event, EventType};

/// Deadline for positive-signal polls — matches the 5s the observe integration
/// suite uses to absorb dispatcher scheduling jitter under parallel CI load.
const POLL_DEADLINE: Duration = Duration::from_secs(5);

/// Configure the global dispatcher for fast flushes exactly once per test
/// binary (mirrors `tests/observe/mod.rs::ensure_test_dispatcher`).
fn ensure_test_dispatcher() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = configure_dispatcher(DispatcherConfig::testing());
    });
}

/// Poll `probe` up to `deadline`, checking every 10ms. Avoids fixed sleeps so
/// the test stays resilient under CI scheduling jitter.
fn poll_until<F: FnMut() -> bool>(deadline: Duration, mut probe: F) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if probe() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    probe()
}

fn count_with_marker(writer: &MemoryWriter, marker: &str) -> usize {
    writer
        .all_events()
        .iter()
        .filter(|e| e.message.contains(marker))
        .count()
}

/// Named proxy around a shared `MemoryWriter` so multiple concurrent tests can
/// register distinct capture writers against the global registry (the built-in
/// `MemoryWriter::name()` is a fixed `"memory"`).
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
}

fn register_capture(name: &'static str) -> Arc<MemoryWriter> {
    let inner = Arc::new(MemoryWriter::with_capacity(64));
    register_writer(Box::new(CaptureWriter {
        inner: Arc::clone(&inner),
        name,
    }));
    inner
}

/// Layer 1 constructors must not dispatch events. Building a `Problem` through
/// `crate::primitives::types::ProblemExt` (the event-free re-export) is expected
/// to produce nothing on the wire — this is the core #409 guarantee.
#[test]
fn layer1_problem_constructors_dispatch_no_events() {
    use crate::primitives::types::ProblemExt;

    ensure_test_dispatcher();

    let name = "layer_isolation_l1_silent";
    let marker = "L1_NOEVENT_409_a71c";
    let capture = register_capture(name);

    // Construct via the Layer-1 trait. The message carries the marker so a leak
    // would be visible in the captured events.
    let _validation = <crate::observe::Problem as ProblemExt>::validation(marker);
    let _security = <crate::observe::Problem as ProblemExt>::security(marker);
    let _permission = <crate::observe::Problem as ProblemExt>::permission_denied(marker);

    // Dispatch a separate probe event and wait for it, so we confirm the
    // dispatcher actually flushed rather than merely timing out on silence.
    let probe_name = "layer_isolation_l1_probe";
    let probe_marker = "L1_PROBE_409_a71c";
    let probe = register_capture(probe_name);
    dispatch(Event::new(EventType::Info, probe_marker));
    let flushed = poll_until(POLL_DEADLINE, || {
        count_with_marker(&probe, probe_marker) >= 1
    });

    let leaked = count_with_marker(&capture, marker);
    unregister_writer(name);
    unregister_writer(probe_name);

    assert!(
        flushed,
        "probe writer should confirm the dispatcher flushed"
    );
    assert_eq!(
        leaked, 0,
        "Layer-1 ProblemExt constructors must dispatch zero events (issue #409 leak)"
    );
}

/// The Layer-3 `MetricsBuilder` must re-emit a CRITICAL security event when the
/// primitive raises a security-class failure — restoring the audit trail the
/// Layer-1 side effect used to provide. `silent()` must stay silent.
///
/// The label-count (cardinality) check is used as the trigger because it
/// returns `Problem::security` unconditionally on breach, with no character or
/// ordering gate in front of it — an unambiguously reachable security path.
/// Unbounded label cardinality is itself a denial-of-service vector, so the
/// CRITICAL classification is warranted.
#[test]
fn layer3_metrics_builder_emits_security_event_on_cardinality_breach() {
    use crate::identifiers::MetricsBuilder;

    ensure_test_dispatcher();

    let name = "layer_isolation_l3_metrics";
    let capture = register_capture(name);

    // A distinctive over-limit count (default max is 20). The count appears in
    // the emitted message ("... N labels ... (input: N)"), so it doubles as the
    // per-test marker.
    let over_limit = 409_777; // labels — unique, unmistakably over 20
    let err = MetricsBuilder::new().validate_label_count(over_limit);
    assert!(err.is_err(), "cardinality breach must fail validation");

    let emitted = poll_until(POLL_DEADLINE, || count_with_marker(&capture, "409777") >= 1);

    // A silent builder must not emit anything for the same breach.
    let silent_over_limit = 409_888;
    let _ = MetricsBuilder::silent().validate_label_count(silent_over_limit);
    let silent_count = count_with_marker(&capture, "409888");

    unregister_writer(name);

    assert!(
        emitted,
        "L3 MetricsBuilder must emit a security event on cardinality breach"
    );
    assert_eq!(
        silent_count, 0,
        "silent() MetricsBuilder must not emit events"
    );
}

/// The Layer-3 `EnvironmentBuilder` must emit a CRITICAL security event when a
/// caller attempts to override a critical system variable (e.g. `PATH`), which
/// the primitive surfaces via `Problem::security` → `PermissionDenied`. This is
/// a genuinely reachable security path (valid chars, valid start char) and one
/// of the more sensitive: overriding `PATH`/`LD_PRELOAD` is a classic attack.
#[test]
fn layer3_environment_builder_emits_security_event_on_critical_override() {
    use crate::identifiers::EnvironmentBuilder;

    ensure_test_dispatcher();

    let name = "layer_isolation_l3_env";
    let capture = register_capture(name);

    // PATH is a critical system variable; the primitive returns
    // Problem::security("Cannot override critical system variable 'PATH'").
    let err = EnvironmentBuilder::new().validate_env_var("PATH");
    assert!(err.is_err(), "overriding a critical var must fail");

    // The emitted message embeds the var name; "critical system variable" is a
    // stable marker unique to this security path.
    let emitted = poll_until(POLL_DEADLINE, || {
        count_with_marker(&capture, "Cannot override critical system variable 'PATH'") >= 1
    });

    let silent_env = EnvironmentBuilder::silent();
    let _ = silent_env.validate_env_var("LD_PRELOAD");
    let silent_count = count_with_marker(&capture, "LD_PRELOAD");

    unregister_writer(name);

    assert!(
        emitted,
        "L3 EnvironmentBuilder must emit a security event on critical-var override"
    );
    assert_eq!(
        silent_count, 0,
        "silent() EnvironmentBuilder must not emit events"
    );
}

/// A benign validation failure (bad characters, not an injection) must NOT be
/// escalated to a security event — only `Problem::PermissionDenied` failures
/// are. Guards against over-emitting on the far more common Warning path.
#[test]
fn layer3_generic_builder_no_security_event_on_benign_failure() {
    use crate::identifiers::GenericBuilder;

    ensure_test_dispatcher();

    let name = "layer_isolation_l3_benign";
    let capture = register_capture(name);

    // Leading digit -> "must start with letter or underscore" (Validation),
    // not a security detection. The token would surface if wrongly escalated.
    let token = "9invalid_L3BENIGN_409_c5d1";
    let err = GenericBuilder::new().validate_identifier(token);
    assert!(err.is_err(), "bad identifier must fail validation");

    // Dispatch a probe so we do not just time out on legitimate silence.
    let probe_marker = "L3BENIGN_PROBE_409_c5d1";
    dispatch(Event::new(EventType::Info, probe_marker));
    let flushed = poll_until(POLL_DEADLINE, || {
        count_with_marker(&capture, probe_marker) >= 1
    });

    let escalated = count_with_marker(&capture, "_L3BENIGN_409_c5d1");
    unregister_writer(name);

    assert!(flushed, "probe event should confirm the dispatcher flushed");
    assert_eq!(
        escalated, 0,
        "benign (non-security) validation failures must not emit a security event"
    );
}

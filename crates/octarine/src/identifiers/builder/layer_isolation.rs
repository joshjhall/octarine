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

/// Deadline for positive-signal polls.
///
/// Sized for the **worst case**, not the configured one: `EVENT_DISPATCHER` is
/// a process-global `Lazy`, so `configure_dispatcher` only takes effect if it
/// runs before any other test in the binary dispatches an event (it returns
/// `false` otherwise — see [`ensure_test_dispatcher`]). When this test loses
/// that race the dispatcher runs on `DispatcherConfig::default()`, whose
/// `flush_interval` is 1s rather than the 10ms of `testing()`.
///
/// A single probe event never fills the default 100-event batch, so it only
/// reaches writers on a `flush_timer` tick. The deadline must therefore clear
/// several 1s ticks plus scheduling jitter under parallel load — at 5s a mere
/// handful of ticks had to land on time, which is what made this test fail
/// intermittently in the full 6800-test suite.
const POLL_DEADLINE: Duration = Duration::from_secs(30);

/// Request fast dispatcher flushes for this test binary.
///
/// Returns whether `DispatcherConfig::testing()` was actually installed.
/// Configuration is only possible before the global dispatcher's first use, so
/// a `false` return means another test got there first and the dispatcher is
/// running on [`DispatcherConfig::default`] (1s flush interval). That is not an
/// error — [`POLL_DEADLINE`] is sized to tolerate it — but it must not be
/// mistaken for a successful configuration, which is why the result is named
/// rather than discarded.
fn ensure_test_dispatcher() -> bool {
    static INIT: OnceLock<bool> = OnceLock::new();
    *INIT.get_or_init(|| configure_dispatcher(DispatcherConfig::testing()))
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

fn count_with_marker_of_type(writer: &MemoryWriter, marker: &str, ty: EventType) -> usize {
    writer
        .all_events()
        .iter()
        .filter(|e| e.event_type == ty && e.message.contains(marker))
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

    let fast_flush = ensure_test_dispatcher();

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
        "probe writer should confirm the dispatcher flushed within {POLL_DEADLINE:?} \
         (fast-flush config installed: {fast_flush}; when false the dispatcher \
         runs on the 1s default flush interval)"
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

    let fast_flush = ensure_test_dispatcher();

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
        "L3 MetricsBuilder must emit a security event on cardinality breach \
         (fast-flush config installed: {fast_flush}; when false the dispatcher \
         runs on the 1s default flush interval)"
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

    let fast_flush = ensure_test_dispatcher();

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
        "L3 EnvironmentBuilder must emit a security event on critical-var override \
         (fast-flush config installed: {fast_flush}; when false the dispatcher \
         runs on the 1s default flush interval)"
    );
    assert_eq!(
        silent_count, 0,
        "silent() EnvironmentBuilder must not emit events"
    );
}

/// A benign validation failure (bad characters, not an injection) must emit a
/// WARNING event — restoring the audit trail Layer-1 constructors used to
/// provide (issue #683) — but must NOT be escalated to a CRITICAL security
/// event; only `Problem::PermissionDenied` failures are. `silent()` must stay
/// silent. Guards both the newly-restored Warning path and the security
/// non-escalation guarantee.
#[test]
fn layer3_generic_builder_emits_warning_on_benign_failure() {
    use crate::identifiers::GenericBuilder;

    let fast_flush = ensure_test_dispatcher();

    let name = "layer_isolation_l3_benign";
    let capture = register_capture(name);

    // Leading digit -> "must start with letter or underscore" (Validation),
    // not a security detection. The identifier appears in the emitted message.
    let bad_ident = "9_benign_warn_marker_ident";
    let err = GenericBuilder::new().validate_identifier(bad_ident);
    assert!(err.is_err(), "bad identifier must fail validation");

    // The benign failure must land as a WARNING carrying the input identifier.
    let warned = poll_until(POLL_DEADLINE, || {
        count_with_marker_of_type(&capture, bad_ident, EventType::Warning) >= 1
    });

    // A silent builder must not emit anything for the same benign failure.
    let silent_ident = "9_benign_silent_marker_ident";
    let _ = GenericBuilder::silent().validate_identifier(silent_ident);
    let silent_count = count_with_marker(&capture, silent_ident);

    // The benign path must NOT be escalated to a CRITICAL security event, which
    // dispatches as `EventType::SystemError` (see observe/event/dispatch.rs).
    let escalated = count_with_marker_of_type(&capture, bad_ident, EventType::SystemError);
    unregister_writer(name);

    assert!(
        warned,
        "L3 GenericBuilder must emit a WARNING event on a benign validation failure \
         (fast-flush config installed: {fast_flush}; when false the dispatcher \
         runs on the 1s default flush interval)"
    );
    assert_eq!(
        silent_count, 0,
        "silent() GenericBuilder must not emit events for a benign failure"
    );
    assert_eq!(
        escalated, 0,
        "benign (non-security) validation failures must not emit a CRITICAL security event"
    );
}

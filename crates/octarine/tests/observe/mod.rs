//! Integration tests for the observe module
//!
//! These tests verify end-to-end behavior across observe components:
//! - Event creation and dispatch
//! - Writer implementations
//! - Async dispatch behavior
//! - PII detection through full pipeline
//! - Multi-tenant context isolation
//! - Context capture from thread-local/task-local storage
//! - Metrics export (Prometheus, StatsD)
//! - Tracing crate integration
//! - Audit builders and compliance tagging

#![allow(clippy::panic, clippy::expect_used)]

use std::sync::OnceLock;
use std::time::Duration;

use octarine::observe::writers::{DispatcherConfig, configure_dispatcher};

/// Apply `DispatcherConfig::testing()` to the global dispatcher exactly once
/// per integration-test binary. Sets `batch_size = 1` and
/// `flush_interval = 10ms` so dispatched events reach registered writers
/// within tens of milliseconds instead of waiting up to the default
/// 1-second flush tick.
///
/// Every test in this binary that queries the dispatcher (directly via
/// `dispatch()` / stats APIs, or indirectly via logging shortcuts like
/// `info()` / `warn()`) MUST call this helper first. The dispatcher is a
/// lazily-initialised global: whichever test queries it first pins its
/// configuration for the remainder of the binary, so a single test that
/// skips this call can default-configure the singleton and re-introduce
/// the CI flake described in issue #223.
///
/// Calling it first is necessary but **not sufficient**: this helper cannot
/// force the configuration, only request it. The return value reports whether
/// `testing()` was actually installed — see the body and
/// [`WRITER_POLL_DEADLINE`].
///
/// Why an explicit per-test call rather than a binary-load ctor: the crate
/// sets `unsafe_code = "forbid"` at the Cargo.toml level, which rules out
/// `.init_array` crates like `ctor`. The `OnceLock` keeps the call cheap
/// after the first test runs it.
pub(super) fn ensure_test_dispatcher() -> bool {
    static INIT: OnceLock<bool> = OnceLock::new();
    // `configure_dispatcher` returns false if the dispatcher was already
    // initialised by an earlier dispatch in this process, in which case the
    // fast-flush config is DISCARDED and the binary runs on
    // `DispatcherConfig::default()` — a 1s flush interval instead of 10ms.
    //
    // That outcome is survivable but NOT equivalent: any deadline that polls
    // for events to reach a *writer* must be sized for the 1s case (see
    // `WRITER_POLL_DEADLINE`). Callers get the result so a failure can report
    // which config was actually installed instead of sending the next reader
    // hunting for phantom CPU contention (issues #732, #747).
    *INIT.get_or_init(|| configure_dispatcher(DispatcherConfig::testing()))
}

/// Deadline for polls that wait on events reaching a registered **writer**.
///
/// Sized for the worst case [`ensure_test_dispatcher`] can leave in place: a
/// single event never fills the 100-event default batch, so it only reaches
/// writers on a `flush_timer` tick, and that tick is 1s when the fast-flush
/// config lost the race. This is a failure deadline, not a latency budget —
/// on the happy path (10ms flush) polls still return in milliseconds, so a
/// large value costs nothing.
///
/// Polls that only read dispatcher *queue* counters (`dispatcher_stats`) or
/// the metrics registry do not wait on a flush and do not need this.
pub(super) const WRITER_POLL_DEADLINE: Duration = Duration::from_secs(30);

mod async_dispatch;
mod audit_builders;
mod context_capture;
mod event_flow;
mod metrics_export;
mod pii_pipeline;
mod thresholds;
mod tracing_integration;
mod tracing_layer;
mod writer_dispatch;
mod writer_file;
mod writer_memory;

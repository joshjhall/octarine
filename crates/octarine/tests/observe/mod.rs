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
/// Why an explicit per-test call rather than a binary-load ctor: the crate
/// sets `unsafe_code = "forbid"` at the Cargo.toml level, which rules out
/// `.init_array` crates like `ctor`. The `OnceLock` keeps the call cheap
/// after the first test runs it.
pub(super) fn ensure_test_dispatcher() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        // `configure_dispatcher` returns false if the dispatcher has already
        // been initialised by an earlier dispatch in this process. Either
        // outcome is fine — the critical invariant is that every test that
        // touches the dispatcher calls this before doing so.
        let _ = configure_dispatcher(DispatcherConfig::testing());
    });
}

mod async_dispatch;
mod audit_builders;
mod context_capture;
mod event_flow;
mod metrics_export;
mod pii_pipeline;
mod thresholds;
mod tracing_integration;
mod writer_dispatch;
mod writer_file;
mod writer_memory;

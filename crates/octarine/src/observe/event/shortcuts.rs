//! Event shortcuts for common logging patterns
//!
//! These shortcuts provide quick ways to dispatch events without
//! needing to build them manually. They all use full context capture.
//!
//! For more control, use EventBuilder directly.

use crate::observe::context::shortcuts as context_shortcuts;
use crate::observe::event::builder::EventBuilder;

// ==========================================
// LOGGING SHORTCUTS
// ==========================================

/// Dispatches a debug event immediately
pub fn debug(message: impl Into<String>) {
    EventBuilder::new(message)
        .with_context(context_shortcuts::full())
        .debug();
}

/// Dispatches an info event immediately
pub fn info(message: impl Into<String>) {
    EventBuilder::new(message)
        .with_context(context_shortcuts::full())
        .info();
}

/// Dispatches a warning event immediately
pub fn warn(message: impl Into<String>) {
    EventBuilder::new(message)
        .with_context(context_shortcuts::full())
        .warn();
}

/// Dispatches an error event immediately (just logs, no Problem)
pub fn error(message: impl Into<String>) {
    EventBuilder::new(message)
        .with_context(context_shortcuts::full())
        .error();
}

/// Dispatches a critical event immediately
pub fn critical(message: impl Into<String>) {
    EventBuilder::new(message)
        .with_context(context_shortcuts::security())
        .critical();
}

// ==========================================
// BUSINESS EVENT SHORTCUTS
// ==========================================

/// Dispatches a success event immediately
pub fn success(message: impl Into<String>) {
    EventBuilder::new(message)
        .with_context(context_shortcuts::full())
        .success();
}

/// Dispatches a trace event immediately (for detailed debugging)
pub fn trace(message: impl Into<String>) {
    EventBuilder::new(message)
        .with_context(context_shortcuts::minimal())
        .debug(); // Trace is just debug with minimal context
}

// ==========================================
// SECURITY EVENT SHORTCUTS
// ==========================================

/// Dispatches an authentication success event
pub fn auth_success(user: &str) {
    EventBuilder::new(format!("Authentication successful for user: {}", user))
        .with_context(context_shortcuts::authentication(user))
        .auth_success();
}

/// Dispatches an authentication failure event
pub fn auth_failure(user: &str, _reason: &str) {
    EventBuilder::new(format!("Authentication failed for user: {}", user))
        .with_context(context_shortcuts::authentication(user))
        .auth_failure();
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    //! Tests for the event shortcuts.
    //!
    //! # Why not MemoryWriter capture?
    //!
    //! The audit finding (`test-gaps-007`) suggested using `MemoryWriter`
    //! to capture events and assert on `EventType` (e.g. `auth_failure` →
    //! `EventType::LoginFailure`). That approach is not currently feasible:
    //! `writers::dispatch_to_writers_sync` calls
    //! `tokio::runtime::Builder::new_current_thread().build().block_on(...)`
    //! from within the async dispatcher's existing runtime, which panics
    //! with "Cannot start a runtime from within a runtime". The panic is
    //! swallowed, so registered writers silently never receive dispatched
    //! events. (Verified empirically: events DO queue —
    //! `dispatcher_stats()` increments — but never reach the writer.)
    //!
    //! Until that pre-existing dispatcher bug is fixed, the best coverage
    //! we can give these shortcuts is:
    //!
    //! 1. **Smoke tests** — call the shortcut, assert no panic. Covers the
    //!    full synchronous call path up to the queue enqueue.
    //! 2. **Queue assertion** — verify `dispatcher_stats()` increments
    //!    after the shortcut is called, proving the event reaches the
    //!    dispatcher boundary (the last point we can observe it).
    //!
    //! EventType assertions remain the subject of a follow-up issue on
    //! the dispatcher runtime-in-runtime panic.

    use super::*;
    use crate::observe::writers::dispatcher_stats;
    use std::time::Duration;

    // ==========================================
    // Smoke tests — no panic across shortcut call paths
    // ==========================================

    #[test]
    fn debug_smoke() {
        debug("debug message");
    }

    #[test]
    fn info_smoke() {
        info("info message");
    }

    #[test]
    fn warn_smoke() {
        warn("warn message");
    }

    #[test]
    fn error_smoke() {
        error("error message");
    }

    #[test]
    fn critical_smoke() {
        critical("critical message");
    }

    #[test]
    fn success_smoke() {
        success("success message");
    }

    #[test]
    fn trace_smoke() {
        trace("trace message");
    }

    #[test]
    fn auth_success_smoke() {
        auth_success("alice");
    }

    #[test]
    fn auth_failure_smoke() {
        auth_failure("alice", "bad password");
    }

    // ==========================================
    // Queue assertions — shortcut reaches dispatcher
    // ==========================================
    //
    // These are `#[tokio::test]` because the dispatcher stats are backed by
    // atomics that may not be immediately visible after the enqueue
    // returns; a brief yield + sleep lets the background thread update the
    // counter. `#[serial]` is used because `dispatcher_stats()` reads a
    // global — parallel callers would interfere with the before/after
    // delta.

    async fn yield_to_dispatcher() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn info_increments_dispatcher_queue() {
        let before = dispatcher_stats().total_written;
        info("queue-assertion-info");
        yield_to_dispatcher().await;
        let after = dispatcher_stats().total_written;
        assert!(
            after > before,
            "info() should enqueue at least one event (before={before}, after={after})"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn critical_increments_dispatcher_queue() {
        let before = dispatcher_stats().total_written;
        critical("queue-assertion-critical");
        yield_to_dispatcher().await;
        let after = dispatcher_stats().total_written;
        assert!(
            after > before,
            "critical() should enqueue at least one event (before={before}, after={after})"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn auth_failure_increments_dispatcher_queue() {
        // Load-bearing: regressions that silently no-op this shortcut would
        // break security monitoring — the queue delta is the strongest
        // observable signal until the dispatcher runtime-in-runtime bug is
        // fixed and we can assert on EventType::LoginFailure.
        let before = dispatcher_stats().total_written;
        auth_failure("alice", "invalid credentials");
        yield_to_dispatcher().await;
        let after = dispatcher_stats().total_written;
        assert!(
            after > before,
            "auth_failure() should enqueue at least one event for audit (before={before}, after={after})"
        );
    }
}

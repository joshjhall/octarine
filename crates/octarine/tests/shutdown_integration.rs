//! Integration tests for the graceful shutdown module (issue #413).
//!
//! `runtime/shutdown/{coordinator,hooks,functions,signals,restart}.rs` had no
//! tests at all — not inline, not integration. These tests drive the public
//! `octarine::runtime::shutdown` surface on a real tokio runtime.
//!
//! ## Deliberately not covered
//!
//! `wait_for_shutdown()` and `ShutdownCoordinator::wait_for_signal()` install
//! real SIGTERM/SIGINT handlers and block until the process is actually
//! signalled; calling either here would hang the suite. Their observable
//! effects are exercised through the manual-trigger siblings
//! (`trigger()` / `trigger_with_reason()`), which drive the same phase,
//! token, and broadcast transitions.
//!
//! `ShutdownCoordinator::with_hook()` is also avoided: it takes a
//! `blocking_lock()` on the hook list, which panics inside an async runtime.
//! It is documented as an initialization-time builder; `add_hook()` is the
//! async-context equivalent and is what these tests use.
//!
//! ## Timing
//!
//! Hook timeouts are expressed as short `Duration`s on `HookConfig`, so the
//! implementation's own timer drives the test rather than a wall-clock sleep
//! in the test body (`octarine-test-resilience`).

#![allow(clippy::panic, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use octarine::observe::Problem;
use octarine::runtime::shutdown::{
    HookConfig, RestartCoordinator, RestartIntent, RestartState, ShutdownCoordinator,
    ShutdownPhase, ShutdownReason, ShutdownSignal, shutdown_coordinator,
};
use tokio::sync::Mutex;

// ============================================================================
// Construction and configuration
// ============================================================================

/// A default coordinator is running, not draining, and not shutting down.
#[tokio::test]
async fn test_coordinator_starts_in_running_state() {
    let coordinator = ShutdownCoordinator::new();

    assert_eq!(coordinator.phase().await, ShutdownPhase::Running);
    assert!(!coordinator.is_shutting_down());
    assert!(coordinator.is_healthy());
    assert!(
        !coordinator.is_draining_enabled(),
        "draining is opt-in via with_drain_timeout"
    );
    assert!(
        coordinator.trigger_signal().await.is_none(),
        "no signal has been recorded yet"
    );
    assert!(coordinator.reason().await.is_none());
}

/// `with_drain_timeout` both enables draining and stores the timeout, and the
/// stored value differs from the 5s default so a stubbed getter would fail.
#[tokio::test]
async fn test_with_drain_timeout_enables_and_stores() {
    let default = ShutdownCoordinator::new();
    assert!(!default.is_draining_enabled());
    assert_eq!(default.drain_timeout(), Duration::from_secs(5));

    let configured = ShutdownCoordinator::new().with_drain_timeout(Duration::from_secs(12));
    assert!(configured.is_draining_enabled());
    assert_eq!(configured.drain_timeout(), Duration::from_secs(12));
}

/// `shutdown_coordinator()` is the constructor shortcut and yields a usable,
/// running coordinator.
#[tokio::test]
async fn test_shutdown_coordinator_shortcut() {
    let coordinator = shutdown_coordinator();

    assert_eq!(coordinator.phase().await, ShutdownPhase::Running);
    assert!(!coordinator.is_shutting_down());
}

// ============================================================================
// Manual trigger
// ============================================================================

/// `trigger()` moves the coordinator into shutdown, cancels the token, and
/// publishes a `Manual` signal to subscribers.
#[tokio::test]
async fn test_trigger_transitions_and_broadcasts() {
    let coordinator = ShutdownCoordinator::new();
    let mut receiver = coordinator.subscribe();
    let token = coordinator.token();

    assert!(!token.is_cancelled(), "token starts uncancelled");

    coordinator.trigger().await;

    assert!(coordinator.is_shutting_down());
    assert_eq!(coordinator.phase().await, ShutdownPhase::ShuttingDown);
    assert!(token.is_cancelled(), "the cancellation token must fire");
    assert_eq!(
        coordinator.trigger_signal().await,
        Some(ShutdownSignal::Manual)
    );
    assert_eq!(
        receiver.recv().await.expect("subscriber receives a signal"),
        ShutdownSignal::Manual
    );
}

/// `trigger()` is idempotent — a second call does not re-broadcast.
#[tokio::test]
async fn test_trigger_is_idempotent() {
    let coordinator = ShutdownCoordinator::new();
    let mut receiver = coordinator.subscribe();

    coordinator.trigger().await;
    coordinator.trigger().await;

    assert_eq!(
        receiver.recv().await.expect("first signal"),
        ShutdownSignal::Manual
    );
    assert!(
        receiver.try_recv().is_err(),
        "a repeated trigger must not publish a second signal"
    );
}

/// `trigger_with_reason` records the structured reason for later inspection.
#[tokio::test]
async fn test_trigger_with_reason_records_reason() {
    let coordinator = ShutdownCoordinator::new();

    coordinator
        .trigger_with_reason(ShutdownReason::FatalError {
            component: "database".to_string(),
            message: "Connection pool exhausted".to_string(),
        })
        .await;

    let reason = coordinator.reason().await.expect("a reason was recorded");
    match reason {
        ShutdownReason::FatalError { component, message } => {
            assert_eq!(component, "database");
            assert_eq!(message, "Connection pool exhausted");
        }
        other => panic!("expected FatalError, got {other:?}"),
    }

    assert!(coordinator.is_shutting_down());
    assert_eq!(coordinator.phase().await, ShutdownPhase::ShuttingDown);
}

/// Health reporting reflects the shutdown transition.
#[tokio::test]
async fn test_health_status_changes_on_trigger() {
    let coordinator = ShutdownCoordinator::new();

    let before = coordinator.health_status().await;
    assert!(
        before.is_healthy(),
        "a running coordinator reports healthy, got {before:?}"
    );

    coordinator.trigger().await;

    let after = coordinator.health_status().await;
    assert!(
        after.is_shutting_down(),
        "after triggering, health must report shutting down, got {after:?}"
    );
    assert!(
        !coordinator.is_healthy(),
        "is_healthy must flip once shutdown is triggered"
    );
}

// ============================================================================
// Hook registration and execution
// ============================================================================

/// A registered hook actually runs, and the returned stats count it.
#[tokio::test]
async fn test_run_hooks_executes_hook_and_counts_success() {
    let coordinator = ShutdownCoordinator::new();
    let ran = Arc::new(AtomicUsize::new(0));

    let counter = Arc::clone(&ran);
    coordinator
        .add_hook("cleanup", move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await;

    let stats = coordinator.run_hooks().await;

    assert_eq!(
        ran.load(Ordering::SeqCst),
        1,
        "the hook body must actually have executed"
    );
    assert_eq!(stats.hooks_registered, 1);
    assert_eq!(stats.hooks_succeeded, 1);
    assert_eq!(stats.hooks_failed, 0);
    assert_eq!(stats.hooks_timed_out, 0);
    assert_eq!(coordinator.phase().await, ShutdownPhase::Complete);
}

/// `run_hooks` with nothing registered is a no-op that still reports zeroes.
#[tokio::test]
async fn test_run_hooks_with_no_hooks() {
    let coordinator = ShutdownCoordinator::new();

    let stats = coordinator.run_hooks().await;

    assert_eq!(stats.hooks_registered, 0);
    assert_eq!(stats.hooks_succeeded, 0);
    assert_eq!(coordinator.phase().await, ShutdownPhase::Complete);
}

/// A hook returning `Err` is counted as failed, not succeeded — and the other
/// hooks still run.
#[tokio::test]
async fn test_failing_hook_is_counted_and_does_not_block_others() {
    let coordinator = ShutdownCoordinator::new();
    let good_ran = Arc::new(AtomicUsize::new(0));

    coordinator
        .add_hook("failing", || async {
            Err(Problem::Runtime("hook blew up".to_string()))
        })
        .await;

    let counter = Arc::clone(&good_ran);
    coordinator
        .add_hook("healthy", move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await;

    let stats = coordinator.run_hooks().await;

    assert_eq!(stats.hooks_registered, 2);
    assert_eq!(
        stats.hooks_failed, 1,
        "the erroring hook must count as failed"
    );
    assert_eq!(stats.hooks_succeeded, 1);
    assert_eq!(
        good_ran.load(Ordering::SeqCst),
        1,
        "a failing hook must not prevent later hooks from running"
    );
}

/// A hook that outlives its configured timeout is counted as timed out.
#[tokio::test]
async fn test_hook_timeout_is_counted() {
    let coordinator = ShutdownCoordinator::new();

    coordinator
        .add_hook_with_config(
            HookConfig::new("slow").with_timeout(Duration::from_millis(20)),
            || async {
                // Far longer than the 20ms hook timeout above.
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(())
            },
        )
        .await;

    let stats = coordinator.run_hooks().await;

    assert_eq!(
        stats.hooks_timed_out, 1,
        "a hook exceeding its timeout must be counted as timed out"
    );
    assert_eq!(stats.hooks_succeeded, 0);
}

/// Hooks run in priority order — lowest priority value first. Asserting the
/// recorded *order* (not merely that both ran) is what makes this meaningful.
#[tokio::test]
async fn test_hooks_run_in_priority_order() {
    let coordinator = ShutdownCoordinator::new();
    let order: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));

    // Registered last-first, so insertion order cannot produce the expected
    // result by accident.
    let log = Arc::clone(&order);
    coordinator
        .add_hook_with_config(HookConfig::new("late").with_priority(20), move || {
            let log = Arc::clone(&log);
            async move {
                log.lock().await.push("late");
                Ok(())
            }
        })
        .await;

    let log = Arc::clone(&order);
    coordinator
        .add_hook_with_config(HookConfig::new("early").with_priority(1), move || {
            let log = Arc::clone(&log);
            async move {
                log.lock().await.push("early");
                Ok(())
            }
        })
        .await;

    coordinator.run_hooks().await;

    assert_eq!(
        order.lock().await.as_slice(),
        ["early", "late"],
        "hooks must execute in ascending priority order"
    );
}

/// `hook_count` tracks registrations, and `deregister_hook` removes exactly
/// one hook — the removed hook then does not run.
#[tokio::test]
async fn test_deregister_hook_removes_it_from_execution() {
    let coordinator = ShutdownCoordinator::new();
    let doomed_ran = Arc::new(AtomicUsize::new(0));
    let kept_ran = Arc::new(AtomicUsize::new(0));

    assert_eq!(coordinator.hook_count().await, 0);

    let counter = Arc::clone(&doomed_ran);
    let handle = coordinator
        .add_hook("doomed", move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await;

    let counter = Arc::clone(&kept_ran);
    coordinator
        .add_hook("kept", move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await;

    assert_eq!(coordinator.hook_count().await, 2);

    assert!(
        coordinator.deregister_hook(handle).await,
        "deregistering a live handle returns true"
    );
    assert_eq!(coordinator.hook_count().await, 1);
    assert!(
        !coordinator.deregister_hook(handle).await,
        "deregistering the same handle twice returns false"
    );

    coordinator.run_hooks().await;

    assert_eq!(
        doomed_ran.load(Ordering::SeqCst),
        0,
        "the deregistered hook must not run"
    );
    assert_eq!(
        kept_ran.load(Ordering::SeqCst),
        1,
        "the remaining hook must still run"
    );
}

/// A hook with retries is re-attempted after a failure and can then succeed.
#[tokio::test]
async fn test_hook_retries_until_success() {
    let coordinator = ShutdownCoordinator::new();
    let attempts = Arc::new(AtomicUsize::new(0));

    let counter = Arc::clone(&attempts);
    coordinator
        .add_hook_with_config(
            HookConfig::new("flaky").with_retries(3, Duration::from_millis(1)),
            move || {
                let counter = Arc::clone(&counter);
                async move {
                    // Fail the first attempt, succeed on the second.
                    if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(Problem::Runtime("transient".to_string()))
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .await;

    let stats = coordinator.run_hooks().await;

    assert_eq!(
        attempts.load(Ordering::SeqCst),
        2,
        "the hook must be retried exactly once before succeeding"
    );
    assert_eq!(stats.hooks_succeeded, 1);
    assert_eq!(stats.hooks_failed, 0);
}

// ============================================================================
// Restart coordination
// ============================================================================

/// A fresh restart coordinator has requested nothing.
#[tokio::test]
async fn test_restart_coordinator_starts_idle() {
    let restart = RestartCoordinator::new();

    assert!(!restart.should_restart());
    assert_eq!(restart.state().await, RestartState::None);
    assert!(restart.intent().await.is_none());
}

/// `request_restart` records the intent and triggers the shutdown it is
/// handed — the two coordinators are wired together.
#[tokio::test]
async fn test_request_restart_records_intent_and_triggers_shutdown() {
    let shutdown = ShutdownCoordinator::new();
    let restart = RestartCoordinator::new();

    restart
        .request_restart(RestartIntent::ConfigReload, &shutdown)
        .await;

    assert!(restart.should_restart());
    assert_eq!(restart.state().await, RestartState::Pending);
    assert_eq!(restart.intent().await, Some(RestartIntent::ConfigReload));
    assert!(
        shutdown.is_shutting_down(),
        "requesting a restart must trigger the shutdown coordinator"
    );
    assert!(
        shutdown.is_restarting(&restart),
        "the shutdown coordinator must report the pending restart"
    );
}

/// `mark_ready` moves Pending → Ready, and `wait_for_ready` then returns true.
#[tokio::test]
async fn test_mark_ready_then_wait_for_ready() {
    let shutdown = ShutdownCoordinator::new();
    let restart = RestartCoordinator::new();

    restart
        .request_restart(RestartIntent::Update, &shutdown)
        .await;
    restart.mark_ready().await;

    assert_eq!(restart.state().await, RestartState::Ready);
    assert!(
        restart.wait_for_ready().await,
        "wait_for_ready returns true once the restart is Ready"
    );
}

/// `cancel` moves Pending → Cancelled, and `wait_for_ready` returns false.
#[tokio::test]
async fn test_cancel_restart() {
    let shutdown = ShutdownCoordinator::new();
    let restart = RestartCoordinator::new();

    restart
        .request_restart(RestartIntent::Scheduled, &shutdown)
        .await;
    restart.cancel().await;

    assert_eq!(restart.state().await, RestartState::Cancelled);
    assert!(
        !restart.wait_for_ready().await,
        "a cancelled restart is not ready"
    );
}

/// `reset` clears intent and state for a new lifecycle.
#[tokio::test]
async fn test_reset_restart_coordinator() {
    let shutdown = ShutdownCoordinator::new();
    let restart = RestartCoordinator::new();

    restart
        .request_restart(
            RestartIntent::Degradation {
                reason: "latency".to_string(),
            },
            &shutdown,
        )
        .await;
    assert!(restart.should_restart());

    restart.reset().await;

    assert!(!restart.should_restart(), "reset clears the request flag");
    assert_eq!(restart.state().await, RestartState::None);
    assert!(restart.intent().await.is_none());
}

/// `run_hooks_for_restart` runs the hooks *and* marks the restart ready in one
/// call — both effects must be observable.
#[tokio::test]
async fn test_run_hooks_for_restart_runs_hooks_and_marks_ready() {
    let shutdown = ShutdownCoordinator::new();
    let restart = RestartCoordinator::new();
    let ran = Arc::new(AtomicUsize::new(0));

    let counter = Arc::clone(&ran);
    shutdown
        .add_hook("cleanup", move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await;

    restart
        .request_restart(RestartIntent::Manual, &shutdown)
        .await;
    shutdown.run_hooks_for_restart(&restart).await;

    assert_eq!(ran.load(Ordering::SeqCst), 1, "the hook must have run");
    assert_eq!(
        restart.state().await,
        RestartState::Ready,
        "a pending restart must be marked ready once hooks finish"
    );
}

/// Without a restart request, `run_hooks_for_restart` still runs hooks but
/// leaves the restart state alone.
#[tokio::test]
async fn test_run_hooks_for_restart_without_request() {
    let shutdown = ShutdownCoordinator::new();
    let restart = RestartCoordinator::new();
    let ran = Arc::new(AtomicUsize::new(0));

    let counter = Arc::clone(&ran);
    shutdown
        .add_hook("cleanup", move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await;

    shutdown.run_hooks_for_restart(&restart).await;

    assert_eq!(ran.load(Ordering::SeqCst), 1, "the hook must still run");
    assert_eq!(
        restart.state().await,
        RestartState::None,
        "an unrequested restart must not be marked ready"
    );
}

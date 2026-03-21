//! Shutdown progress callbacks
//!
//! This module provides callbacks for monitoring shutdown progress,
//! useful for status dashboards and logging.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use super::types::{ShutdownPhase, ShutdownReason, ShutdownSignal, ShutdownStats};

// ============================================================================
// ShutdownProgress
// ============================================================================

/// Progress information during shutdown
///
/// This struct provides a snapshot of shutdown progress that can be used
/// for monitoring, logging, or display purposes.
#[derive(Debug, Clone)]
pub struct ShutdownProgress {
    /// Current shutdown phase
    pub phase: ShutdownPhase,
    /// Signal that triggered shutdown (if any)
    pub signal: Option<ShutdownSignal>,
    /// Reason for shutdown (if provided)
    pub reason: Option<ShutdownReason>,
    /// Name of the hook currently executing (if any)
    pub current_hook: Option<String>,
    /// Number of hooks completed
    pub hooks_completed: usize,
    /// Total number of hooks to run
    pub hooks_total: usize,
    /// Time elapsed since shutdown started
    pub elapsed: Duration,
}

impl ShutdownProgress {
    /// Calculate progress as a percentage (0.0 - 1.0)
    pub fn percentage(&self) -> f64 {
        if self.hooks_total == 0 {
            if self.phase == ShutdownPhase::Complete {
                1.0
            } else {
                0.0
            }
        } else {
            self.hooks_completed as f64 / self.hooks_total as f64
        }
    }

    /// Check if shutdown is complete
    pub fn is_complete(&self) -> bool {
        self.phase.is_finished()
    }
}

impl std::fmt::Display for ShutdownProgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pct = (self.percentage() * 100.0) as u32;

        match self.phase {
            ShutdownPhase::Running => write!(f, "running"),
            ShutdownPhase::Draining => write!(f, "draining... ({}ms)", self.elapsed.as_millis()),
            ShutdownPhase::ShuttingDown => {
                if let Some(hook) = &self.current_hook {
                    write!(
                        f,
                        "[{}%] running hook '{}' ({}/{})",
                        pct, hook, self.hooks_completed, self.hooks_total
                    )
                } else {
                    write!(
                        f,
                        "[{}%] shutting down ({}/{})",
                        pct, self.hooks_completed, self.hooks_total
                    )
                }
            }
            ShutdownPhase::Complete => write!(
                f,
                "complete ({} hooks in {}ms)",
                self.hooks_total,
                self.elapsed.as_millis()
            ),
            ShutdownPhase::ForcedShutdown => {
                write!(f, "forced shutdown after {}ms", self.elapsed.as_millis())
            }
        }
    }
}

// ============================================================================
// ShutdownEvent
// ============================================================================

/// Events emitted during shutdown
///
/// Subscribe to these events for real-time shutdown monitoring.
#[derive(Debug, Clone)]
pub enum ShutdownEvent {
    /// Shutdown has been triggered
    Started {
        /// Signal that triggered shutdown
        signal: ShutdownSignal,
        /// Reason (if provided)
        reason: Option<ShutdownReason>,
    },
    /// Draining phase started
    DrainingStarted {
        /// Number of in-flight requests
        in_flight: usize,
    },
    /// Draining phase completed
    DrainingCompleted {
        /// Whether draining completed successfully (vs timeout)
        success: bool,
        /// Remaining in-flight requests (0 if success)
        remaining: usize,
    },
    /// A hook is starting
    HookStarting {
        /// Hook name
        name: String,
        /// Hook index (0-based)
        index: usize,
        /// Total hooks
        total: usize,
    },
    /// A hook completed successfully
    HookCompleted {
        /// Hook name
        name: String,
        /// Duration of hook execution
        duration: Duration,
    },
    /// A hook failed
    HookFailed {
        /// Hook name
        name: String,
        /// Error message
        error: String,
        /// Duration before failure
        duration: Duration,
    },
    /// A hook timed out
    HookTimedOut {
        /// Hook name
        name: String,
        /// Configured timeout
        timeout: Duration,
    },
    /// Shutdown complete
    Completed {
        /// Final statistics
        stats: ShutdownStats,
    },
    /// Shutdown was forced due to timeout
    ForcedShutdown {
        /// Statistics at time of force
        stats: ShutdownStats,
        /// Number of hooks skipped
        skipped: usize,
    },
}

// ============================================================================
// ProgressCallback
// ============================================================================

/// A callback function for shutdown progress updates
pub type ProgressCallback = Arc<dyn Fn(ShutdownProgress) + Send + Sync>;

/// A callback function for shutdown events
pub type EventCallback = Arc<dyn Fn(ShutdownEvent) + Send + Sync>;

// ============================================================================
// ProgressReporter
// ============================================================================

/// Reports shutdown progress to registered callbacks
///
/// This is used internally by the coordinator to emit progress updates.
#[derive(Default)]
pub(super) struct ProgressReporter {
    /// Progress callbacks
    progress_callbacks: RwLock<Vec<ProgressCallback>>,
    /// Event callbacks
    event_callbacks: RwLock<Vec<EventCallback>>,
}

impl ProgressReporter {
    /// Create a new progress reporter
    pub fn new() -> Self {
        Self {
            progress_callbacks: RwLock::new(Vec::new()),
            event_callbacks: RwLock::new(Vec::new()),
        }
    }

    /// Register a progress callback
    pub async fn on_progress(&self, callback: ProgressCallback) {
        self.progress_callbacks.write().await.push(callback);
    }

    /// Register an event callback
    pub async fn on_event(&self, callback: EventCallback) {
        self.event_callbacks.write().await.push(callback);
    }

    /// Emit a progress update
    #[allow(dead_code)] // Will be used when integrated into hooks module
    pub async fn emit_progress(&self, progress: ShutdownProgress) {
        let callbacks = self.progress_callbacks.read().await;
        for callback in callbacks.iter() {
            callback(progress.clone());
        }
    }

    /// Emit an event
    #[allow(dead_code)] // Will be used when integrated into hooks module
    pub async fn emit_event(&self, event: ShutdownEvent) {
        let callbacks = self.event_callbacks.read().await;
        for callback in callbacks.iter() {
            callback(event.clone());
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn test_progress_percentage_no_hooks() {
        let progress = ShutdownProgress {
            phase: ShutdownPhase::Running,
            signal: None,
            reason: None,
            current_hook: None,
            hooks_completed: 0,
            hooks_total: 0,
            elapsed: Duration::from_secs(0),
        };
        assert_eq!(progress.percentage(), 0.0);

        let complete = ShutdownProgress {
            phase: ShutdownPhase::Complete,
            ..progress.clone()
        };
        assert_eq!(complete.percentage(), 1.0);
    }

    #[test]
    fn test_progress_percentage_with_hooks() {
        let progress = ShutdownProgress {
            phase: ShutdownPhase::ShuttingDown,
            signal: Some(ShutdownSignal::Terminate),
            reason: None,
            current_hook: Some("cleanup".to_string()),
            hooks_completed: 2,
            hooks_total: 4,
            elapsed: Duration::from_millis(500),
        };
        assert_eq!(progress.percentage(), 0.5);
    }

    #[test]
    fn test_progress_display() {
        let running = ShutdownProgress {
            phase: ShutdownPhase::Running,
            signal: None,
            reason: None,
            current_hook: None,
            hooks_completed: 0,
            hooks_total: 0,
            elapsed: Duration::from_secs(0),
        };
        assert_eq!(running.to_string(), "running");

        let draining = ShutdownProgress {
            phase: ShutdownPhase::Draining,
            elapsed: Duration::from_millis(500),
            ..running.clone()
        };
        assert_eq!(draining.to_string(), "draining... (500ms)");

        let shutting_down = ShutdownProgress {
            phase: ShutdownPhase::ShuttingDown,
            current_hook: Some("database".to_string()),
            hooks_completed: 1,
            hooks_total: 3,
            elapsed: Duration::from_millis(200),
            ..running.clone()
        };
        assert_eq!(
            shutting_down.to_string(),
            "[33%] running hook 'database' (1/3)"
        );

        let complete = ShutdownProgress {
            phase: ShutdownPhase::Complete,
            hooks_completed: 3,
            hooks_total: 3,
            elapsed: Duration::from_millis(1500),
            ..running.clone()
        };
        assert_eq!(complete.to_string(), "complete (3 hooks in 1500ms)");

        let forced = ShutdownProgress {
            phase: ShutdownPhase::ForcedShutdown,
            elapsed: Duration::from_millis(30000),
            ..running
        };
        assert_eq!(forced.to_string(), "forced shutdown after 30000ms");
    }

    #[tokio::test]
    async fn test_progress_reporter_callbacks() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let reporter = ProgressReporter::new();
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        reporter
            .on_progress(Arc::new(move |_| {
                call_count_clone.fetch_add(1, Ordering::SeqCst);
            }))
            .await;

        let progress = ShutdownProgress {
            phase: ShutdownPhase::ShuttingDown,
            signal: Some(ShutdownSignal::Terminate),
            reason: None,
            current_hook: None,
            hooks_completed: 0,
            hooks_total: 1,
            elapsed: Duration::from_secs(0),
        };

        reporter.emit_progress(progress.clone()).await;
        reporter.emit_progress(progress).await;

        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_event_reporter_callbacks() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let reporter = ProgressReporter::new();
        let event_count = Arc::new(AtomicUsize::new(0));
        let event_count_clone = Arc::clone(&event_count);

        reporter
            .on_event(Arc::new(move |_| {
                event_count_clone.fetch_add(1, Ordering::SeqCst);
            }))
            .await;

        reporter
            .emit_event(ShutdownEvent::Started {
                signal: ShutdownSignal::Terminate,
                reason: None,
            })
            .await;

        reporter
            .emit_event(ShutdownEvent::HookStarting {
                name: "test".to_string(),
                index: 0,
                total: 1,
            })
            .await;

        assert_eq!(event_count.load(Ordering::SeqCst), 2);
    }
}

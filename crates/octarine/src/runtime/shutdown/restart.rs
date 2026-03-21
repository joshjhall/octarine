//! Graceful restart support
//!
//! This module provides support for graceful restarts, allowing a service
//! to signal that it wants to restart rather than fully shutdown.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::RwLock;

use crate::observe;

use super::coordinator::ShutdownCoordinator;

// ============================================================================
// RestartIntent
// ============================================================================

/// Intent for restart behavior
///
/// This enum describes why a restart was requested and can influence
/// restart behavior (e.g., whether to reload configuration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartIntent {
    /// Restart to pick up configuration changes
    ConfigReload,
    /// Restart to apply updates
    Update,
    /// Restart due to memory pressure (clean slate)
    MemoryPressure,
    /// Restart due to detected degradation
    Degradation {
        /// Description of the degradation
        reason: String,
    },
    /// Scheduled restart (maintenance window)
    Scheduled,
    /// Manual restart requested by operator
    Manual,
    /// Custom restart reason
    Custom {
        /// Custom reason code
        code: String,
        /// Custom message
        message: String,
    },
}

impl std::fmt::Display for RestartIntent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConfigReload => write!(f, "configuration reload"),
            Self::Update => write!(f, "update"),
            Self::MemoryPressure => write!(f, "memory pressure"),
            Self::Degradation { reason } => write!(f, "degradation: {}", reason),
            Self::Scheduled => write!(f, "scheduled"),
            Self::Manual => write!(f, "manual"),
            Self::Custom { code, message } => write!(f, "[{}] {}", code, message),
        }
    }
}

// ============================================================================
// RestartState
// ============================================================================

/// State of a restart request
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartState {
    /// No restart requested
    None,
    /// Restart requested, waiting for shutdown
    Pending,
    /// Shutdown complete, ready to restart
    Ready,
    /// Restart was cancelled
    Cancelled,
}

impl std::fmt::Display for RestartState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Pending => write!(f, "pending"),
            Self::Ready => write!(f, "ready"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

// ============================================================================
// RestartCoordinator
// ============================================================================

/// Coordinates graceful restarts
///
/// This struct works alongside `ShutdownCoordinator` to manage restarts.
/// When a restart is requested, it triggers shutdown and tracks the restart
/// intent so the application knows to restart after cleanup.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::shutdown::{ShutdownCoordinator, RestartCoordinator, RestartIntent};
///
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// let shutdown = ShutdownCoordinator::new();
/// let restart = RestartCoordinator::new();
///
/// // Request a restart due to config change
/// restart.request_restart(RestartIntent::ConfigReload, &shutdown).await;
///
/// // After shutdown completes, check if we should restart
/// if restart.should_restart() {
///     println!("Restarting: {}", restart.intent().await.unwrap());
///     // ... spawn new process or re-initialize ...
/// }
/// # });
/// ```
pub struct RestartCoordinator {
    /// Whether a restart has been requested
    restart_requested: Arc<AtomicBool>,
    /// The intent for the restart
    intent: Arc<RwLock<Option<RestartIntent>>>,
    /// Current restart state
    state: Arc<RwLock<RestartState>>,
}

impl Default for RestartCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl RestartCoordinator {
    /// Create a new restart coordinator
    pub fn new() -> Self {
        Self {
            restart_requested: Arc::new(AtomicBool::new(false)),
            intent: Arc::new(RwLock::new(None)),
            state: Arc::new(RwLock::new(RestartState::None)),
        }
    }

    /// Request a graceful restart
    ///
    /// This triggers shutdown on the provided coordinator and marks the
    /// restart as pending. After shutdown completes, `should_restart()`
    /// will return `true`.
    ///
    /// # Arguments
    ///
    /// * `intent` - The reason for the restart
    /// * `shutdown` - The shutdown coordinator to trigger
    pub async fn request_restart(&self, intent: RestartIntent, shutdown: &ShutdownCoordinator) {
        if self.restart_requested.swap(true, Ordering::SeqCst) {
            // Already requested
            observe::warn(
                "restart_already_requested",
                "Restart already requested, ignoring duplicate request",
            );
            return;
        }

        observe::info(
            "restart_requested",
            format!("Graceful restart requested: {}", intent),
        );

        *self.intent.write().await = Some(intent);
        *self.state.write().await = RestartState::Pending;

        // Trigger shutdown
        shutdown.trigger().await;
    }

    /// Check if a restart has been requested
    pub fn should_restart(&self) -> bool {
        self.restart_requested.load(Ordering::SeqCst)
    }

    /// Get the restart intent (if any)
    pub async fn intent(&self) -> Option<RestartIntent> {
        self.intent.read().await.clone()
    }

    /// Get the current restart state
    pub async fn state(&self) -> RestartState {
        *self.state.read().await
    }

    /// Mark the restart as ready (call after shutdown completes)
    ///
    /// This transitions from `Pending` to `Ready`, indicating that
    /// shutdown has completed and the application can now restart.
    pub async fn mark_ready(&self) {
        if *self.state.read().await == RestartState::Pending {
            *self.state.write().await = RestartState::Ready;
            observe::info("restart_ready", "Shutdown complete, ready to restart");
        }
    }

    /// Cancel a pending restart
    ///
    /// This cancels a restart that was requested but hasn't completed yet.
    /// Note that if shutdown has already been triggered, it will continue
    /// but the application won't restart afterward.
    pub async fn cancel(&self) {
        let current_state = *self.state.read().await;
        if current_state == RestartState::Pending {
            *self.state.write().await = RestartState::Cancelled;
            observe::info("restart_cancelled", "Restart request cancelled");
        }
    }

    /// Reset the restart coordinator for a new lifecycle
    ///
    /// Call this after a restart has been performed to reset the state.
    pub async fn reset(&self) {
        self.restart_requested.store(false, Ordering::SeqCst);
        *self.intent.write().await = None;
        *self.state.write().await = RestartState::None;
        observe::debug("restart_reset", "Restart coordinator reset");
    }

    /// Wait for the restart to be ready
    ///
    /// This method blocks until the restart state transitions to `Ready`
    /// or `Cancelled`. Returns `true` if ready to restart, `false` if cancelled.
    pub async fn wait_for_ready(&self) -> bool {
        loop {
            let state = *self.state.read().await;
            match state {
                RestartState::Ready => return true,
                RestartState::Cancelled => return false,
                RestartState::None => return false,
                RestartState::Pending => {
                    // Poll periodically
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }
}

impl ShutdownCoordinator {
    /// Check if shutdown was triggered for a restart
    ///
    /// This is a convenience method that checks if the given restart
    /// coordinator has a pending or ready restart.
    pub fn is_restarting(&self, restart: &RestartCoordinator) -> bool {
        restart.should_restart()
    }

    /// Run hooks and mark restart as ready
    ///
    /// This is a convenience method that runs shutdown hooks and then
    /// marks the restart coordinator as ready if a restart was requested.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use octarine::runtime::shutdown::{ShutdownCoordinator, RestartCoordinator, RestartIntent};
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let shutdown = ShutdownCoordinator::new();
    /// let restart = RestartCoordinator::new();
    ///
    /// // ... setup hooks ...
    ///
    /// // Wait for signal
    /// shutdown.wait_for_signal().await;
    ///
    /// // Run hooks and prepare for potential restart
    /// shutdown.run_hooks_for_restart(&restart).await;
    ///
    /// // Check if we should restart
    /// if restart.should_restart() {
    ///     // Restart the application
    /// }
    /// # });
    /// ```
    pub async fn run_hooks_for_restart(&self, restart: &RestartCoordinator) {
        let stats = self.run_hooks().await;

        // If a restart was requested, mark it as ready
        if restart.should_restart() {
            restart.mark_ready().await;
        }

        observe::info(
            "shutdown_for_restart_complete",
            format!(
                "Shutdown complete (restart={}): {} hooks in {}ms",
                restart.should_restart(),
                stats.hooks_registered,
                stats.duration_ms
            ),
        );
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::runtime::shutdown::ShutdownPhase;

    #[tokio::test]
    async fn test_restart_coordinator_creation() {
        let restart = RestartCoordinator::new();

        assert!(!restart.should_restart());
        assert!(restart.intent().await.is_none());
        assert_eq!(restart.state().await, RestartState::None);
    }

    #[tokio::test]
    async fn test_request_restart() {
        let shutdown = ShutdownCoordinator::new();
        let restart = RestartCoordinator::new();

        restart
            .request_restart(RestartIntent::ConfigReload, &shutdown)
            .await;

        assert!(restart.should_restart());
        assert_eq!(restart.intent().await, Some(RestartIntent::ConfigReload));
        assert_eq!(restart.state().await, RestartState::Pending);
        assert!(shutdown.is_shutting_down());
    }

    #[tokio::test]
    async fn test_mark_ready() {
        let shutdown = ShutdownCoordinator::new();
        let restart = RestartCoordinator::new();

        restart
            .request_restart(RestartIntent::Manual, &shutdown)
            .await;

        assert_eq!(restart.state().await, RestartState::Pending);

        restart.mark_ready().await;

        assert_eq!(restart.state().await, RestartState::Ready);
    }

    #[tokio::test]
    async fn test_cancel_restart() {
        let shutdown = ShutdownCoordinator::new();
        let restart = RestartCoordinator::new();

        restart
            .request_restart(RestartIntent::Scheduled, &shutdown)
            .await;

        restart.cancel().await;

        assert_eq!(restart.state().await, RestartState::Cancelled);
        // Still marked as restart requested (shutdown continues)
        assert!(restart.should_restart());
    }

    #[tokio::test]
    async fn test_reset() {
        let shutdown = ShutdownCoordinator::new();
        let restart = RestartCoordinator::new();

        restart
            .request_restart(RestartIntent::Update, &shutdown)
            .await;

        restart.mark_ready().await;
        restart.reset().await;

        assert!(!restart.should_restart());
        assert!(restart.intent().await.is_none());
        assert_eq!(restart.state().await, RestartState::None);
    }

    #[tokio::test]
    async fn test_wait_for_ready() {
        let shutdown = ShutdownCoordinator::new();
        let restart = RestartCoordinator::new();

        restart
            .request_restart(RestartIntent::Manual, &shutdown)
            .await;

        // Spawn task to mark ready after delay
        let restart_clone = RestartCoordinator {
            restart_requested: Arc::clone(&restart.restart_requested),
            intent: Arc::clone(&restart.intent),
            state: Arc::clone(&restart.state),
        };

        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            restart_clone.mark_ready().await;
        });

        let ready = restart.wait_for_ready().await;
        assert!(ready);
        assert_eq!(restart.state().await, RestartState::Ready);
    }

    #[tokio::test]
    async fn test_restart_intent_display() {
        assert_eq!(
            RestartIntent::ConfigReload.to_string(),
            "configuration reload"
        );
        assert_eq!(RestartIntent::Update.to_string(), "update");
        assert_eq!(RestartIntent::MemoryPressure.to_string(), "memory pressure");
        assert_eq!(
            RestartIntent::Degradation {
                reason: "high latency".to_string()
            }
            .to_string(),
            "degradation: high latency"
        );
        assert_eq!(RestartIntent::Scheduled.to_string(), "scheduled");
        assert_eq!(RestartIntent::Manual.to_string(), "manual");
        assert_eq!(
            RestartIntent::Custom {
                code: "RESTART001".to_string(),
                message: "custom reason".to_string()
            }
            .to_string(),
            "[RESTART001] custom reason"
        );
    }

    #[tokio::test]
    async fn test_is_restarting() {
        let shutdown = ShutdownCoordinator::new();
        let restart = RestartCoordinator::new();

        assert!(!shutdown.is_restarting(&restart));

        restart
            .request_restart(RestartIntent::Manual, &shutdown)
            .await;

        assert!(shutdown.is_restarting(&restart));
    }

    #[tokio::test]
    async fn test_run_hooks_for_restart() {
        let shutdown = ShutdownCoordinator::new();
        let restart = RestartCoordinator::new();

        shutdown.add_hook("test", || async { Ok(()) }).await;

        restart
            .request_restart(RestartIntent::ConfigReload, &shutdown)
            .await;

        shutdown.run_hooks_for_restart(&restart).await;

        assert_eq!(restart.state().await, RestartState::Ready);
        assert_eq!(shutdown.phase().await, ShutdownPhase::Complete);
    }
}

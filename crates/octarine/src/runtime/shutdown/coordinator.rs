//! Shutdown coordinator implementation
//!
//! The `ShutdownCoordinator` manages graceful shutdown of services with
//! signal handling, ordered hooks, and timeout management.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
use std::time::Duration;

use tokio::sync::{Mutex, RwLock, broadcast};
use tokio_util::sync::CancellationToken;

use crate::observe;

use super::progress::{EventCallback, ProgressCallback, ProgressReporter};
use super::types::{
    ShutdownHealthStatus, ShutdownHook, ShutdownPhase, ShutdownReason, ShutdownSignal,
    ShutdownStats,
};

// ============================================================================
// ShutdownCoordinator
// ============================================================================

/// Coordinates graceful shutdown across services
///
/// The coordinator handles:
/// - Signal detection (SIGTERM, SIGINT, Ctrl+C)
/// - Ordered execution of cleanup hooks
/// - Timeout management with force-quit
/// - Health status during shutdown
///
/// # Example
///
/// ```rust,no_run
/// use octarine::runtime::shutdown::ShutdownCoordinator;
/// use std::time::Duration;
///
/// let shutdown = ShutdownCoordinator::new()
///     .with_timeout(Duration::from_secs(30));
///
/// // Wait for shutdown signal
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// shutdown.wait_for_signal().await;
/// shutdown.run_hooks().await;
/// # });
/// ```
pub struct ShutdownCoordinator {
    /// Cancellation token for cooperative shutdown
    pub(super) cancel_token: CancellationToken,
    /// Broadcast channel for shutdown signal
    pub(super) signal_tx: broadcast::Sender<ShutdownSignal>,
    /// Registered shutdown hooks
    pub(super) hooks: Arc<Mutex<Vec<ShutdownHook>>>,
    /// Shutdown timeout
    pub(super) timeout: Duration,
    /// Current shutdown phase
    pub(super) phase: Arc<RwLock<ShutdownPhase>>,
    /// Whether shutdown has been triggered
    pub(super) triggered: Arc<AtomicBool>,
    /// The signal that triggered shutdown
    pub(super) trigger_signal: Arc<RwLock<Option<ShutdownSignal>>>,
    /// Hook counter for ordering (priority)
    pub(super) hook_counter: AtomicUsize,
    /// Hook ID counter for unique identification
    pub(super) hook_id_counter: AtomicU64,
    /// Shutdown statistics
    pub(super) stats: Arc<RwLock<ShutdownStats>>,
    /// Reason for shutdown (if triggered with reason)
    pub(super) reason: Arc<RwLock<Option<ShutdownReason>>>,
    /// Drain timeout (time to wait for in-flight requests before running hooks)
    pub(super) drain_timeout: Duration,
    /// Whether draining is enabled
    pub(super) draining_enabled: bool,
    /// Progress reporter for callbacks
    pub(super) progress_reporter: Arc<ProgressReporter>,
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownCoordinator {
    /// Create a new shutdown coordinator with default settings
    ///
    /// Default timeout is 30 seconds.
    pub fn new() -> Self {
        let (signal_tx, _) = broadcast::channel(16);

        observe::debug(
            "shutdown_coordinator_created",
            "Shutdown coordinator initialized with 30s timeout",
        );

        Self {
            cancel_token: CancellationToken::new(),
            signal_tx,
            hooks: Arc::new(Mutex::new(Vec::new())),
            timeout: Duration::from_secs(30),
            phase: Arc::new(RwLock::new(ShutdownPhase::Running)),
            triggered: Arc::new(AtomicBool::new(false)),
            trigger_signal: Arc::new(RwLock::new(None)),
            hook_counter: AtomicUsize::new(0),
            hook_id_counter: AtomicU64::new(1), // Start at 1 so 0 is never valid
            stats: Arc::new(RwLock::new(ShutdownStats::default())),
            reason: Arc::new(RwLock::new(None)),
            drain_timeout: Duration::from_secs(5),
            draining_enabled: false,
            progress_reporter: Arc::new(ProgressReporter::new()),
        }
    }

    /// Set the shutdown timeout
    ///
    /// After this duration, remaining hooks are skipped and shutdown is forced.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        observe::debug(
            "shutdown_timeout_configured",
            format!("Shutdown timeout set to {}ms", timeout.as_millis()),
        );
        self
    }

    /// Enable pre-shutdown draining phase
    ///
    /// When enabled, the coordinator will enter a `Draining` phase before
    /// running shutdown hooks. This allows load balancers to stop sending
    /// traffic and in-flight requests to complete.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time to wait in the draining phase
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::runtime::shutdown::ShutdownCoordinator;
    /// use std::time::Duration;
    ///
    /// let coordinator = ShutdownCoordinator::new()
    ///     .with_drain_timeout(Duration::from_secs(10))
    ///     .with_timeout(Duration::from_secs(30));
    /// ```
    #[must_use]
    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self.draining_enabled = true;
        observe::debug(
            "shutdown_drain_configured",
            format!("Drain timeout set to {}ms", timeout.as_millis()),
        );
        self
    }

    /// Check if draining is enabled
    pub fn is_draining_enabled(&self) -> bool {
        self.draining_enabled
    }

    /// Get the drain timeout
    pub fn drain_timeout(&self) -> Duration {
        self.drain_timeout
    }

    /// Get a cancellation token for cooperative shutdown
    ///
    /// Workers can use this token to detect shutdown and stop gracefully.
    pub fn token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// Subscribe to shutdown signals
    ///
    /// Returns a receiver that will get the shutdown signal when triggered.
    pub fn subscribe(&self) -> broadcast::Receiver<ShutdownSignal> {
        self.signal_tx.subscribe()
    }

    /// Check if shutdown has been triggered
    pub fn is_shutting_down(&self) -> bool {
        self.triggered.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get the current shutdown phase
    pub async fn phase(&self) -> ShutdownPhase {
        *self.phase.read().await
    }

    /// Get the signal that triggered shutdown (if any)
    pub async fn trigger_signal(&self) -> Option<ShutdownSignal> {
        *self.trigger_signal.read().await
    }

    /// Get shutdown statistics
    pub async fn stats(&self) -> ShutdownStats {
        self.stats.read().await.clone()
    }

    /// Get the reason for shutdown (if triggered with a reason)
    pub async fn reason(&self) -> Option<ShutdownReason> {
        self.reason.read().await.clone()
    }

    /// Check if the service should report as healthy
    ///
    /// Returns `false` once shutdown has been triggered, which can be used
    /// to fail health checks and stop receiving new traffic.
    pub fn is_healthy(&self) -> bool {
        !self.is_shutting_down()
    }

    /// Get detailed health status for Kubernetes-style probes
    ///
    /// Returns `ShutdownHealthStatus::Healthy` during normal operation, and
    /// `ShutdownHealthStatus::ShuttingDown` once shutdown has been triggered.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::runtime::shutdown::{ShutdownCoordinator, ShutdownHealthStatus};
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let coordinator = ShutdownCoordinator::new();
    ///
    /// // For readiness probe (should stop receiving traffic during shutdown)
    /// if coordinator.health_status().await.is_ready() {
    ///     // Accept new connections
    /// }
    ///
    /// // For liveness probe (service is still alive even during shutdown)
    /// if coordinator.health_status().await.is_alive() {
    ///     // Report as alive
    /// }
    /// # });
    /// ```
    pub async fn health_status(&self) -> ShutdownHealthStatus {
        if self.is_shutting_down() {
            let phase = *self.phase.read().await;
            let signal = *self.trigger_signal.read().await;
            ShutdownHealthStatus::ShuttingDown { phase, signal }
        } else {
            ShutdownHealthStatus::Healthy
        }
    }

    /// Register a callback for shutdown progress updates
    ///
    /// The callback will be called whenever shutdown progress changes,
    /// such as when a hook starts, completes, or fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::runtime::shutdown::ShutdownCoordinator;
    /// use std::sync::Arc;
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let coordinator = ShutdownCoordinator::new();
    ///
    /// coordinator.on_progress(Arc::new(|progress| {
    ///     println!("Shutdown progress: {}", progress);
    /// })).await;
    /// # });
    /// ```
    pub async fn on_progress(&self, callback: ProgressCallback) {
        self.progress_reporter.on_progress(callback).await;
    }

    /// Register a callback for shutdown events
    ///
    /// The callback will be called for discrete shutdown events,
    /// such as hooks starting, completing, or timing out.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::runtime::shutdown::{ShutdownCoordinator, ShutdownEvent};
    /// use std::sync::Arc;
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let coordinator = ShutdownCoordinator::new();
    ///
    /// coordinator.on_event(Arc::new(|event| {
    ///     match event {
    ///         ShutdownEvent::HookStarting { name, .. } => {
    ///             println!("Starting hook: {}", name);
    ///         }
    ///         ShutdownEvent::Completed { stats } => {
    ///             println!("Shutdown complete: {:?}", stats);
    ///         }
    ///         _ => {}
    ///     }
    /// })).await;
    /// # });
    /// ```
    pub async fn on_event(&self, callback: EventCallback) {
        self.progress_reporter.on_event(callback).await;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;

    #[tokio::test]
    async fn test_shutdown_coordinator_creation() {
        let coordinator = ShutdownCoordinator::new();
        assert!(!coordinator.is_shutting_down());
        assert_eq!(coordinator.phase().await, ShutdownPhase::Running);
    }

    #[tokio::test]
    async fn test_health_check() {
        let coordinator = ShutdownCoordinator::new();

        assert!(coordinator.is_healthy());
        coordinator.trigger().await;
        assert!(!coordinator.is_healthy());
    }

    #[tokio::test]
    async fn test_timeout_configuration() {
        let coordinator = ShutdownCoordinator::new().with_timeout(Duration::from_secs(60));

        assert_eq!(coordinator.timeout, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_health_status_healthy() {
        let coordinator = ShutdownCoordinator::new();

        let status = coordinator.health_status().await;
        assert_eq!(status, ShutdownHealthStatus::Healthy);
        assert!(status.is_healthy());
        assert!(status.is_ready());
        assert!(status.is_alive());
        assert!(!status.is_shutting_down());
    }

    #[tokio::test]
    async fn test_health_status_shutting_down() {
        let coordinator = ShutdownCoordinator::new();

        coordinator.trigger().await;

        let status = coordinator.health_status().await;
        match &status {
            ShutdownHealthStatus::ShuttingDown { phase, signal } => {
                assert_eq!(*phase, ShutdownPhase::ShuttingDown);
                assert_eq!(*signal, Some(ShutdownSignal::Manual));
            }
            _ => panic!("Expected ShuttingDown status"),
        }
        assert!(!status.is_healthy());
        assert!(!status.is_ready());
        assert!(status.is_alive()); // Still alive during shutdown
        assert!(status.is_shutting_down());
    }

    #[tokio::test]
    async fn test_health_status_display() {
        let healthy = ShutdownHealthStatus::Healthy;
        assert_eq!(healthy.to_string(), "healthy");

        let shutting_down = ShutdownHealthStatus::ShuttingDown {
            phase: ShutdownPhase::ShuttingDown,
            signal: Some(ShutdownSignal::Terminate),
        };
        assert_eq!(
            shutting_down.to_string(),
            "shutting_down (shutting_down, triggered by SIGTERM)"
        );

        let unhealthy = ShutdownHealthStatus::Unhealthy {
            reason: "database connection lost".to_string(),
        };
        assert_eq!(unhealthy.to_string(), "unhealthy: database connection lost");
    }
}

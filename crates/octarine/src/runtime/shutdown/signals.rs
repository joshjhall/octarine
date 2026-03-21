//! Signal handling for shutdown coordination
//!
//! This module handles OS signals (SIGTERM, SIGINT) and manual triggers.

use std::sync::atomic::Ordering;

use crate::observe;

use super::coordinator::ShutdownCoordinator;
use super::types::{ShutdownPhase, ShutdownReason, ShutdownSignal};

impl ShutdownCoordinator {
    /// Manually trigger shutdown
    ///
    /// This is useful for programmatic shutdown (e.g., after a fatal error).
    pub async fn trigger(&self) {
        if self.triggered.swap(true, Ordering::SeqCst) {
            // Already triggered
            return;
        }

        observe::info("shutdown_triggered", "Shutdown triggered manually");

        *self.trigger_signal.write().await = Some(ShutdownSignal::Manual);
        *self.phase.write().await = ShutdownPhase::ShuttingDown;
        self.cancel_token.cancel();
        let _ = self.signal_tx.send(ShutdownSignal::Manual);
    }

    /// Manually trigger shutdown with a structured reason
    ///
    /// This is useful for programmatic shutdown with detailed context about
    /// why shutdown was initiated. The reason is logged and can be queried
    /// via `reason()`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::runtime::shutdown::{ShutdownCoordinator, ShutdownReason};
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let coordinator = ShutdownCoordinator::new();
    ///
    /// // Trigger due to a fatal error
    /// coordinator.trigger_with_reason(ShutdownReason::FatalError {
    ///     component: "database".to_string(),
    ///     message: "Connection pool exhausted".to_string(),
    /// }).await;
    ///
    /// // Check the reason later
    /// if let Some(reason) = coordinator.reason().await {
    ///     println!("Shutdown reason: {}", reason);
    /// }
    /// # });
    /// ```
    pub async fn trigger_with_reason(&self, reason: ShutdownReason) {
        if self.triggered.swap(true, Ordering::SeqCst) {
            // Already triggered
            return;
        }

        observe::info(
            "shutdown_triggered",
            format!("Shutdown triggered: {}", reason),
        );

        *self.reason.write().await = Some(reason);
        *self.trigger_signal.write().await = Some(ShutdownSignal::Manual);
        *self.phase.write().await = ShutdownPhase::ShuttingDown;
        self.cancel_token.cancel();
        let _ = self.signal_tx.send(ShutdownSignal::Manual);
    }

    /// Wait for a shutdown signal (SIGTERM, SIGINT, or manual trigger)
    ///
    /// This method blocks until a shutdown signal is received.
    /// On Unix, it handles SIGTERM and SIGINT.
    /// On Windows, it handles Ctrl+C.
    ///
    /// # Panics
    ///
    /// Panics if signal handlers cannot be installed. This is intentional as
    /// signal handling is critical for graceful shutdown.
    #[allow(clippy::expect_used)]
    pub async fn wait_for_signal(&self) {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};

            let mut sigterm =
                signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
            let mut sigint =
                signal(SignalKind::interrupt()).expect("Failed to install SIGINT handler");

            let signal = tokio::select! {
                _ = sigterm.recv() => ShutdownSignal::Terminate,
                _ = sigint.recv() => ShutdownSignal::Interrupt,
                _ = self.cancel_token.cancelled() => {
                    // Manual trigger
                    return;
                }
            };

            self.handle_signal(signal).await;
        }

        #[cfg(windows)]
        {
            let signal = tokio::select! {
                _ = tokio::signal::ctrl_c() => ShutdownSignal::Interrupt,
                _ = self.cancel_token.cancelled() => {
                    // Manual trigger
                    return;
                }
            };

            self.handle_signal(signal).await;
        }

        #[cfg(not(any(unix, windows)))]
        {
            // Fallback: just wait for manual trigger
            self.cancel_token.cancelled().await;
        }
    }

    /// Handle a received signal
    pub(super) async fn handle_signal(&self, signal: ShutdownSignal) {
        if self.triggered.swap(true, Ordering::SeqCst) {
            // Already triggered, this is a second signal - force immediate shutdown
            observe::warn(
                "shutdown_forced",
                format!(
                    "Received second {} signal, forcing immediate shutdown",
                    signal
                ),
            );
            *self.phase.write().await = ShutdownPhase::ForcedShutdown;
            return;
        }

        observe::info(
            "shutdown_signal_received",
            format!("Received {} signal, initiating graceful shutdown", signal),
        );

        *self.trigger_signal.write().await = Some(signal);
        *self.phase.write().await = ShutdownPhase::ShuttingDown;
        self.cancel_token.cancel();
        let _ = self.signal_tx.send(signal);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::runtime::shutdown::ShutdownCoordinator;

    #[tokio::test]
    async fn test_manual_trigger() {
        let coordinator = ShutdownCoordinator::new();

        assert!(!coordinator.is_shutting_down());
        coordinator.trigger().await;
        assert!(coordinator.is_shutting_down());
        assert_eq!(coordinator.phase().await, ShutdownPhase::ShuttingDown);
        assert_eq!(
            coordinator.trigger_signal().await,
            Some(ShutdownSignal::Manual)
        );
    }

    #[tokio::test]
    async fn test_cancellation_token() {
        let coordinator = ShutdownCoordinator::new();
        let token = coordinator.token();

        assert!(!token.is_cancelled());
        coordinator.trigger().await;
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn test_broadcast_subscription() {
        let coordinator = ShutdownCoordinator::new();
        let mut receiver = coordinator.subscribe();

        coordinator.trigger().await;

        let signal = receiver.recv().await.expect("should receive signal");
        assert_eq!(signal, ShutdownSignal::Manual);
    }

    #[tokio::test]
    async fn test_trigger_with_reason_fatal_error() {
        let coordinator = ShutdownCoordinator::new();

        coordinator
            .trigger_with_reason(ShutdownReason::FatalError {
                component: "database".to_string(),
                message: "Connection pool exhausted".to_string(),
            })
            .await;

        assert!(coordinator.is_shutting_down());
        let reason = coordinator.reason().await;
        assert_eq!(
            reason,
            Some(ShutdownReason::FatalError {
                component: "database".to_string(),
                message: "Connection pool exhausted".to_string(),
            })
        );
    }

    #[tokio::test]
    async fn test_trigger_with_reason_requested() {
        let coordinator = ShutdownCoordinator::new();

        coordinator
            .trigger_with_reason(ShutdownReason::Requested)
            .await;

        assert!(coordinator.is_shutting_down());
        assert_eq!(coordinator.reason().await, Some(ShutdownReason::Requested));
    }

    #[tokio::test]
    async fn test_trigger_without_reason_has_no_reason() {
        let coordinator = ShutdownCoordinator::new();

        coordinator.trigger().await;

        assert!(coordinator.is_shutting_down());
        assert!(coordinator.reason().await.is_none());
    }

    #[tokio::test]
    async fn test_shutdown_reason_display() {
        assert_eq!(ShutdownReason::Requested.to_string(), "shutdown requested");

        assert_eq!(
            ShutdownReason::FatalError {
                component: "api".to_string(),
                message: "panic".to_string(),
            }
            .to_string(),
            "fatal error in api: panic"
        );

        assert_eq!(
            ShutdownReason::ResourceExhausted {
                resource: "memory".to_string(),
                current: "8GB".to_string(),
                limit: "8GB".to_string(),
            }
            .to_string(),
            "memory exhausted (8GB / 8GB)"
        );

        assert_eq!(
            ShutdownReason::DependencyFailure {
                dependency: "redis".to_string(),
                message: "connection refused".to_string(),
            }
            .to_string(),
            "dependency 'redis' failed: connection refused"
        );

        assert_eq!(
            ShutdownReason::Maintenance {
                reason: "scheduled upgrade".to_string(),
            }
            .to_string(),
            "maintenance: scheduled upgrade"
        );

        assert_eq!(
            ShutdownReason::Custom {
                code: "ERR001".to_string(),
                message: "custom failure".to_string(),
            }
            .to_string(),
            "[ERR001] custom failure"
        );
    }
}

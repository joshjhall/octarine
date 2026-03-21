//! Convenience functions for shutdown coordination
//!
//! These functions provide simple shortcuts for common shutdown patterns.

use crate::observe;

use super::coordinator::ShutdownCoordinator;
use super::types::ShutdownSignal;

/// Create a new shutdown coordinator with default settings
///
/// This is a convenience function equivalent to `ShutdownCoordinator::new()`.
///
/// # Example
///
/// ```rust,no_run
/// use octarine::runtime::shutdown::shutdown_coordinator;
///
/// let shutdown = shutdown_coordinator();
/// ```
pub fn shutdown_coordinator() -> ShutdownCoordinator {
    ShutdownCoordinator::new()
}

/// Wait for a shutdown signal and return the signal type
///
/// This is a convenience function for simple use cases where you don't need
/// the full coordinator functionality.
///
/// # Panics
///
/// Panics if signal handlers cannot be installed. This is intentional as
/// signal handling is critical for graceful shutdown.
///
/// # Example
///
/// ```rust,no_run
/// use octarine::runtime::shutdown::wait_for_shutdown;
///
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// let signal = wait_for_shutdown().await;
/// println!("Received {:?}", signal);
/// # });
/// ```
#[allow(clippy::expect_used)]
pub async fn wait_for_shutdown() -> ShutdownSignal {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to install SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                observe::info("shutdown_signal_received", "Received SIGTERM signal");
                ShutdownSignal::Terminate
            }
            _ = sigint.recv() => {
                observe::info("shutdown_signal_received", "Received SIGINT signal");
                ShutdownSignal::Interrupt
            }
        }
    }

    #[cfg(windows)]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        observe::info("shutdown_signal_received", "Received Ctrl+C signal");
        ShutdownSignal::Interrupt
    }

    #[cfg(not(any(unix, windows)))]
    {
        // Fallback: wait forever (should never happen in practice)
        std::future::pending::<()>().await;
        ShutdownSignal::Manual
    }
}

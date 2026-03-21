//! Graceful shutdown coordination with observability
//!
//! This module provides coordinated service shutdown with signal handling,
//! timeout management, and cleanup hooks. All operations are instrumented
//! with observe for compliance-grade audit trails.
//!
//! # Features
//!
//! - **Signal Handling**: SIGTERM, SIGINT (Unix), Ctrl+C (Windows)
//! - **Ordered Hooks**: Cleanup hooks run in registration order
//! - **Timeout Management**: Force-quit after configurable timeout
//! - **Health Integration**: Report unhealthy during shutdown
//! - **Observability**: All shutdown events logged via observe
//!
//! # Usage
//!
//! ## Basic Shutdown Coordination
//!
//! ```rust,no_run
//! use octarine::runtime::shutdown::ShutdownCoordinator;
//! use std::time::Duration;
//!
//! # async fn run_server() {}
//! # async fn flush_buffers() {}
//! # async fn close_connections() {}
//!
//! #[tokio::main]
//! async fn main() {
//!     let shutdown = ShutdownCoordinator::new()
//!         .with_timeout(Duration::from_secs(30))
//!         .with_hook("flush_buffers", || Box::pin(async { flush_buffers().await; Ok(()) }))
//!         .with_hook("close_connections", || Box::pin(async { close_connections().await; Ok(()) }));
//!
//!     tokio::select! {
//!         _ = run_server() => {}
//!         _ = shutdown.wait_for_signal() => {
//!             shutdown.run_hooks().await;
//!         }
//!     }
//! }
//! ```
//!
//! ## With Shutdown Token
//!
//! ```rust,no_run
//! use octarine::runtime::shutdown::ShutdownCoordinator;
//!
//! # async fn process_request() {}
//!
//! #[tokio::main]
//! async fn main() {
//!     let shutdown = ShutdownCoordinator::new();
//!     let token = shutdown.token();
//!
//!     // Pass token to workers
//!     tokio::spawn(async move {
//!         loop {
//!             tokio::select! {
//!                 _ = token.cancelled() => break,
//!                 _ = process_request() => {}
//!             }
//!         }
//!     });
//!
//!     shutdown.wait_for_signal().await;
//!     shutdown.run_hooks().await;
//! }
//! ```
//!
//! # Module Structure
//!
//! - `types` - Core types (ShutdownSignal, ShutdownPhase, ShutdownStats)
//! - `coordinator` - The main ShutdownCoordinator implementation
//! - `functions` - Convenience functions for simple use cases

mod coordinator;
mod draining;
mod functions;
mod hooks;
mod integration;
mod progress;
mod restart;
mod signals;
mod types;

// Re-export public API
pub use coordinator::ShutdownCoordinator;
pub use draining::{DrainGuard, DrainTracker};
pub use functions::{shutdown_coordinator, wait_for_shutdown};
pub use integration::{ShutdownAware, ShutdownIntegration};
pub use progress::{EventCallback, ProgressCallback, ShutdownEvent, ShutdownProgress};
pub use restart::{RestartCoordinator, RestartIntent, RestartState};
pub use types::{
    HookConfig, HookFn, HookHandle, HookResult, ShutdownHealthStatus, ShutdownPhase,
    ShutdownReason, ShutdownSignal, ShutdownStats,
};

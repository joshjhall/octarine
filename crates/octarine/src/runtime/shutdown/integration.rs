//! Runtime component integration for shutdown coordination
//!
//! This module provides automatic shutdown hook registration for runtime
//! components like worker pools, channels, and circuit breakers.
//!
//! # Example
//!
//! ```rust
//! use octarine::runtime::shutdown::{ShutdownCoordinator, ShutdownIntegration};
//! use octarine::runtime::r#async::WorkerPool;
//!
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! let coordinator = ShutdownCoordinator::new();
//! let integration = ShutdownIntegration::new(&coordinator);
//!
//! // Register a worker pool for automatic shutdown
//! let pool = WorkerPool::new("processors", 4);
//! integration.register_worker_pool("processors", pool).await;
//!
//! // When shutdown is triggered, the pool will be shut down automatically
//! coordinator.trigger().await;
//! coordinator.run_hooks().await;
//! # });
//! ```

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::observe;
use crate::runtime::r#async::WorkerPool;

use super::coordinator::ShutdownCoordinator;
use super::types::{HookConfig, HookResult};

// ============================================================================
// ShutdownIntegration
// ============================================================================

/// Integration helper for registering runtime components with shutdown coordination
///
/// This struct provides convenient methods to register various runtime components
/// (worker pools, channels, etc.) with a shutdown coordinator. When shutdown is
/// triggered, registered components are automatically cleaned up in the correct order.
///
/// # Priority Ordering
///
/// Components are shut down in a specific order based on priority:
/// 1. Stop accepting new work (channels close senders)
/// 2. Wait for in-flight work to complete (worker pools drain)
/// 3. Clean up resources (circuit breakers reset)
///
/// # Example
///
/// ```rust
/// use octarine::runtime::shutdown::{ShutdownCoordinator, ShutdownIntegration};
/// use octarine::runtime::r#async::WorkerPool;
///
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// let coordinator = ShutdownCoordinator::new();
/// let integration = ShutdownIntegration::new(&coordinator);
///
/// // Register multiple components
/// let pool1 = WorkerPool::new("writers", 2);
/// let pool2 = WorkerPool::new("readers", 4);
///
/// integration.register_worker_pool("writers", pool1).await;
/// integration.register_worker_pool("readers", pool2).await;
///
/// // Trigger shutdown - all pools will be shut down
/// coordinator.trigger().await;
/// coordinator.run_hooks().await;
/// # });
/// ```
pub struct ShutdownIntegration<'a> {
    coordinator: &'a ShutdownCoordinator,
}

impl<'a> ShutdownIntegration<'a> {
    /// Create a new shutdown integration helper
    ///
    /// # Arguments
    ///
    /// * `coordinator` - The shutdown coordinator to register hooks with
    pub fn new(coordinator: &'a ShutdownCoordinator) -> Self {
        observe::debug(
            "shutdown_integration_created",
            "Shutdown integration helper created",
        );
        Self { coordinator }
    }

    /// Register a worker pool for automatic shutdown
    ///
    /// The pool will be gracefully shut down when the coordinator triggers,
    /// waiting for all queued tasks to complete.
    ///
    /// # Arguments
    ///
    /// * `name` - Name for the shutdown hook
    /// * `pool` - The worker pool to register
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::runtime::shutdown::{ShutdownCoordinator, ShutdownIntegration};
    /// use octarine::runtime::r#async::WorkerPool;
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let coordinator = ShutdownCoordinator::new();
    /// let integration = ShutdownIntegration::new(&coordinator);
    ///
    /// let pool = WorkerPool::new("tasks", 4);
    /// integration.register_worker_pool("task_pool", pool).await;
    /// # });
    /// ```
    pub async fn register_worker_pool(&self, name: &str, pool: WorkerPool) {
        let pool = Arc::new(Mutex::new(Some(pool)));
        let pool_name = name.to_string();

        let config = HookConfig::new(name).with_priority(50); // Middle priority

        self.coordinator
            .add_hook_with_config(config, {
                let pool = Arc::clone(&pool);
                let pool_name = pool_name.clone();
                move || {
                    let pool = Arc::clone(&pool);
                    let pool_name = pool_name.clone();
                    Box::pin(async move {
                        let mut guard = pool.lock().await;
                        if let Some(p) = guard.take() {
                            observe::info(
                                "worker_pool_shutdown_hook",
                                format!("Shutting down worker pool '{}'", pool_name),
                            );
                            p.shutdown().await;
                        }
                        Ok(())
                    })
                }
            })
            .await;

        observe::debug(
            "worker_pool_registered",
            format!("Worker pool '{}' registered for shutdown", pool_name),
        );
    }

    /// Register a custom cleanup function
    ///
    /// This is a convenience method for registering arbitrary cleanup logic
    /// that should run during shutdown.
    ///
    /// # Arguments
    ///
    /// * `name` - Name for the shutdown hook
    /// * `priority` - Hook priority (lower runs first)
    /// * `cleanup` - The cleanup function to run
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::runtime::shutdown::{ShutdownCoordinator, ShutdownIntegration};
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let coordinator = ShutdownCoordinator::new();
    /// let integration = ShutdownIntegration::new(&coordinator);
    ///
    /// integration.register_cleanup("flush_logs", 90, || async {
    ///     // Flush log buffers
    ///     Ok(())
    /// }).await;
    /// # });
    /// ```
    pub async fn register_cleanup<F, Fut>(&self, name: &str, priority: usize, cleanup: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = HookResult> + Send + 'static,
    {
        let config = HookConfig::new(name).with_priority(priority);

        self.coordinator.add_hook_with_config(config, cleanup).await;

        observe::debug(
            "cleanup_registered",
            format!("Cleanup '{}' registered with priority {}", name, priority),
        );
    }
}

// ============================================================================
// Convenience Extension Trait
// ============================================================================

/// Extension trait for easy shutdown integration
///
/// This trait provides a fluent API for registering components with
/// a shutdown coordinator.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::shutdown::{ShutdownCoordinator, ShutdownAware};
/// use octarine::runtime::r#async::WorkerPool;
///
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// let coordinator = ShutdownCoordinator::new();
///
/// // Fluent registration
/// let pool = WorkerPool::new("tasks", 4);
/// pool.register_shutdown(&coordinator, "task_pool").await;
/// # });
/// ```
pub trait ShutdownAware {
    /// Register this component with a shutdown coordinator
    ///
    /// When shutdown is triggered, this component will be properly cleaned up.
    fn register_shutdown(
        self,
        coordinator: &ShutdownCoordinator,
        name: &str,
    ) -> impl std::future::Future<Output = ()> + Send;
}

impl ShutdownAware for WorkerPool {
    async fn register_shutdown(self, coordinator: &ShutdownCoordinator, name: &str) {
        let integration = ShutdownIntegration::new(coordinator);
        integration.register_worker_pool(name, self).await;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn test_register_worker_pool() {
        let coordinator = ShutdownCoordinator::new();
        let integration = ShutdownIntegration::new(&coordinator);

        let pool = WorkerPool::new("test_pool", 2);
        integration.register_worker_pool("test_pool", pool).await;

        // Trigger shutdown
        coordinator.trigger().await;
        coordinator.run_hooks().await;

        // Pool should be shut down (no way to verify directly, but no panic means success)
    }

    #[tokio::test]
    async fn test_register_multiple_pools() {
        let coordinator = ShutdownCoordinator::new();
        let integration = ShutdownIntegration::new(&coordinator);

        let pool1 = WorkerPool::new("pool1", 2);
        let pool2 = WorkerPool::new("pool2", 2);

        integration.register_worker_pool("pool1", pool1).await;
        integration.register_worker_pool("pool2", pool2).await;

        // Both should be registered
        coordinator.trigger().await;
        let stats = coordinator.run_hooks().await;

        assert!(stats.hooks_succeeded >= 2);
    }

    #[tokio::test]
    async fn test_register_cleanup() {
        let coordinator = ShutdownCoordinator::new();
        let integration = ShutdownIntegration::new(&coordinator);

        let cleanup_ran = Arc::new(AtomicBool::new(false));
        let cleanup_ran_clone = Arc::clone(&cleanup_ran);

        integration
            .register_cleanup("test_cleanup", 50, move || {
                let cleanup_ran = Arc::clone(&cleanup_ran_clone);
                async move {
                    cleanup_ran.store(true, Ordering::SeqCst);
                    Ok(())
                }
            })
            .await;

        coordinator.trigger().await;
        coordinator.run_hooks().await;

        assert!(cleanup_ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_cleanup_priority_ordering() {
        let coordinator = ShutdownCoordinator::new();
        let integration = ShutdownIntegration::new(&coordinator);

        let order = Arc::new(Mutex::new(Vec::new()));

        // Register in reverse priority order
        let order_clone = Arc::clone(&order);
        integration
            .register_cleanup("low_priority", 100, move || {
                let order = Arc::clone(&order_clone);
                async move {
                    order.lock().await.push("low");
                    Ok(())
                }
            })
            .await;

        let order_clone = Arc::clone(&order);
        integration
            .register_cleanup("high_priority", 10, move || {
                let order = Arc::clone(&order_clone);
                async move {
                    order.lock().await.push("high");
                    Ok(())
                }
            })
            .await;

        let order_clone = Arc::clone(&order);
        integration
            .register_cleanup("medium_priority", 50, move || {
                let order = Arc::clone(&order_clone);
                async move {
                    order.lock().await.push("medium");
                    Ok(())
                }
            })
            .await;

        coordinator.trigger().await;
        coordinator.run_hooks().await;

        let execution_order = order.lock().await;
        assert_eq!(*execution_order, vec!["high", "medium", "low"]);
    }

    #[tokio::test]
    async fn test_shutdown_aware_trait() {
        let coordinator = ShutdownCoordinator::new();

        let pool = WorkerPool::new("trait_test", 2);
        pool.register_shutdown(&coordinator, "trait_pool").await;

        coordinator.trigger().await;
        let stats = coordinator.run_hooks().await;

        assert!(stats.hooks_succeeded >= 1);
    }

    #[tokio::test]
    async fn test_worker_pool_with_tasks() {
        let coordinator = ShutdownCoordinator::new();
        let integration = ShutdownIntegration::new(&coordinator);

        let pool = WorkerPool::new("busy_pool", 2);

        // Spawn some tasks
        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = Arc::clone(&completed);

        pool.spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            completed_clone.store(true, Ordering::SeqCst);
        })
        .expect("spawn should succeed");

        // Give the task time to start
        tokio::time::sleep(Duration::from_millis(30)).await;

        integration.register_worker_pool("busy_pool", pool).await;

        // Shutdown should wait for tasks to complete
        coordinator.trigger().await;
        coordinator.run_hooks().await;

        // Task should have completed before shutdown finished
        assert!(completed.load(Ordering::SeqCst));
    }
}

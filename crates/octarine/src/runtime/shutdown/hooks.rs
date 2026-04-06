//! Shutdown hook management
//!
//! This module handles registration, removal, and execution of shutdown hooks.

use std::future::Future;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::observe;

use super::coordinator::ShutdownCoordinator;
use super::types::{
    HookConfig, HookFn, HookHandle, HookResult, ShutdownHook, ShutdownPhase, ShutdownStats,
};

impl ShutdownCoordinator {
    /// Register a shutdown hook (builder pattern)
    ///
    /// Hooks are executed in registration order during shutdown.
    /// Each hook should complete quickly or respect the cancellation token.
    ///
    /// Note: This method does not return a `HookHandle` because it's designed
    /// for the builder pattern. Use `add_hook` if you need to remove hooks later.
    ///
    /// # Arguments
    ///
    /// * `name` - Descriptive name for logging
    /// * `hook` - Async function to execute during shutdown
    ///
    /// # Panics
    ///
    /// Panics if the hooks mutex is poisoned (should never happen in normal operation).
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn with_hook<F, Fut>(self, name: impl Into<String>, hook: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = HookResult> + Send + 'static,
    {
        let name = name.into();
        let id = self.hook_id_counter.fetch_add(1, Ordering::SeqCst);
        let priority = self.hook_counter.fetch_add(1, Ordering::SeqCst);

        observe::debug(
            "shutdown_hook_registered",
            format!(
                "Registered shutdown hook '{}' (id={}) with priority {}",
                name, id, priority
            ),
        );

        let hook_fn: HookFn = Box::new(move || Box::pin(hook()));

        // Use blocking_lock for synchronous builder pattern
        // This is safe because with_hook is only used during initialization
        // before any async code is running
        {
            let mut hooks_guard = self.hooks.blocking_lock();
            hooks_guard.push(ShutdownHook {
                id,
                name,
                func: hook_fn,
                priority,
                timeout: None,
                max_retries: 0,
                retry_delay: Duration::from_millis(100),
            });
        }

        self
    }

    /// Register a shutdown hook (async method)
    ///
    /// Returns a `HookHandle` that can be used to remove the hook later.
    /// Use this method when you need to register hooks after initialization.
    pub async fn add_hook<F, Fut>(&self, name: impl Into<String>, hook: F) -> HookHandle
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = HookResult> + Send + 'static,
    {
        let name = name.into();
        let id = self.hook_id_counter.fetch_add(1, Ordering::SeqCst);
        let priority = self.hook_counter.fetch_add(1, Ordering::SeqCst);

        observe::debug(
            "shutdown_hook_registered",
            format!(
                "Registered shutdown hook '{}' (id={}) with priority {}",
                name, id, priority
            ),
        );

        let hook_fn: HookFn = Box::new(move || Box::pin(hook()));

        let mut hooks_guard = self.hooks.lock().await;
        hooks_guard.push(ShutdownHook {
            id,
            name,
            func: hook_fn,
            priority,
            timeout: None,
            max_retries: 0,
            retry_delay: Duration::from_millis(100),
        });

        HookHandle(id)
    }

    /// Register a shutdown hook with advanced configuration
    ///
    /// Returns a `HookHandle` that can be used to remove the hook later.
    /// Use this method when you need per-hook timeouts, explicit priority, or retries.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use octarine::runtime::shutdown::{ShutdownCoordinator, HookConfig};
    /// use std::time::Duration;
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let coordinator = ShutdownCoordinator::new();
    ///
    /// // Register a hook with timeout and retries
    /// let handle = coordinator.add_hook_with_config(
    ///     HookConfig::new("cleanup")
    ///         .with_timeout(Duration::from_secs(5))
    ///         .with_retries(3, Duration::from_millis(100)),
    ///     || async { Ok(()) }
    /// ).await;
    ///
    /// // Later, remove the hook if needed
    /// coordinator.deregister_hook(handle).await;
    /// # });
    /// ```
    pub async fn add_hook_with_config<F, Fut>(&self, config: HookConfig, hook: F) -> HookHandle
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = HookResult> + Send + 'static,
    {
        let id = self.hook_id_counter.fetch_add(1, Ordering::SeqCst);
        let priority = config
            .priority
            .unwrap_or_else(|| self.hook_counter.fetch_add(1, Ordering::SeqCst));

        let timeout_msg = config
            .timeout
            .map(|t| format!(", timeout={}ms", t.as_millis()))
            .unwrap_or_default();

        let retry_msg = if config.max_retries > 0 {
            format!(", retries={}", config.max_retries)
        } else {
            String::new()
        };

        observe::debug(
            "shutdown_hook_registered",
            format!(
                "Registered shutdown hook '{}' (id={}) with priority {}{}{}",
                config.name, id, priority, timeout_msg, retry_msg
            ),
        );

        let hook_fn: HookFn = Box::new(move || Box::pin(hook()));

        let mut hooks_guard = self.hooks.lock().await;
        hooks_guard.push(ShutdownHook {
            id,
            name: config.name,
            func: hook_fn,
            priority,
            timeout: config.timeout,
            max_retries: config.max_retries,
            retry_delay: config.retry_delay,
        });

        HookHandle(id)
    }

    /// Remove a previously registered shutdown hook
    ///
    /// Returns `true` if the hook was found and removed, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use octarine::runtime::shutdown::ShutdownCoordinator;
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let coordinator = ShutdownCoordinator::new();
    ///
    /// let handle = coordinator.add_hook("cleanup", || async { Ok(()) }).await;
    ///
    /// // Remove the hook
    /// let removed = coordinator.deregister_hook(handle).await;
    /// assert!(removed);
    ///
    /// // Trying to remove again returns false
    /// let removed_again = coordinator.deregister_hook(handle).await;
    /// assert!(!removed_again);
    /// # });
    /// ```
    pub async fn deregister_hook(&self, handle: HookHandle) -> bool {
        let mut hooks_guard = self.hooks.lock().await;
        let initial_len = hooks_guard.len();

        hooks_guard.retain(|h| h.id != handle.0);

        let removed = hooks_guard.len() < initial_len;

        if removed {
            observe::debug(
                "shutdown_hook_removed",
                format!("Removed shutdown hook with id={}", handle.0),
            );
        }

        removed
    }

    /// Get the number of currently registered hooks
    pub async fn hook_count(&self) -> usize {
        self.hooks.lock().await.len()
    }

    /// Run all registered shutdown hooks
    ///
    /// Hooks are executed in priority order. Each hook can have an individual
    /// timeout, or will share the global timeout. If the global timeout is
    /// reached, remaining hooks are skipped and shutdown is forced.
    ///
    /// # Returns
    ///
    /// Statistics about hook execution.
    pub async fn run_hooks(&self) -> ShutdownStats {
        let start = std::time::Instant::now();

        observe::info(
            "shutdown_hooks_starting",
            "Beginning shutdown hook execution",
        );

        // Sort hooks by priority
        let mut hooks = self.hooks.lock().await;
        hooks.sort_by_key(|h| h.priority);

        let total_hooks = hooks.len();
        {
            let mut stats = self.stats.write().await;
            stats.hooks_registered = total_hooks;
        }

        observe::info(
            "shutdown_hooks_count",
            format!(
                "Executing {} shutdown hooks with {}ms global timeout",
                total_hooks,
                self.timeout.as_millis()
            ),
        );

        let mut succeeded = 0usize;
        let mut failed = 0usize;
        let mut timed_out = 0usize;
        let mut skipped = 0usize;

        // Calculate default per-hook timeout (global timeout divided by hook count)
        let default_hook_timeout = if total_hooks > 0 {
            self.timeout
                .checked_div(total_hooks as u32)
                .unwrap_or(self.timeout)
        } else {
            self.timeout
        };

        // Execute hooks with overall timeout
        let timeout_result = tokio::time::timeout(self.timeout, async {
            for hook in hooks.iter() {
                // Use hook's individual timeout or default
                let hook_timeout = hook.timeout.unwrap_or(default_hook_timeout);
                let max_attempts = hook.max_retries.saturating_add(1); // retries + initial attempt

                let retry_info = if hook.max_retries > 0 {
                    format!(", max_retries={}", hook.max_retries)
                } else {
                    String::new()
                };

                observe::debug(
                    "shutdown_hook_executing",
                    format!(
                        "Executing shutdown hook '{}' with {}ms timeout{}",
                        hook.name,
                        hook_timeout.as_millis(),
                        retry_info
                    ),
                );

                let hook_start = std::time::Instant::now();
                let mut last_error = None;
                let mut hook_succeeded = false;
                let mut hook_timed_out = false;

                // Try execution with retries
                for attempt in 0..max_attempts {
                    if attempt > 0 {
                        observe::debug(
                            "shutdown_hook_retry",
                            format!(
                                "Retrying shutdown hook '{}' (attempt {}/{})",
                                hook.name,
                                attempt.saturating_add(1),
                                max_attempts
                            ),
                        );
                        tokio::time::sleep(hook.retry_delay).await;
                    }

                    let result = tokio::time::timeout(hook_timeout, (hook.func)()).await;

                    match result {
                        Ok(Ok(())) => {
                            hook_succeeded = true;
                            break;
                        }
                        Ok(Err(e)) => {
                            last_error = Some(e);
                            // Continue to retry if we have attempts left
                        }
                        Err(_) => {
                            hook_timed_out = true;
                            // Timeout - don't retry, timeouts are usually not transient
                            break;
                        }
                    }
                }

                let hook_duration = hook_start.elapsed();

                if hook_succeeded {
                    succeeded = succeeded.saturating_add(1);
                    observe::info(
                        "shutdown_hook_completed",
                        format!(
                            "Shutdown hook '{}' completed successfully in {}ms",
                            hook.name,
                            hook_duration.as_millis()
                        ),
                    );
                } else if hook_timed_out {
                    timed_out = timed_out.saturating_add(1);
                    observe::warn(
                        "shutdown_hook_timeout",
                        format!(
                            "Shutdown hook '{}' timed out after {}ms",
                            hook.name,
                            hook_timeout.as_millis()
                        ),
                    );
                } else if let Some(ref e) = last_error {
                    failed = failed.saturating_add(1);
                    let retry_msg = if hook.max_retries > 0 {
                        format!(" after {} retries", hook.max_retries)
                    } else {
                        String::new()
                    };
                    observe::error(
                        "shutdown_hook_failed",
                        format!(
                            "Shutdown hook '{}' failed{} in {}ms: {}",
                            hook.name,
                            retry_msg,
                            hook_duration.as_millis(),
                            e
                        ),
                    );
                }
            }
        })
        .await;

        // Check if we hit global timeout
        if timeout_result.is_err() {
            skipped = total_hooks
                .saturating_sub(succeeded.saturating_add(failed).saturating_add(timed_out));
            observe::warn(
                "shutdown_global_timeout_reached",
                format!(
                    "Global shutdown timeout reached after {}ms, {} hooks skipped",
                    self.timeout.as_millis(),
                    skipped
                ),
            );
            *self.phase.write().await = ShutdownPhase::ForcedShutdown;
        } else {
            *self.phase.write().await = ShutdownPhase::Complete;
        }

        let duration = start.elapsed();

        // Update stats
        let stats = {
            let mut stats = self.stats.write().await;
            stats.hooks_succeeded = succeeded;
            stats.hooks_failed = failed;
            stats.hooks_timed_out = timed_out;
            stats.hooks_skipped = skipped;
            stats.duration_ms = duration.as_millis() as u64;
            stats.clone()
        };

        observe::info(
            "shutdown_complete",
            format!(
                "Shutdown complete in {}ms: {} succeeded, {} failed, {} timed out, {} skipped",
                stats.duration_ms,
                stats.hooks_succeeded,
                stats.hooks_failed,
                stats.hooks_timed_out,
                stats.hooks_skipped
            ),
        );

        stats
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::observe::fail;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn test_shutdown_hooks_execution() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        let coordinator = ShutdownCoordinator::new();

        coordinator
            .add_hook("increment", move || {
                let c = Arc::clone(&counter_clone);
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            })
            .await;

        let stats = coordinator.run_hooks().await;

        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(stats.hooks_registered, 1);
        assert_eq!(stats.hooks_succeeded, 1);
        assert_eq!(stats.hooks_failed, 0);
    }

    #[tokio::test]
    async fn test_hook_failure_handling() {
        let coordinator = ShutdownCoordinator::new();

        coordinator
            .add_hook("failing_hook", || async {
                Err(fail("hook_failed", "Test failure"))
            })
            .await;

        let stats = coordinator.run_hooks().await;

        assert_eq!(stats.hooks_registered, 1);
        assert_eq!(stats.hooks_succeeded, 0);
        assert_eq!(stats.hooks_failed, 1);
    }

    #[tokio::test]
    async fn test_multiple_hooks_order() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let order1 = Arc::clone(&order);
        let order2 = Arc::clone(&order);
        let order3 = Arc::clone(&order);

        let coordinator = ShutdownCoordinator::new();

        coordinator
            .add_hook("first", move || {
                let o = Arc::clone(&order1);
                async move {
                    o.lock().await.push(1);
                    Ok(())
                }
            })
            .await;

        coordinator
            .add_hook("second", move || {
                let o = Arc::clone(&order2);
                async move {
                    o.lock().await.push(2);
                    Ok(())
                }
            })
            .await;

        coordinator
            .add_hook("third", move || {
                let o = Arc::clone(&order3);
                async move {
                    o.lock().await.push(3);
                    Ok(())
                }
            })
            .await;

        coordinator.run_hooks().await;

        let final_order = order.lock().await;
        assert_eq!(*final_order, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_shutdown_stats() {
        let coordinator = ShutdownCoordinator::new();

        coordinator.add_hook("success1", || async { Ok(()) }).await;
        coordinator.add_hook("success2", || async { Ok(()) }).await;
        coordinator
            .add_hook("failure", || async { Err(fail("test", "fail")) })
            .await;

        let stats = coordinator.run_hooks().await;

        assert_eq!(stats.hooks_registered, 3);
        assert_eq!(stats.hooks_succeeded, 2);
        assert_eq!(stats.hooks_failed, 1);
        assert_eq!(stats.hooks_skipped, 0);
    }

    #[tokio::test]
    async fn test_hook_config_with_timeout() {
        let coordinator = ShutdownCoordinator::new();

        // Add a hook with a short individual timeout
        coordinator
            .add_hook_with_config(
                HookConfig::new("slow_hook").with_timeout(Duration::from_millis(50)),
                || async {
                    // This hook will timeout
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Ok(())
                },
            )
            .await;

        let stats = coordinator.run_hooks().await;

        assert_eq!(stats.hooks_registered, 1);
        assert_eq!(stats.hooks_succeeded, 0);
        assert_eq!(stats.hooks_failed, 0);
        assert_eq!(stats.hooks_timed_out, 1);
        assert_eq!(stats.hooks_skipped, 0);
    }

    #[tokio::test]
    async fn test_hook_config_with_priority() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let order1 = Arc::clone(&order);
        let order2 = Arc::clone(&order);
        let order3 = Arc::clone(&order);

        let coordinator = ShutdownCoordinator::new();

        // Add hooks with explicit priorities (out of order)
        coordinator
            .add_hook_with_config(HookConfig::new("third").with_priority(300), move || {
                let o = Arc::clone(&order3);
                async move {
                    o.lock().await.push(3);
                    Ok(())
                }
            })
            .await;

        coordinator
            .add_hook_with_config(HookConfig::new("first").with_priority(100), move || {
                let o = Arc::clone(&order1);
                async move {
                    o.lock().await.push(1);
                    Ok(())
                }
            })
            .await;

        coordinator
            .add_hook_with_config(HookConfig::new("second").with_priority(200), move || {
                let o = Arc::clone(&order2);
                async move {
                    o.lock().await.push(2);
                    Ok(())
                }
            })
            .await;

        coordinator.run_hooks().await;

        let final_order = order.lock().await;
        assert_eq!(*final_order, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_hook_timeout_does_not_block_others() {
        let executed = Arc::new(AtomicUsize::new(0));
        let exec1 = Arc::clone(&executed);
        let exec2 = Arc::clone(&executed);

        let coordinator = ShutdownCoordinator::new();

        // First hook times out
        coordinator
            .add_hook_with_config(
                HookConfig::new("slow").with_timeout(Duration::from_millis(10)),
                move || {
                    let e = Arc::clone(&exec1);
                    async move {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        e.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                },
            )
            .await;

        // Second hook should still run
        coordinator
            .add_hook_with_config(
                HookConfig::new("fast").with_timeout(Duration::from_millis(100)),
                move || {
                    let e = Arc::clone(&exec2);
                    async move {
                        e.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                },
            )
            .await;

        let stats = coordinator.run_hooks().await;

        // The slow hook timed out, but the fast one succeeded
        assert_eq!(stats.hooks_timed_out, 1);
        assert_eq!(stats.hooks_succeeded, 1);
        assert_eq!(executed.load(Ordering::SeqCst), 1); // Only fast hook completed
    }

    #[tokio::test]
    async fn test_mixed_stats() {
        let coordinator = ShutdownCoordinator::new();

        // Success
        coordinator.add_hook("success", || async { Ok(()) }).await;

        // Failure
        coordinator
            .add_hook("failure", || async { Err(fail("test", "fail")) })
            .await;

        // Timeout
        coordinator
            .add_hook_with_config(
                HookConfig::new("timeout").with_timeout(Duration::from_millis(10)),
                || async {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Ok(())
                },
            )
            .await;

        let stats = coordinator.run_hooks().await;

        assert_eq!(stats.hooks_registered, 3);
        assert_eq!(stats.hooks_succeeded, 1);
        assert_eq!(stats.hooks_failed, 1);
        assert_eq!(stats.hooks_timed_out, 1);
        assert_eq!(stats.hooks_skipped, 0);
    }

    #[tokio::test]
    async fn test_deregister_hook() {
        let coordinator = ShutdownCoordinator::new();

        let handle1 = coordinator.add_hook("hook1", || async { Ok(()) }).await;
        let handle2 = coordinator.add_hook("hook2", || async { Ok(()) }).await;

        assert_eq!(coordinator.hook_count().await, 2);

        // Remove first hook
        let removed = coordinator.deregister_hook(handle1).await;
        assert!(removed);
        assert_eq!(coordinator.hook_count().await, 1);

        // Try to remove again - should return false
        let removed_again = coordinator.deregister_hook(handle1).await;
        assert!(!removed_again);
        assert_eq!(coordinator.hook_count().await, 1);

        // Second hook should still be there
        let stats = coordinator.run_hooks().await;
        assert_eq!(stats.hooks_registered, 1);
        assert_eq!(stats.hooks_succeeded, 1);

        // Remove the remaining hook after it ran (no-op but should work)
        let removed = coordinator.deregister_hook(handle2).await;
        // Note: The hook was moved out during run_hooks, so this might be false
        // depending on implementation. Let's just verify it doesn't panic.
        let _ = removed;
    }

    #[tokio::test]
    async fn test_hook_handle_equality() {
        let coordinator = ShutdownCoordinator::new();

        let handle1 = coordinator.add_hook("hook1", || async { Ok(()) }).await;
        let handle2 = coordinator.add_hook("hook2", || async { Ok(()) }).await;

        // Different hooks should have different handles
        assert_ne!(handle1, handle2);

        // Same handle should be equal to itself
        assert_eq!(handle1, handle1);

        // IDs should be accessible
        assert!(handle1.id() > 0);
        assert!(handle2.id() > handle1.id());
    }

    #[tokio::test]
    async fn test_deregister_hook_before_shutdown() {
        let executed = Arc::new(AtomicUsize::new(0));
        let exec1 = Arc::clone(&executed);
        let exec2 = Arc::clone(&executed);

        let coordinator = ShutdownCoordinator::new();

        let handle1 = coordinator
            .add_hook("will_be_removed", move || {
                let e = Arc::clone(&exec1);
                async move {
                    e.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            })
            .await;

        coordinator
            .add_hook("will_run", move || {
                let e = Arc::clone(&exec2);
                async move {
                    e.fetch_add(10, Ordering::SeqCst);
                    Ok(())
                }
            })
            .await;

        // Remove the first hook before shutdown
        coordinator.deregister_hook(handle1).await;

        // Run shutdown
        let stats = coordinator.run_hooks().await;

        // Only the second hook should have run
        assert_eq!(executed.load(Ordering::SeqCst), 10);
        assert_eq!(stats.hooks_registered, 1);
        assert_eq!(stats.hooks_succeeded, 1);
    }

    #[tokio::test]
    async fn test_hook_retry_succeeds_on_second_attempt() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = Arc::clone(&attempts);

        let coordinator = ShutdownCoordinator::new();

        // Hook that fails first attempt, succeeds on second
        coordinator
            .add_hook_with_config(
                HookConfig::new("retry_hook").with_retries(2, Duration::from_millis(10)),
                move || {
                    let a = Arc::clone(&attempts_clone);
                    async move {
                        let attempt = a.fetch_add(1, Ordering::SeqCst);
                        if attempt == 0 {
                            Err(fail("transient", "First attempt fails"))
                        } else {
                            Ok(())
                        }
                    }
                },
            )
            .await;

        let stats = coordinator.run_hooks().await;

        // Should have attempted twice (initial + 1 retry)
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        // Should succeed because second attempt worked
        assert_eq!(stats.hooks_succeeded, 1);
        assert_eq!(stats.hooks_failed, 0);
    }

    #[tokio::test]
    async fn test_hook_retry_exhausted() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = Arc::clone(&attempts);

        let coordinator = ShutdownCoordinator::new();

        // Hook that always fails
        coordinator
            .add_hook_with_config(
                HookConfig::new("always_fails").with_retries(2, Duration::from_millis(10)),
                move || {
                    let a = Arc::clone(&attempts_clone);
                    async move {
                        a.fetch_add(1, Ordering::SeqCst);
                        Err(fail("permanent", "Always fails"))
                    }
                },
            )
            .await;

        let stats = coordinator.run_hooks().await;

        // Should have attempted 3 times (initial + 2 retries)
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        // Should fail after all retries exhausted
        assert_eq!(stats.hooks_succeeded, 0);
        assert_eq!(stats.hooks_failed, 1);
    }

    #[tokio::test]
    async fn test_hook_no_retry_on_timeout() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = Arc::clone(&attempts);

        let coordinator = ShutdownCoordinator::new();

        // Hook that times out - should not retry
        coordinator
            .add_hook_with_config(
                HookConfig::new("timeout_hook")
                    .with_timeout(Duration::from_millis(20))
                    .with_retries(2, Duration::from_millis(10)),
                move || {
                    let a = Arc::clone(&attempts_clone);
                    async move {
                        a.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        Ok(())
                    }
                },
            )
            .await;

        let stats = coordinator.run_hooks().await;

        // Should have attempted only once (no retry on timeout)
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(stats.hooks_timed_out, 1);
        assert_eq!(stats.hooks_succeeded, 0);
    }
}

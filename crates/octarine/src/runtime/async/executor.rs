//! Adaptive executor with observability
//!
//! Provides an adaptive executor that works in both sync and async contexts
//! with comprehensive logging and metrics.
//!
//! # Features
//!
//! - Automatic detection of async runtime
//! - Seamless sync/async bridging
//! - Full observability (logging, metrics)
//! - Configurable thread pools
//!
//! # Example
//!
//! ```rust
//! use octarine::runtime::r#async::{Executor, ExecutorConfig};
//!
//! // Create with default configuration
//! let executor = Executor::new();
//!
//! // Execute a future (works in sync or async context)
//! let result = executor.block_on(async {
//!     42
//! });
//! assert!(result.is_ok());
//! ```
//!
//! In an async context, you can also spawn tasks:
//!
//! ```rust,no_run
//! use octarine::runtime::r#async::Executor;
//!
//! # async fn example() {
//! let executor = Executor::new();
//! let handle = executor.spawn(async { "done" }).unwrap();
//! let value = handle.await.unwrap();
//! # }
//! ```

// Allow arithmetic operations - counters are bounded and safe
#![allow(clippy::arithmetic_side_effects)]

use crate::observe::{self, Result};
use crate::primitives::runtime::r#async::{
    AdaptiveExecutor as PrimitiveExecutor, ExecutorConfig as PrimitiveConfig,
    ExecutorStats as PrimitiveStats,
};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global executor statistics
static EXECUTOR_STATS: ExecutorStats = ExecutorStats::new();

struct ExecutorStats {
    total_block_on: AtomicU64,
    total_spawns: AtomicU64,
    sync_executions: AtomicU64,
    async_executions: AtomicU64,
}

impl ExecutorStats {
    const fn new() -> Self {
        Self {
            total_block_on: AtomicU64::new(0),
            total_spawns: AtomicU64::new(0),
            sync_executions: AtomicU64::new(0),
            async_executions: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Executor configuration
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    inner: PrimitiveConfig,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutorConfig {
    /// Create a new configuration with defaults
    pub fn new() -> Self {
        Self {
            inner: PrimitiveConfig::default(),
        }
    }

    /// Set the number of worker threads
    pub fn with_worker_threads(mut self, threads: usize) -> Self {
        self.inner = self.inner.with_worker_threads(threads);
        self
    }

    /// Enable or disable time driver
    pub fn with_time(mut self, enable: bool) -> Self {
        self.inner = self.inner.with_time(enable);
        self
    }

    /// Enable or disable I/O driver
    pub fn with_io(mut self, enable: bool) -> Self {
        self.inner = self.inner.with_io(enable);
        self
    }

    /// Lightweight configuration (single thread, time only)
    pub fn lightweight() -> Self {
        Self {
            inner: PrimitiveConfig::lightweight(),
        }
    }

    /// Full-featured configuration (multi-thread, all features)
    pub fn full_featured() -> Self {
        Self {
            inner: PrimitiveConfig::full_featured(),
        }
    }

    /// Compute-only configuration (multi-thread, no I/O)
    pub fn compute_only() -> Self {
        Self {
            inner: PrimitiveConfig::compute_only(),
        }
    }
}

// ============================================================================
// Executor
// ============================================================================

/// Adaptive executor with observability
///
/// Automatically detects whether it's running in an async context and adapts
/// accordingly. When no async runtime exists, it creates a temporary one.
pub struct Executor {
    inner: PrimitiveExecutor,
    name: String,
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

impl Executor {
    /// Create a new executor with default configuration
    pub fn new() -> Self {
        Self::with_name("default")
    }

    /// Create a new executor with a name
    pub fn with_name(name: impl Into<String>) -> Self {
        Self::with_config(name, ExecutorConfig::default())
    }

    /// Create a new executor with custom configuration
    pub fn with_config(name: impl Into<String>, config: ExecutorConfig) -> Self {
        let name = name.into();
        let inner = PrimitiveExecutor::with_config(config.inner);

        observe::debug(
            "executor_created",
            format!(
                "Executor '{}' created (mode: {})",
                name,
                if inner.is_async() { "async" } else { "sync" }
            ),
        );

        Self { inner, name }
    }

    /// Execute a future, adapting to the current context
    ///
    /// - If in an async context, uses `block_in_place` to run on the existing runtime
    /// - If in a sync context, creates a temporary runtime
    ///
    /// # Errors
    ///
    /// Returns error if runtime creation fails in sync mode.
    pub fn block_on<F>(&self, future: F) -> Result<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        EXECUTOR_STATS
            .total_block_on
            .fetch_add(1, Ordering::Relaxed);

        let start = std::time::Instant::now();
        let is_async = self.inner.is_async();

        if is_async {
            EXECUTOR_STATS
                .async_executions
                .fetch_add(1, Ordering::Relaxed);
        } else {
            EXECUTOR_STATS
                .sync_executions
                .fetch_add(1, Ordering::Relaxed);
        }

        let result = self.inner.block_on(future);
        let elapsed = start.elapsed();

        match &result {
            Ok(_) => {
                observe::trace(
                    "executor_block_on",
                    format!(
                        "Executor '{}' completed execution ({}, {:?})",
                        self.name,
                        if is_async { "async" } else { "sync" },
                        elapsed
                    ),
                );
            }
            Err(e) => {
                observe::error(
                    "executor_block_on_failed",
                    format!("Executor '{}' execution failed: {}", self.name, e),
                );
            }
        }

        result
    }

    /// Spawn a future as a background task
    ///
    /// Only works in async context. Returns error in sync context.
    ///
    /// # Errors
    ///
    /// Returns error if not in async mode (no runtime to spawn on).
    pub fn spawn<F>(&self, future: F) -> Result<tokio::task::JoinHandle<F::Output>>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        EXECUTOR_STATS.total_spawns.fetch_add(1, Ordering::Relaxed);

        observe::trace(
            "executor_spawn",
            format!("Executor '{}' spawning task", self.name),
        );

        self.inner.spawn(future)
    }

    /// Run a closure that returns a future
    ///
    /// Convenience wrapper around `block_on`.
    pub fn run<F, Fut, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.block_on(f())
    }

    /// Check if currently in an async context
    pub fn is_async(&self) -> bool {
        self.inner.is_async()
    }

    /// Check if currently in a sync context
    pub fn is_sync(&self) -> bool {
        self.inner.is_sync()
    }

    /// Get the executor name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get executor statistics
    pub fn stats(&self) -> ExecutorStatistics {
        self.inner.stats().into()
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Statistics for a specific executor
#[derive(Debug, Clone)]
pub struct ExecutorStatistics {
    /// Total block_on calls
    pub block_on_calls: u64,
    /// block_on calls in async mode
    pub block_on_async: u64,
    /// block_on calls in sync mode (created runtime)
    pub block_on_sync: u64,
    /// Runtimes created
    pub runtimes_created: u64,
    /// Spawn calls
    pub spawn_calls: u64,
    /// Successful spawns
    pub spawn_success: u64,
    /// Failed spawns (not in async mode)
    pub spawn_failed: u64,
    /// Whether currently in async mode
    pub is_async: bool,
}

impl From<PrimitiveStats> for ExecutorStatistics {
    fn from(stats: PrimitiveStats) -> Self {
        Self {
            block_on_calls: stats.block_on_calls,
            block_on_async: stats.block_on_async,
            block_on_sync: stats.block_on_sync,
            runtimes_created: stats.runtimes_created,
            spawn_calls: stats.spawn_calls,
            spawn_success: stats.spawn_success,
            spawn_failed: stats.spawn_failed,
            is_async: stats.is_async,
        }
    }
}

/// Global executor statistics
#[derive(Debug, Clone)]
pub struct GlobalExecutorStatistics {
    /// Total block_on calls across all executors
    pub total_block_on: u64,
    /// Total spawns across all executors
    pub total_spawns: u64,
    /// Sync mode executions
    pub sync_executions: u64,
    /// Async mode executions
    pub async_executions: u64,
}

/// Get global executor statistics
pub fn executor_stats() -> GlobalExecutorStatistics {
    GlobalExecutorStatistics {
        total_block_on: EXECUTOR_STATS.total_block_on.load(Ordering::Relaxed),
        total_spawns: EXECUTOR_STATS.total_spawns.load(Ordering::Relaxed),
        sync_executions: EXECUTOR_STATS.sync_executions.load(Ordering::Relaxed),
        async_executions: EXECUTOR_STATS.async_executions.load(Ordering::Relaxed),
    }
}

/// Check if executors are performing well
///
/// Returns true if most executions are in async context (not creating runtimes).
pub fn executors_healthy() -> bool {
    let stats = executor_stats();
    if stats.total_block_on == 0 {
        return true;
    }

    // Healthy if less than 10% of executions require runtime creation
    let sync_rate = stats.sync_executions as f64 / stats.total_block_on as f64;
    sync_rate < 0.1
}

/// Check if executors are degraded
///
/// Returns true if sync execution rate is between 10% and 30%.
pub fn executors_is_degraded() -> bool {
    let stats = executor_stats();
    if stats.total_block_on == 0 {
        return false;
    }

    let sync_rate = stats.sync_executions as f64 / stats.total_block_on as f64;
    (0.1..0.3).contains(&sync_rate)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_executor_default() {
        let executor = Executor::default();
        assert_eq!(executor.name(), "default");
    }

    #[test]
    fn test_executor_with_name() {
        let executor = Executor::with_name("custom");
        assert_eq!(executor.name(), "custom");
    }

    #[test]
    fn test_executor_sync_mode() {
        let executor = Executor::new();

        // In test context without runtime, should be sync
        assert!(executor.is_sync());

        let result = executor.block_on(async { 42 }).expect("should succeed");
        assert_eq!(result, 42);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_executor_async_mode() {
        let executor = Executor::new();

        // In tokio::test with multi_thread, should detect async
        assert!(executor.is_async());

        let result = executor
            .block_on(async { "hello" })
            .expect("should succeed");
        assert_eq!(result, "hello");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_executor_spawn() {
        let executor = Executor::new();
        assert!(executor.is_async());

        let handle = executor.spawn(async { 123 }).expect("spawn should succeed");
        let result = handle.await.expect("task should complete");
        assert_eq!(result, 123);
    }

    #[test]
    fn test_executor_spawn_in_sync_fails() {
        let executor = Executor::new();
        assert!(executor.is_sync());

        let result = executor.spawn(async { 42 });
        assert!(result.is_err());
    }

    #[test]
    fn test_config_presets() {
        let _light = ExecutorConfig::lightweight();
        let _full = ExecutorConfig::full_featured();
        let _compute = ExecutorConfig::compute_only();
        // Just verify they don't panic
    }

    #[test]
    fn test_global_stats() {
        let stats = executor_stats();
        // Just verify the function returns valid stats
        let _ = stats.total_block_on; // Verify field exists
    }
}

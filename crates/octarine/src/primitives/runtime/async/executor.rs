//! Adaptive executor for sync/async context handling
//!
//! Pure executor implementation with no dependencies on observe or other internal
//! modules. The `runtime` module wraps these primitives and adds observability.
#![allow(dead_code)] // Public API primitives - not all items used internally yet
//!
//! ## Features
//!
//! - **Adaptive execution**: Detects async context and adapts strategy
//! - **Runtime creation**: Creates temporary runtime in sync contexts
//! - **Task spawning**: Spawn tasks when in async context
//! - **Configuration**: Worker threads, time/IO features
//!
//! ## Usage Examples
//!
//! ### Basic Execution
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::executor::AdaptiveExecutor;
//!
//! let executor = AdaptiveExecutor::new();
//!
//! // Works in both sync and async contexts
//! let result = executor.block_on(async { 42 })?;
//! assert_eq!(result, 42);
//! ```
//!
//! ### With Configuration
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::executor::{AdaptiveExecutor, ExecutorConfig};
//!
//! let config = ExecutorConfig::default()
//!     .with_worker_threads(4)
//!     .with_time(true)
//!     .with_io(true);
//!
//! let executor = AdaptiveExecutor::with_config(config);
//! ```
//!
//! ### Spawning Tasks
//!
//! ```rust,ignore
//! // Only works in async context
//! if executor.is_async() {
//!     let handle = executor.spawn(async { do_work().await })?;
//!     let result = handle.await?;
//! }
//! ```
//!
//! ## Design Notes
//!
//! This is a **primitive** module - it has NO dependencies on observe or other
//! internal modules. The `runtime::Executor` wrapper adds logging, metrics,
//! and event dispatching.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::runtime::{Handle, Runtime};

use crate::primitives::{Problem, Result};

// =============================================================================
// Executor Configuration
// =============================================================================

/// Configuration for the adaptive executor
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Whether to create a runtime if not in async context
    pub create_runtime: bool,
    /// Number of worker threads for created runtime
    pub worker_threads: usize,
    /// Enable time features in created runtime
    pub enable_time: bool,
    /// Enable I/O features in created runtime
    pub enable_io: bool,
}

impl ExecutorConfig {
    /// Create a new executor configuration with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether to create a runtime in sync context
    pub fn with_create_runtime(mut self, create: bool) -> Self {
        self.create_runtime = create;
        self
    }

    /// Set the number of worker threads
    ///
    /// Setting to 1 uses current-thread runtime (lighter weight).
    /// Setting to > 1 uses multi-thread runtime.
    pub fn with_worker_threads(mut self, threads: usize) -> Self {
        self.worker_threads = threads;
        self
    }

    /// Enable or disable time features
    pub fn with_time(mut self, enable: bool) -> Self {
        self.enable_time = enable;
        self
    }

    /// Enable or disable I/O features
    pub fn with_io(mut self, enable: bool) -> Self {
        self.enable_io = enable;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.worker_threads == 0 {
            return Err(Problem::Validation(
                "Worker threads must be at least 1".into(),
            ));
        }
        Ok(())
    }

    /// Lightweight configuration for simple async operations
    ///
    /// Single-threaded with time support only. Minimal overhead for
    /// simple async tasks like timeouts and delays.
    ///
    /// - Single thread
    /// - Time enabled, I/O disabled
    pub fn lightweight() -> Self {
        Self {
            create_runtime: true,
            worker_threads: 1,
            enable_time: true,
            enable_io: false,
        }
    }

    /// Full-featured configuration for I/O-heavy workloads
    ///
    /// Multi-threaded with all features enabled. Good for applications
    /// doing network I/O, file operations, etc.
    ///
    /// - Workers: Number of logical CPUs
    /// - Time and I/O enabled
    pub fn full_featured() -> Self {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Self {
            create_runtime: true,
            worker_threads: cpus,
            enable_time: true,
            enable_io: true,
        }
    }

    /// Computation-only configuration
    ///
    /// Multi-threaded but no I/O features. Good for CPU-bound async
    /// tasks that don't need network or file I/O.
    ///
    /// - Workers: Number of logical CPUs
    /// - Time enabled, I/O disabled
    pub fn compute_only() -> Self {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Self {
            create_runtime: true,
            worker_threads: cpus,
            enable_time: true,
            enable_io: false,
        }
    }
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            create_runtime: true,
            worker_threads: 1, // Single-threaded by default (lighter weight)
            enable_time: true,
            enable_io: true,
        }
    }
}

// =============================================================================
// Execution Mode
// =============================================================================

/// Internal execution mode
#[derive(Debug, Clone)]
enum ExecutorMode {
    /// We're inside a tokio runtime
    Async(Handle),
    /// No runtime detected, need to create one
    Sync,
}

// =============================================================================
// Executor Statistics
// =============================================================================

/// Statistics for executor operations
#[derive(Debug)]
pub struct ExecutorStats {
    /// Total block_on calls
    pub block_on_calls: u64,
    /// Block_on calls in async mode
    pub block_on_async: u64,
    /// Block_on calls in sync mode (runtime created)
    pub block_on_sync: u64,
    /// Total spawn calls
    pub spawn_calls: u64,
    /// Successful spawns
    pub spawn_success: u64,
    /// Failed spawns (no runtime)
    pub spawn_failed: u64,
    /// Runtimes created
    pub runtimes_created: u64,
    /// Whether currently in async mode
    pub is_async: bool,
}

/// Internal metrics tracking
struct ExecutorMetrics {
    block_on_calls: AtomicU64,
    block_on_async: AtomicU64,
    block_on_sync: AtomicU64,
    spawn_calls: AtomicU64,
    spawn_success: AtomicU64,
    spawn_failed: AtomicU64,
    runtimes_created: AtomicU64,
}

impl ExecutorMetrics {
    fn new() -> Self {
        Self {
            block_on_calls: AtomicU64::new(0),
            block_on_async: AtomicU64::new(0),
            block_on_sync: AtomicU64::new(0),
            spawn_calls: AtomicU64::new(0),
            spawn_success: AtomicU64::new(0),
            spawn_failed: AtomicU64::new(0),
            runtimes_created: AtomicU64::new(0),
        }
    }

    fn snapshot(&self, is_async: bool) -> ExecutorStats {
        ExecutorStats {
            block_on_calls: self.block_on_calls.load(Ordering::Relaxed),
            block_on_async: self.block_on_async.load(Ordering::Relaxed),
            block_on_sync: self.block_on_sync.load(Ordering::Relaxed),
            spawn_calls: self.spawn_calls.load(Ordering::Relaxed),
            spawn_success: self.spawn_success.load(Ordering::Relaxed),
            spawn_failed: self.spawn_failed.load(Ordering::Relaxed),
            runtimes_created: self.runtimes_created.load(Ordering::Relaxed),
            is_async,
        }
    }
}

// =============================================================================
// Adaptive Executor
// =============================================================================

/// An executor that adapts to both async and sync contexts
///
/// This executor automatically detects whether it's running inside a tokio
/// runtime and adapts its execution strategy accordingly:
///
/// - **Async mode**: Uses `block_in_place` to run futures on the existing runtime
/// - **Sync mode**: Creates a temporary runtime to run the future
///
/// # Example
///
/// ```rust,ignore
/// use octarine::primitives::runtime::executor::AdaptiveExecutor;
///
/// // Works in both sync and async contexts
/// let executor = AdaptiveExecutor::new();
/// let result = executor.block_on(async { 42 })?;
/// ```
pub struct AdaptiveExecutor {
    mode: ExecutorMode,
    config: ExecutorConfig,
    metrics: ExecutorMetrics,
}

impl AdaptiveExecutor {
    /// Create a new adaptive executor with default configuration
    ///
    /// Automatically detects if we're in an async context.
    pub fn new() -> Self {
        Self::with_config(ExecutorConfig::default())
    }

    /// Create an adaptive executor with custom configuration
    pub fn with_config(config: ExecutorConfig) -> Self {
        let mode = Handle::try_current()
            .map(ExecutorMode::Async)
            .unwrap_or(ExecutorMode::Sync);

        Self {
            mode,
            config,
            metrics: ExecutorMetrics::new(),
        }
    }

    /// Check if we're in an async context
    ///
    /// Returns `true` if a tokio runtime was detected, `false` otherwise.
    pub fn is_async(&self) -> bool {
        matches!(self.mode, ExecutorMode::Async(_))
    }

    /// Check if we're in a sync context
    pub fn is_sync(&self) -> bool {
        matches!(self.mode, ExecutorMode::Sync)
    }

    /// Get the current configuration
    pub fn config(&self) -> &ExecutorConfig {
        &self.config
    }

    /// Get current statistics
    pub fn stats(&self) -> ExecutorStats {
        self.metrics.snapshot(self.is_async())
    }

    /// Execute a future, adapting to the current context
    ///
    /// In async mode, uses `block_in_place` to run on the existing runtime.
    /// In sync mode, creates a temporary runtime if configured to do so.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - In sync mode and `create_runtime` is false
    /// - Runtime creation fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let executor = AdaptiveExecutor::new();
    /// let result = executor.block_on(async {
    ///     do_async_work().await
    /// })?;
    /// ```
    pub fn block_on<F>(&self, future: F) -> Result<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.metrics.block_on_calls.fetch_add(1, Ordering::Relaxed);

        match &self.mode {
            ExecutorMode::Async(handle) => {
                self.metrics.block_on_async.fetch_add(1, Ordering::Relaxed);
                // We're already in async context, use block_in_place
                Ok(tokio::task::block_in_place(move || handle.block_on(future)))
            }

            ExecutorMode::Sync => {
                if !self.config.create_runtime {
                    return Err(Problem::Runtime(
                        "No runtime available and create_runtime is disabled".into(),
                    ));
                }

                self.metrics.block_on_sync.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .runtimes_created
                    .fetch_add(1, Ordering::Relaxed);

                // Create a minimal runtime
                let runtime = self.create_runtime()?;
                Ok(runtime.block_on(future))
            }
        }
    }

    /// Spawn a task on the runtime
    ///
    /// Only works in async mode. Returns error in sync mode.
    ///
    /// # Errors
    ///
    /// Returns error if not in async mode (no runtime to spawn on).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let executor = AdaptiveExecutor::new();
    /// if executor.is_async() {
    ///     let handle = executor.spawn(async { 42 })?;
    ///     let result = handle.await?;
    /// }
    /// ```
    pub fn spawn<F>(&self, future: F) -> Result<tokio::task::JoinHandle<F::Output>>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.metrics.spawn_calls.fetch_add(1, Ordering::Relaxed);

        match &self.mode {
            ExecutorMode::Async(handle) => {
                self.metrics.spawn_success.fetch_add(1, Ordering::Relaxed);
                Ok(handle.spawn(future))
            }

            ExecutorMode::Sync => {
                self.metrics.spawn_failed.fetch_add(1, Ordering::Relaxed);
                Err(Problem::Runtime(
                    "Cannot spawn: no async runtime available".into(),
                ))
            }
        }
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

    /// Create a minimal runtime for sync contexts
    fn create_runtime(&self) -> Result<Runtime> {
        let mut builder = if self.config.worker_threads == 1 {
            tokio::runtime::Builder::new_current_thread()
        } else {
            let mut b = tokio::runtime::Builder::new_multi_thread();
            b.worker_threads(self.config.worker_threads);
            b
        };

        if self.config.enable_time {
            builder.enable_time();
        }

        if self.config.enable_io {
            builder.enable_io();
        }

        builder
            .build()
            .map_err(|e| Problem::Runtime(format!("Failed to create tokio runtime: {}", e)))
    }
}

impl Default for AdaptiveExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Result Types
// =============================================================================

/// Outcome of an execution attempt
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// Executed in async mode (existing runtime)
    ExecutedAsync,
    /// Executed in sync mode (created runtime)
    ExecutedSync,
    /// Could not execute
    Failed(String),
}

impl std::fmt::Display for ExecutionOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionOutcome::ExecutedAsync => write!(f, "ExecutedAsync"),
            ExecutionOutcome::ExecutedSync => write!(f, "ExecutedSync"),
            ExecutionOutcome::Failed(reason) => write!(f, "Failed({})", reason),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // =========================================================================
    // ExecutorConfig Tests
    // =========================================================================

    #[test]
    fn test_executor_config_default() {
        let config = ExecutorConfig::default();
        assert!(config.create_runtime);
        assert_eq!(config.worker_threads, 1);
        assert!(config.enable_time);
        assert!(config.enable_io);
    }

    #[test]
    fn test_executor_config_builder() {
        let config = ExecutorConfig::new()
            .with_create_runtime(false)
            .with_worker_threads(4)
            .with_time(false)
            .with_io(false);

        assert!(!config.create_runtime);
        assert_eq!(config.worker_threads, 4);
        assert!(!config.enable_time);
        assert!(!config.enable_io);
    }

    #[test]
    fn test_executor_config_validate() {
        let valid = ExecutorConfig::new();
        assert!(valid.validate().is_ok());

        let invalid = ExecutorConfig::new().with_worker_threads(0);
        assert!(invalid.validate().is_err());
    }

    // =========================================================================
    // AdaptiveExecutor Tests - Sync Context
    // =========================================================================

    #[test]
    fn test_executor_sync_context() {
        // Not in async context
        let executor = AdaptiveExecutor::new();
        assert!(!executor.is_async());
        assert!(executor.is_sync());
    }

    #[test]
    fn test_executor_block_on_sync() {
        let executor = AdaptiveExecutor::new();

        let result = executor
            .block_on(async { 42 })
            .expect("execution should succeed");

        assert_eq!(result, 42);
    }

    #[test]
    fn test_executor_block_on_sync_complex() {
        let executor = AdaptiveExecutor::new();

        let result = executor
            .block_on(async {
                let a = 10;
                let b = 20;
                a + b
            })
            .expect("execution should succeed");

        assert_eq!(result, 30);
    }

    #[test]
    fn test_executor_spawn_fails_in_sync() {
        let executor = AdaptiveExecutor::new();

        let result = executor.spawn(async { 42 });
        assert!(result.is_err());
    }

    #[test]
    fn test_executor_no_create_runtime() {
        let config = ExecutorConfig::new().with_create_runtime(false);
        let executor = AdaptiveExecutor::with_config(config);

        let result = executor.block_on(async { 42 });
        assert!(result.is_err());
    }

    #[test]
    fn test_executor_run_convenience() {
        let executor = AdaptiveExecutor::new();

        let result = executor
            .run(|| async { "hello" })
            .expect("run should succeed");

        assert_eq!(result, "hello");
    }

    #[test]
    fn test_executor_stats_sync() {
        let executor = AdaptiveExecutor::new();

        // Initial stats
        let stats = executor.stats();
        assert_eq!(stats.block_on_calls, 0);
        assert!(!stats.is_async);

        // After block_on
        let _ = executor.block_on(async { 1 });
        let stats = executor.stats();
        assert_eq!(stats.block_on_calls, 1);
        assert_eq!(stats.block_on_sync, 1);
        assert_eq!(stats.runtimes_created, 1);
    }

    // =========================================================================
    // AdaptiveExecutor Tests - Async Context
    // =========================================================================

    #[tokio::test(flavor = "multi_thread")]
    async fn test_executor_async_context() {
        let executor = AdaptiveExecutor::new();
        assert!(executor.is_async());
        assert!(!executor.is_sync());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_executor_block_on_async() {
        let executor = AdaptiveExecutor::new();

        let result = executor
            .block_on(async { "async result" })
            .expect("execution should succeed");

        assert_eq!(result, "async result");
    }

    #[tokio::test]
    async fn test_executor_spawn_in_async() {
        let executor = AdaptiveExecutor::new();

        let handle = executor
            .spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                100
            })
            .expect("spawn should succeed");

        let result = handle.await.expect("task should complete");
        assert_eq!(result, 100);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_executor_stats_async() {
        let executor = AdaptiveExecutor::new();

        let _ = executor.block_on(async { 1 });
        let stats = executor.stats();
        assert_eq!(stats.block_on_calls, 1);
        assert_eq!(stats.block_on_async, 1);
        assert_eq!(stats.runtimes_created, 0);
        assert!(stats.is_async);
    }

    // =========================================================================
    // ExecutionOutcome Tests
    // =========================================================================

    #[test]
    fn test_execution_outcome_display() {
        assert_eq!(
            format!("{}", ExecutionOutcome::ExecutedAsync),
            "ExecutedAsync"
        );
        assert_eq!(
            format!("{}", ExecutionOutcome::ExecutedSync),
            "ExecutedSync"
        );
        assert_eq!(
            format!("{}", ExecutionOutcome::Failed("no runtime".into())),
            "Failed(no runtime)"
        );
    }

    // =========================================================================
    // Multi-threaded Runtime Tests
    // =========================================================================

    #[test]
    fn test_executor_multi_threaded() {
        let config = ExecutorConfig::new().with_worker_threads(2);
        let executor = AdaptiveExecutor::with_config(config);

        let result = executor
            .block_on(async { 42 })
            .expect("execution should succeed");

        assert_eq!(result, 42);
    }

    #[test]
    fn test_preset_lightweight() {
        let config = ExecutorConfig::lightweight();
        assert!(config.create_runtime);
        assert_eq!(config.worker_threads, 1);
        assert!(config.enable_time);
        assert!(!config.enable_io);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preset_full_featured() {
        let config = ExecutorConfig::full_featured();
        assert!(config.create_runtime);
        assert!(config.worker_threads >= 1); // At least 1 CPU
        assert!(config.enable_time);
        assert!(config.enable_io);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preset_compute_only() {
        let config = ExecutorConfig::compute_only();
        assert!(config.create_runtime);
        assert!(config.worker_threads >= 1); // At least 1 CPU
        assert!(config.enable_time);
        assert!(!config.enable_io);
        assert!(config.validate().is_ok());
    }
}

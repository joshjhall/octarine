//! Shortcut functions for common async runtime operations
//!
//! These functions provide convenient access to the most common runtime operations
//! without needing to construct the full types.

use crate::observe::{self, Result};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::task::JoinError;

use super::{
    Channel, ChannelReceiver, ChannelSender, CircuitBreaker, CircuitBreakerStatistics, Executor,
    GlobalChannelStatistics, GlobalExecutorStatistics, GlobalWorkerStatistics, RetryStatistics,
    WorkerPool, channel_stats, channels_healthy, circuit_breaker_stats, circuit_breakers_healthy,
    executor_stats, executors_healthy, retry_is_healthy, retry_stats, worker_stats,
    workers_healthy,
};

// ============================================================================
// Creation Shortcuts
// ============================================================================

/// Create a bounded channel with default settings
///
/// Shortcut for `Channel::new(name, capacity)`.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::r#async::bounded_channel;
///
/// # tokio_test::block_on(async {
/// let (tx, mut rx) = bounded_channel::<String>("events", 1000);
/// tx.send("hello".to_string()).await.unwrap();
/// let msg = rx.recv().await;
/// assert_eq!(msg, Some("hello".to_string()));
/// # });
/// ```
pub fn bounded_channel<T: Send + 'static>(
    name: impl Into<String>,
    capacity: usize,
) -> (ChannelSender<T>, ChannelReceiver<T>) {
    Channel::new(name, capacity).split()
}

/// Create a new circuit breaker with default settings
///
/// Shortcut for `CircuitBreaker::with_defaults(name)`.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::r#async::circuit_breaker;
///
/// let breaker = circuit_breaker("database");
/// assert!(breaker.is_healthy());
/// ```
pub fn circuit_breaker(name: &str) -> CircuitBreaker {
    CircuitBreaker::with_defaults(name)
}

/// Create a new worker pool
///
/// Shortcut for `WorkerPool::new(name, workers)`.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::r#async::worker_pool;
///
/// # tokio_test::block_on(async {
/// let pool = worker_pool("processors", 4);
/// pool.spawn(|| { /* task */ }).unwrap();
/// pool.shutdown().await;
/// # });
/// ```
pub fn worker_pool(name: impl Into<String>, workers: usize) -> WorkerPool {
    WorkerPool::new(name, workers)
}

/// Create a new executor
///
/// Shortcut for `Executor::new()`.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::r#async::executor;
///
/// let exec = executor();
/// let result = exec.block_on(async { 42 });
/// assert!(result.is_ok());
/// ```
pub fn executor() -> Executor {
    Executor::new()
}

/// Spawn a task on the default executor
///
/// Only works in async context. Use `executor().block_on()` for sync contexts.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::r#async::spawn;
///
/// # tokio_test::block_on(async {
/// let handle = spawn(async { 42 }).unwrap();
/// let result = handle.await.unwrap();
/// assert_eq!(result, 42);
/// # });
/// ```
pub fn spawn<F>(future: F) -> Result<tokio::task::JoinHandle<F::Output>>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    Executor::new().spawn(future)
}

// ============================================================================
// Blocking Operations
// ============================================================================

/// Global statistics for spawn_blocking calls
static SPAWN_BLOCKING_STATS: SpawnBlockingStats = SpawnBlockingStats::new();

struct SpawnBlockingStats {
    total_spawned: AtomicU64,
    total_completed: AtomicU64,
    total_failed: AtomicU64,
}

impl SpawnBlockingStats {
    const fn new() -> Self {
        Self {
            total_spawned: AtomicU64::new(0),
            total_completed: AtomicU64::new(0),
            total_failed: AtomicU64::new(0),
        }
    }
}

/// Statistics for spawn_blocking operations
#[derive(Debug, Clone, Default)]
pub struct SpawnBlockingStatistics {
    /// Total blocking tasks spawned
    pub total_spawned: u64,
    /// Total blocking tasks completed successfully
    pub total_completed: u64,
    /// Total blocking tasks that failed (panicked or cancelled)
    pub total_failed: u64,
}

/// Get statistics for spawn_blocking operations
pub fn spawn_blocking_stats() -> SpawnBlockingStatistics {
    SpawnBlockingStatistics {
        total_spawned: SPAWN_BLOCKING_STATS.total_spawned.load(Ordering::Relaxed),
        total_completed: SPAWN_BLOCKING_STATS.total_completed.load(Ordering::Relaxed),
        total_failed: SPAWN_BLOCKING_STATS.total_failed.load(Ordering::Relaxed),
    }
}

/// Run a blocking operation on a dedicated thread pool with observability
///
/// Use this for CPU-intensive work or blocking I/O operations that shouldn't
/// block the async runtime. Context (correlation ID, tenant, user, session) is
/// automatically propagated to the blocking thread.
///
/// This is the Layer 3 wrapper that adds observe instrumentation. For use within
/// other Layer 3 modules (like crypto), use the primitive version directly and
/// add your own observe calls.
///
/// # When to Use
///
/// - CPU-intensive operations (password hashing, encryption of large data)
/// - Blocking I/O (sync file operations, blocking database drivers)
/// - Operations that take >1ms and would block other async tasks
///
/// # Example
///
/// ```rust,ignore
/// use octarine::runtime::r#async::spawn_blocking;
///
/// // CPU-intensive work
/// let hash = spawn_blocking(|| {
///     compute_expensive_hash(&data)
/// }).await?;
///
/// // Blocking file I/O
/// let contents = spawn_blocking(|| {
///     std::fs::read_to_string("large_file.txt")
/// }).await??;
/// ```
///
/// # Errors
///
/// Returns `JoinError` if the blocking task panics or is cancelled.
pub async fn spawn_blocking<F, R>(f: F) -> std::result::Result<R, JoinError>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    SPAWN_BLOCKING_STATS
        .total_spawned
        .fetch_add(1, Ordering::Relaxed);

    let start = Instant::now();
    observe::trace("spawn_blocking", "Spawning blocking task");

    let result = crate::primitives::runtime::r#async::async_utils::spawn_blocking(f).await;

    let elapsed = start.elapsed();

    match &result {
        Ok(_) => {
            SPAWN_BLOCKING_STATS
                .total_completed
                .fetch_add(1, Ordering::Relaxed);
            observe::debug(
                "spawn_blocking",
                format!("Blocking task completed in {:?}", elapsed),
            );
        }
        Err(e) => {
            SPAWN_BLOCKING_STATS
                .total_failed
                .fetch_add(1, Ordering::Relaxed);
            observe::warn(
                "spawn_blocking",
                format!("Blocking task failed after {:?}: {}", elapsed, e),
            );
        }
    }

    result
}

// ============================================================================
// Health Monitoring
// ============================================================================

/// Combined async runtime health status
#[derive(Debug, Clone)]
pub struct RuntimeHealth {
    /// Whether channels are healthy
    pub channels_ok: bool,
    /// Whether circuit breakers are healthy
    pub circuit_breakers_ok: bool,
    /// Whether executors are healthy
    pub executors_ok: bool,
    /// Whether workers are healthy
    pub workers_ok: bool,
    /// Whether retry system is healthy
    pub retry_ok: bool,
}

impl RuntimeHealth {
    /// Check if all runtime components are healthy
    pub fn is_healthy(&self) -> bool {
        self.channels_ok
            && self.circuit_breakers_ok
            && self.executors_ok
            && self.workers_ok
            && self.retry_ok
    }

    /// Check if any runtime component is degraded
    pub fn is_degraded(&self) -> bool {
        !self.is_healthy()
    }

    /// Get a summary of the health status
    pub fn summary(&self) -> String {
        let mut issues = Vec::new();
        if !self.channels_ok {
            issues.push("channels");
        }
        if !self.circuit_breakers_ok {
            issues.push("circuit_breakers");
        }
        if !self.executors_ok {
            issues.push("executors");
        }
        if !self.workers_ok {
            issues.push("workers");
        }
        if !self.retry_ok {
            issues.push("retry");
        }

        if issues.is_empty() {
            "all systems healthy".to_string()
        } else {
            format!("degraded: {}", issues.join(", "))
        }
    }
}

/// Get combined async runtime health status
///
/// Checks all async runtime components and returns a unified health report.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::r#async::runtime_health;
///
/// let health = runtime_health();
/// if health.is_degraded() {
///     eprintln!("Warning: {}", health.summary());
/// }
/// ```
pub fn runtime_health() -> RuntimeHealth {
    RuntimeHealth {
        channels_ok: channels_healthy(),
        circuit_breakers_ok: circuit_breakers_healthy(),
        executors_ok: executors_healthy(),
        workers_ok: workers_healthy(),
        retry_ok: retry_is_healthy(),
    }
}

/// Combined async runtime statistics
#[derive(Debug, Clone)]
pub struct RuntimeStats {
    /// Channel statistics
    pub channels: GlobalChannelStatistics,
    /// Executor statistics
    pub executors: GlobalExecutorStatistics,
    /// Worker statistics
    pub workers: GlobalWorkerStatistics,
    /// Retry statistics
    pub retry: RetryStatistics,
    /// Circuit breaker statistics
    pub circuit_breakers: CircuitBreakerStatistics,
}

/// Get combined async runtime statistics
///
/// Returns statistics from all async runtime components.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::r#async::runtime_stats;
///
/// let stats = runtime_stats();
/// let _ = stats.retry.total_operations;
/// let _ = stats.circuit_breakers.total_calls;
/// ```
pub fn runtime_stats() -> RuntimeStats {
    RuntimeStats {
        channels: channel_stats(),
        executors: executor_stats(),
        workers: worker_stats(),
        retry: retry_stats(),
        circuit_breakers: circuit_breaker_stats(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[tokio::test]
    async fn test_bounded_channel() {
        let (tx, mut rx) = bounded_channel::<i32>("test", 10);
        tx.send(42).await.expect("send should succeed");
        let received = rx.recv().await;
        assert_eq!(received, Some(42));
    }

    #[test]
    fn test_circuit_breaker_shortcut() {
        let cb = circuit_breaker("test_shortcut");
        assert!(cb.is_healthy());
        assert!(!cb.is_degraded());
    }

    #[tokio::test]
    async fn test_worker_pool_shortcut() {
        let pool = worker_pool("test_shortcut", 2);
        assert_eq!(pool.name(), "test_shortcut");
        pool.shutdown().await;
    }

    #[test]
    fn test_executor_shortcut() {
        let exec = executor();
        assert_eq!(exec.name(), "default");
    }

    #[tokio::test]
    async fn test_spawn_shortcut() {
        let handle = spawn(async { 42 }).expect("spawn should succeed in async context");
        let result = handle.await.expect("task should complete");
        assert_eq!(result, 42);
    }

    #[test]
    fn test_runtime_health() {
        let health = runtime_health();
        let _ = health.is_healthy();
        let _ = health.is_degraded();
        let summary = health.summary();
        assert!(
            summary == "all systems healthy" || summary.starts_with("degraded:"),
            "Unexpected summary: {}",
            summary
        );
    }

    #[test]
    fn test_runtime_health_summary_degraded() {
        let health = RuntimeHealth {
            channels_ok: false,
            circuit_breakers_ok: true,
            executors_ok: true,
            workers_ok: false,
            retry_ok: true,
        };
        assert!(health.is_degraded());
        assert!(!health.is_healthy());
        assert_eq!(health.summary(), "degraded: channels, workers");
    }

    #[test]
    fn test_runtime_stats() {
        let stats = runtime_stats();
        let _ = stats.channels.total_channels;
        let _ = stats.circuit_breakers.total_calls;
        let _ = stats.executors.total_block_on;
        let _ = stats.workers.total_pools;
        let _ = stats.retry.total_operations;
    }

    #[tokio::test]
    async fn test_spawn_blocking_basic() {
        let result = spawn_blocking(|| {
            // Simulate blocking work
            std::thread::sleep(std::time::Duration::from_millis(1));
            42
        })
        .await
        .expect("spawn_blocking should succeed");

        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_spawn_blocking_with_result() {
        let result: std::result::Result<i32, &str> = spawn_blocking(|| Ok(42))
            .await
            .expect("spawn_blocking should succeed");

        assert_eq!(result, Ok(42));
    }

    #[test]
    fn test_spawn_blocking_stats() {
        let stats = spawn_blocking_stats();
        // Just verify we can access the stats - actual values depend on other tests
        let _ = stats.total_spawned;
        let _ = stats.total_completed;
        let _ = stats.total_failed;
    }
}

//! Worker pool with observability
//!
//! Provides a fixed-size worker pool for executing tasks with comprehensive
//! logging, metrics, and health monitoring.
//!
//! # Features
//!
//! - Fixed-size worker pool with bounded queue
//! - Full observability (logging, metrics)
//! - Health monitoring and backpressure detection
//! - Graceful shutdown
//!
//! # Example
//!
//! ```rust
//! use octarine::runtime::r#async::{WorkerPool, WorkerConfig};
//!
//! # tokio_test::block_on(async {
//! // Create a pool with 4 workers
//! let pool = WorkerPool::new("processors", 4);
//!
//! // Spawn tasks
//! pool.spawn(|| {
//!     // Do work here
//! }).unwrap();
//!
//! // Graceful shutdown
//! pool.shutdown().await;
//! # });
//! ```

// Allow arithmetic operations - counters are bounded and safe
#![allow(clippy::arithmetic_side_effects)]

use crate::observe::{self, Result};
use crate::primitives::runtime::r#async::{
    WorkerConfig as PrimitiveConfig, WorkerPool as PrimitivePool, WorkerStats as PrimitiveStats,
};
use std::sync::atomic::{AtomicU64, Ordering};

/// Global worker pool statistics
static WORKER_STATS: WorkerStats = WorkerStats::new();

struct WorkerStats {
    total_pools: AtomicU64,
    total_spawned: AtomicU64,
    total_completed: AtomicU64,
    total_rejected: AtomicU64,
}

impl WorkerStats {
    const fn new() -> Self {
        Self {
            total_pools: AtomicU64::new(0),
            total_spawned: AtomicU64::new(0),
            total_completed: AtomicU64::new(0),
            total_rejected: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Worker pool configuration
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    inner: PrimitiveConfig,
}

impl WorkerConfig {
    /// Create a new configuration
    ///
    /// # Arguments
    ///
    /// * `name` - Name for logging and metrics
    /// * `workers` - Number of worker threads
    pub fn new(name: impl Into<String>, workers: usize) -> Self {
        Self {
            inner: PrimitiveConfig::new(name, workers, 1000),
        }
    }

    /// Set the task queue size
    pub fn with_queue_size(mut self, size: usize) -> Self {
        self.inner = self.inner.with_queue_size(size);
        self
    }

    /// Configuration for CPU-bound tasks
    ///
    /// Uses number of CPUs as worker count, large queue.
    pub fn cpu_bound(name: impl Into<String>) -> Self {
        Self {
            inner: PrimitiveConfig::cpu_bound(name),
        }
    }

    /// Configuration for I/O-bound tasks
    ///
    /// Uses 2x CPUs as worker count (to handle blocking).
    pub fn io_bound(name: impl Into<String>) -> Self {
        Self {
            inner: PrimitiveConfig::io_bound(name),
        }
    }

    /// Single-threaded configuration
    ///
    /// Useful for tasks that must run sequentially.
    pub fn single_threaded(name: impl Into<String>) -> Self {
        Self {
            inner: PrimitiveConfig::single_threaded(name),
        }
    }

    /// Get the pool name
    pub fn name(&self) -> &str {
        &self.inner.name_prefix
    }

    /// Get the number of workers
    pub fn workers(&self) -> usize {
        self.inner.worker_count
    }

    /// Get the queue size
    pub fn queue_size(&self) -> usize {
        self.inner.queue_size
    }
}

// ============================================================================
// Worker Pool
// ============================================================================

/// Worker pool with observability
///
/// A fixed-size pool of worker threads that process tasks from a queue.
/// Provides comprehensive logging and metrics for all operations.
pub struct WorkerPool {
    inner: PrimitivePool,
    name: String,
}

impl WorkerPool {
    /// Create a new worker pool with default queue size
    ///
    /// # Arguments
    ///
    /// * `name` - Name for logging and metrics
    /// * `workers` - Number of worker threads
    pub fn new(name: impl Into<String>, workers: usize) -> Self {
        let config = WorkerConfig::new(name, workers);
        Self::with_config(config)
    }

    /// Create a worker pool with custom configuration
    pub fn with_config(config: WorkerConfig) -> Self {
        WORKER_STATS.total_pools.fetch_add(1, Ordering::Relaxed);

        observe::info(
            "worker_pool_created",
            format!(
                "Worker pool '{}' created ({} workers, queue: {})",
                config.name(),
                config.workers(),
                config.queue_size()
            ),
        );

        Self {
            name: config.name().to_string(),
            inner: PrimitivePool::new(config.inner),
        }
    }

    /// Spawn a task on the pool
    ///
    /// Returns an error if the queue is full or pool is shutting down.
    pub fn spawn<F>(&self, task: F) -> Result<()>
    where
        F: FnOnce() + Send + 'static,
    {
        let result = self.inner.spawn(task);

        match &result {
            Ok(()) => {
                WORKER_STATS.total_spawned.fetch_add(1, Ordering::Relaxed);
                observe::trace(
                    "worker_task_spawned",
                    format!("Task spawned on pool '{}'", self.name),
                );
            }
            Err(e) => {
                WORKER_STATS.total_rejected.fetch_add(1, Ordering::Relaxed);
                observe::warn(
                    "worker_task_rejected",
                    format!("Task rejected by pool '{}': {}", self.name, e),
                );
            }
        }

        result
    }

    /// Get the number of active workers
    pub fn active_workers(&self) -> usize {
        self.inner.active_workers()
    }

    /// Get the number of queued tasks
    pub fn queued_tasks(&self) -> usize {
        self.inner.queue_depth()
    }

    /// Check if the pool is idle (no active workers)
    pub fn is_idle(&self) -> bool {
        self.inner.is_idle()
    }

    /// Check if the pool is shutting down
    pub fn is_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    /// Get the pool name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Shutdown the pool gracefully
    ///
    /// Waits for all queued tasks to complete.
    pub async fn shutdown(self) {
        observe::info(
            "worker_pool_shutdown",
            format!("Worker pool '{}' shutting down", self.name),
        );

        self.inner.shutdown().await;

        observe::info(
            "worker_pool_stopped",
            format!("Worker pool '{}' stopped", self.name),
        );
    }

    /// Get pool statistics
    pub fn stats(&self) -> WorkerPoolStatistics {
        self.inner.stats().into()
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Statistics for a specific worker pool
#[derive(Debug, Clone)]
pub struct WorkerPoolStatistics {
    /// Pool name
    pub name: String,
    /// Total workers in the pool
    pub worker_count: usize,
    /// Currently active workers (executing tasks)
    pub active_workers: usize,
    /// Queue capacity
    pub queue_capacity: usize,
    /// Current queue depth (approximate)
    pub queue_depth: usize,
    /// Total tasks submitted
    pub tasks_submitted: u64,
    /// Total tasks completed
    pub tasks_completed: u64,
    /// Tasks rejected (queue full or shutdown)
    pub tasks_rejected: u64,
    /// Whether pool is shutting down
    pub is_shutdown: bool,
}

impl From<PrimitiveStats> for WorkerPoolStatistics {
    fn from(stats: PrimitiveStats) -> Self {
        Self {
            name: stats.name,
            worker_count: stats.worker_count,
            active_workers: stats.active_workers,
            queue_capacity: stats.queue_capacity,
            queue_depth: stats.queue_depth,
            tasks_submitted: stats.tasks_submitted,
            tasks_completed: stats.tasks_completed,
            tasks_rejected: stats.tasks_rejected,
            is_shutdown: stats.is_shutdown,
        }
    }
}

impl WorkerPoolStatistics {
    /// Calculate queue utilization (0.0 to 1.0)
    pub fn queue_utilization(&self) -> f64 {
        if self.queue_capacity == 0 {
            return 0.0;
        }
        self.queue_depth as f64 / self.queue_capacity as f64
    }

    /// Calculate worker utilization (0.0 to 1.0)
    pub fn worker_utilization(&self) -> f64 {
        if self.worker_count == 0 {
            return 0.0;
        }
        self.active_workers as f64 / self.worker_count as f64
    }

    /// Check if pool is under pressure
    pub fn is_under_pressure(&self) -> bool {
        self.queue_utilization() > 0.8 || self.worker_utilization() > 0.9
    }
}

/// Global worker pool statistics
#[derive(Debug, Clone)]
pub struct GlobalWorkerStatistics {
    /// Total pools created
    pub total_pools: u64,
    /// Total tasks spawned across all pools
    pub total_spawned: u64,
    /// Total tasks completed across all pools
    pub total_completed: u64,
    /// Total tasks rejected across all pools
    pub total_rejected: u64,
}

/// Get global worker pool statistics
pub fn worker_stats() -> GlobalWorkerStatistics {
    GlobalWorkerStatistics {
        total_pools: WORKER_STATS.total_pools.load(Ordering::Relaxed),
        total_spawned: WORKER_STATS.total_spawned.load(Ordering::Relaxed),
        total_completed: WORKER_STATS.total_completed.load(Ordering::Relaxed),
        total_rejected: WORKER_STATS.total_rejected.load(Ordering::Relaxed),
    }
}

/// Check if worker pools are healthy
///
/// Returns true if rejection rate is low.
pub fn workers_healthy() -> bool {
    let stats = worker_stats();
    if stats.total_spawned == 0 {
        return true;
    }

    let rejection_rate = stats.total_rejected as f64 / stats.total_spawned as f64;
    rejection_rate < 0.01 // Less than 1% rejection rate
}

/// Check if worker pools are degraded
///
/// Returns true if rejection rate is between 1% and 5%.
pub fn workers_is_degraded() -> bool {
    let stats = worker_stats();
    if stats.total_spawned == 0 {
        return false;
    }

    let rejection_rate = stats.total_rejected as f64 / stats.total_spawned as f64;
    (0.01..0.05).contains(&rejection_rate)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn test_worker_pool_basic() {
        let pool = WorkerPool::new("test", 2);

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        pool.spawn(move || {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        })
        .expect("spawn should succeed");

        // Give worker time to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(counter.load(Ordering::SeqCst), 1);
        pool.shutdown().await;
    }

    #[tokio::test]
    async fn test_worker_pool_multiple_tasks() {
        let pool = WorkerPool::new("multi", 4);
        let counter = Arc::new(AtomicUsize::new(0));

        for _ in 0..10 {
            let c = Arc::clone(&counter);
            pool.spawn(move || {
                c.fetch_add(1, Ordering::SeqCst);
            })
            .expect("spawn should succeed");
        }

        // Wait for completion
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert_eq!(counter.load(Ordering::SeqCst), 10);
        pool.shutdown().await;
    }

    #[test]
    fn test_worker_config_presets() {
        let cpu = WorkerConfig::cpu_bound("cpu");
        assert!(cpu.workers() >= 1);

        let io = WorkerConfig::io_bound("io");
        assert!(io.workers() >= 2);

        let single = WorkerConfig::single_threaded("single");
        assert_eq!(single.workers(), 1);
    }

    #[test]
    fn test_pool_statistics() {
        let stats = WorkerPoolStatistics {
            name: "test".to_string(),
            worker_count: 4,
            active_workers: 4,
            queue_capacity: 10,
            queue_depth: 4,
            tasks_submitted: 100,
            tasks_completed: 95,
            tasks_rejected: 0,
            is_shutdown: false,
        };

        assert!((stats.queue_utilization() - 0.4).abs() < f64::EPSILON);
        assert!((stats.worker_utilization() - 1.0).abs() < f64::EPSILON);
        assert!(stats.is_under_pressure()); // 100% worker utilization
    }

    #[test]
    fn test_global_stats() {
        let stats = worker_stats();
        // Just verify the function returns valid stats
        let _ = stats.total_pools; // Verify field exists
    }
}

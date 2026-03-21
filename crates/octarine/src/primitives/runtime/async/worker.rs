//! Worker pool for background task processing
//!
//! Pure worker pool implementation with no dependencies on observe or other
//! internal modules. The `runtime` module wraps these primitives and adds observability.
#![allow(dead_code)] // Public API primitives - not all items used internally yet
//!
//! ## Features
//!
//! - **Concurrent workers**: Configurable number of workers
//! - **Bounded queue**: Prevents unbounded memory growth (CWE-400)
//! - **Graceful shutdown**: Clean worker termination
//! - **Statistics tracking**: Monitor pool health
//!
//! ## Usage Examples
//!
//! ### Basic Worker Pool
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::worker::{WorkerPool, WorkerConfig};
//!
//! let config = WorkerConfig::new("my_pool", 4, 100);
//! let pool = WorkerPool::new(config);
//!
//! pool.execute(|| {
//!     println!("Task executed!");
//! }).await?;
//! ```
//!
//! ### Spawn Without Waiting
//!
//! ```rust,ignore
//! // Non-blocking task submission
//! pool.spawn(|| {
//!     expensive_work();
//! })?;
//! ```
//!
//! ### Monitoring
//!
//! ```rust,ignore
//! let stats = pool.stats();
//! println!("Active: {}, Completed: {}", stats.active_workers, stats.tasks_completed);
//! ```
//!
//! ## Design Notes
//!
//! This is a **primitive** module - it has NO dependencies on observe or other
//! internal modules. The `runtime::WorkerPool` wrapper adds logging, metrics,
//! and event dispatching.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::primitives::{Problem, Result};

// =============================================================================
// Worker Configuration
// =============================================================================

/// Configuration for a worker pool
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Name prefix for workers (for debugging)
    pub name_prefix: String,
    /// Number of worker threads
    pub worker_count: usize,
    /// Size of the task queue
    pub queue_size: usize,
}

impl WorkerConfig {
    /// Create a new worker configuration
    ///
    /// # Arguments
    ///
    /// * `name_prefix` - Name prefix for worker identification
    /// * `worker_count` - Number of worker threads
    /// * `queue_size` - Maximum tasks that can be queued
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = WorkerConfig::new("my_pool", 4, 100);
    /// ```
    pub fn new(name_prefix: impl Into<String>, worker_count: usize, queue_size: usize) -> Self {
        Self {
            name_prefix: name_prefix.into(),
            worker_count,
            queue_size,
        }
    }

    /// Set the name prefix
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name_prefix = name.into();
        self
    }

    /// Set the worker count
    pub fn with_workers(mut self, count: usize) -> Self {
        self.worker_count = count;
        self
    }

    /// Set the queue size
    pub fn with_queue_size(mut self, size: usize) -> Self {
        self.queue_size = size;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.worker_count == 0 {
            return Err(Problem::Validation("Worker count cannot be 0".into()));
        }
        if self.queue_size == 0 {
            return Err(Problem::Validation("Queue size cannot be 0".into()));
        }
        Ok(())
    }

    /// CPU-bound task configuration
    ///
    /// Uses all available CPUs with moderate queue depth.
    /// Good for computation-heavy tasks that benefit from parallelism.
    ///
    /// - Workers: Number of logical CPUs
    /// - Queue: 1,000 tasks
    pub fn cpu_bound(name: impl Into<String>) -> Self {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Self {
            name_prefix: name.into(),
            worker_count: cpus,
            queue_size: 1_000,
        }
    }

    /// I/O-bound task configuration
    ///
    /// More workers than CPUs to overlap I/O waits with larger queue.
    /// Good for tasks that spend time waiting on I/O operations.
    ///
    /// - Workers: 2x number of logical CPUs
    /// - Queue: 10,000 tasks
    pub fn io_bound(name: impl Into<String>) -> Self {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Self {
            name_prefix: name.into(),
            worker_count: cpus.saturating_mul(2),
            queue_size: 10_000,
        }
    }

    /// Single-threaded configuration
    ///
    /// Single worker for sequential processing. Good for tasks that
    /// must be processed in order or aren't thread-safe.
    ///
    /// - Workers: 1
    /// - Queue: 1,000 tasks
    pub fn single_threaded(name: impl Into<String>) -> Self {
        Self {
            name_prefix: name.into(),
            worker_count: 1,
            queue_size: 1_000,
        }
    }
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            name_prefix: "worker".into(),
            worker_count: 4,
            queue_size: 1000,
        }
    }
}

// =============================================================================
// Worker Statistics
// =============================================================================

/// Statistics for a worker pool
#[derive(Debug, Clone)]
pub struct WorkerStats {
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

impl WorkerStats {
    /// Check if the pool is idle (no active workers)
    pub fn is_idle(&self) -> bool {
        self.active_workers == 0
    }

    /// Check if the pool is healthy
    pub fn is_healthy(&self) -> bool {
        !self.is_shutdown && self.tasks_rejected == 0
    }
}

/// Internal metrics tracking
struct WorkerMetrics {
    active_count: AtomicUsize,
    tasks_submitted: AtomicU64,
    tasks_completed: AtomicU64,
    tasks_rejected: AtomicU64,
}

impl WorkerMetrics {
    fn new() -> Self {
        Self {
            active_count: AtomicUsize::new(0),
            tasks_submitted: AtomicU64::new(0),
            tasks_completed: AtomicU64::new(0),
            tasks_rejected: AtomicU64::new(0),
        }
    }

    fn increment_active(&self) -> usize {
        self.active_count
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    }

    fn decrement_active(&self) {
        self.active_count.fetch_sub(1, Ordering::Relaxed);
    }

    fn increment_submitted(&self) {
        self.tasks_submitted.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_completed(&self) {
        self.tasks_completed.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_rejected(&self) {
        self.tasks_rejected.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(
        &self,
        config: &WorkerConfig,
        queue_depth: usize,
        is_shutdown: bool,
    ) -> WorkerStats {
        WorkerStats {
            name: config.name_prefix.clone(),
            worker_count: config.worker_count,
            active_workers: self.active_count.load(Ordering::Relaxed),
            queue_capacity: config.queue_size,
            queue_depth,
            tasks_submitted: self.tasks_submitted.load(Ordering::Relaxed),
            tasks_completed: self.tasks_completed.load(Ordering::Relaxed),
            tasks_rejected: self.tasks_rejected.load(Ordering::Relaxed),
            is_shutdown,
        }
    }
}

// =============================================================================
// Task Type
// =============================================================================

/// A task that can be executed by workers
pub type Task = Box<dyn FnOnce() + Send + 'static>;

// =============================================================================
// Worker Pool
// =============================================================================

/// A pool of workers for background task processing
///
/// The worker pool manages a configurable number of workers that pull
/// tasks from a shared queue and execute them concurrently.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::primitives::runtime::worker::{WorkerPool, WorkerConfig};
///
/// let pool = WorkerPool::new(WorkerConfig::default());
///
/// // Submit tasks
/// pool.execute(|| println!("Hello from worker!")).await?;
///
/// // Check stats
/// let stats = pool.stats();
/// println!("Completed: {}", stats.tasks_completed);
///
/// // Graceful shutdown
/// pool.shutdown().await;
/// ```
pub struct WorkerPool {
    sender: mpsc::Sender<Task>,
    workers: Vec<Worker>,
    config: WorkerConfig,
    metrics: Arc<WorkerMetrics>,
    shutdown: Arc<AtomicBool>,
}

/// Individual worker handle
struct Worker {
    id: usize,
    handle: JoinHandle<()>,
}

impl WorkerPool {
    /// Create a new worker pool with the given configuration
    pub fn new(config: WorkerConfig) -> Self {
        let (sender, receiver) = mpsc::channel(config.queue_size);
        let metrics = Arc::new(WorkerMetrics::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        // Create shared receiver for workers
        let receiver = Arc::new(tokio::sync::Mutex::new(receiver));

        // Spawn workers
        let mut workers = Vec::with_capacity(config.worker_count);
        for id in 0..config.worker_count {
            let receiver = Arc::clone(&receiver);
            let metrics = Arc::clone(&metrics);
            let shutdown = Arc::clone(&shutdown);

            let handle = tokio::spawn(async move {
                Self::worker_loop(id, receiver, metrics, shutdown).await;
            });

            workers.push(Worker { id, handle });
        }

        Self {
            sender,
            workers,
            config,
            metrics,
            shutdown,
        }
    }

    /// Create a worker pool with default configuration
    pub fn with_defaults() -> Self {
        Self::new(WorkerConfig::default())
    }

    /// Execute a task in the pool (async, waits for queue space)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Pool is shutting down
    /// - Queue is full and cannot accept the task
    pub async fn execute<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce() + Send + 'static,
    {
        self.metrics.increment_submitted();

        if self.shutdown.load(Ordering::Relaxed) {
            self.metrics.increment_rejected();
            return Err(Problem::Runtime(format!(
                "Worker pool '{}' is shutting down",
                self.config.name_prefix
            )));
        }

        self.sender.send(Box::new(f)).await.map_err(|_| {
            self.metrics.increment_rejected();
            Problem::Runtime(format!(
                "Worker pool '{}' queue full",
                self.config.name_prefix
            ))
        })
    }

    /// Spawn a task without waiting (non-blocking)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Pool is shutting down
    /// - Queue is immediately full
    pub fn spawn<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce() + Send + 'static,
    {
        self.metrics.increment_submitted();

        if self.shutdown.load(Ordering::Relaxed) {
            self.metrics.increment_rejected();
            return Err(Problem::Runtime(format!(
                "Worker pool '{}' is shutting down",
                self.config.name_prefix
            )));
        }

        self.sender.try_send(Box::new(f)).map_err(|_| {
            self.metrics.increment_rejected();
            Problem::Runtime(format!(
                "Worker pool '{}' queue full",
                self.config.name_prefix
            ))
        })
    }

    /// Get the number of currently active workers
    pub fn active_workers(&self) -> usize {
        self.metrics.active_count.load(Ordering::Relaxed)
    }

    /// Get the total worker count
    pub fn worker_count(&self) -> usize {
        self.config.worker_count
    }

    /// Check if the pool is idle (no active workers)
    pub fn is_idle(&self) -> bool {
        self.active_workers() == 0
    }

    /// Check if the pool is shutting down
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Get current pool name
    pub fn name(&self) -> &str {
        &self.config.name_prefix
    }

    /// Get current queue depth (approximate)
    pub fn queue_depth(&self) -> usize {
        self.sender
            .max_capacity()
            .saturating_sub(self.sender.capacity())
    }

    /// Get current statistics
    pub fn stats(&self) -> WorkerStats {
        self.metrics.snapshot(
            &self.config,
            self.queue_depth(),
            self.shutdown.load(Ordering::Relaxed),
        )
    }

    /// Gracefully shutdown the worker pool
    ///
    /// Signals shutdown, closes the queue, and waits for all workers to finish.
    pub async fn shutdown(self) {
        // Signal shutdown
        self.shutdown.store(true, Ordering::Relaxed);

        // Close the channel (drop sender)
        drop(self.sender);

        // Wait for all workers to finish
        for worker in self.workers {
            let _ = worker.handle.await;
        }
    }

    /// Worker loop that processes tasks from the queue
    async fn worker_loop(
        _id: usize,
        receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<Task>>>,
        metrics: Arc<WorkerMetrics>,
        shutdown: Arc<AtomicBool>,
    ) {
        loop {
            // Check for shutdown signal
            if shutdown.load(Ordering::Relaxed) {
                break;
            }

            // Try to get next task
            let task = {
                let mut rx = receiver.lock().await;
                rx.recv().await
            };

            match task {
                Some(task) => {
                    // Mark as active
                    metrics.increment_active();

                    // Execute task
                    task();

                    // Mark as complete and inactive
                    metrics.increment_completed();
                    metrics.decrement_active();
                }
                None => {
                    // Channel closed, exit
                    break;
                }
            }
        }
    }
}

// =============================================================================
// Submit Result
// =============================================================================

/// Outcome of a task submission
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Task was accepted and queued
    Queued,
    /// Task was rejected (queue full)
    QueueFull,
    /// Task was rejected (pool shutting down)
    Shutdown,
}

impl std::fmt::Display for SubmitOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubmitOutcome::Queued => write!(f, "Queued"),
            SubmitOutcome::QueueFull => write!(f, "QueueFull"),
            SubmitOutcome::Shutdown => write!(f, "Shutdown"),
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
    use std::sync::atomic::AtomicU32;

    // =========================================================================
    // WorkerConfig Tests
    // =========================================================================

    #[test]
    fn test_worker_config_new() {
        let config = WorkerConfig::new("test", 4, 100);
        assert_eq!(config.name_prefix, "test");
        assert_eq!(config.worker_count, 4);
        assert_eq!(config.queue_size, 100);
    }

    #[test]
    fn test_worker_config_default() {
        let config = WorkerConfig::default();
        assert_eq!(config.name_prefix, "worker");
        assert_eq!(config.worker_count, 4);
        assert_eq!(config.queue_size, 1000);
    }

    #[test]
    fn test_worker_config_builder() {
        let config = WorkerConfig::default()
            .with_name("custom")
            .with_workers(8)
            .with_queue_size(500);

        assert_eq!(config.name_prefix, "custom");
        assert_eq!(config.worker_count, 8);
        assert_eq!(config.queue_size, 500);
    }

    #[test]
    fn test_worker_config_validate() {
        let valid = WorkerConfig::default();
        assert!(valid.validate().is_ok());

        let zero_workers = WorkerConfig::default().with_workers(0);
        assert!(zero_workers.validate().is_err());

        let zero_queue = WorkerConfig::default().with_queue_size(0);
        assert!(zero_queue.validate().is_err());
    }

    // =========================================================================
    // WorkerPool Tests
    // =========================================================================

    #[tokio::test]
    async fn test_worker_pool_new() {
        let config = WorkerConfig::new("test", 2, 10);
        let pool = WorkerPool::new(config);

        assert_eq!(pool.worker_count(), 2);
        assert_eq!(pool.name(), "test");
        assert!(!pool.is_shutdown());
    }

    #[tokio::test]
    async fn test_worker_pool_execute() {
        let pool = WorkerPool::new(WorkerConfig::new("test", 2, 10));

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        pool.execute(move || {
            counter_clone.fetch_add(1, Ordering::Relaxed);
        })
        .await
        .expect("execute should succeed");

        // Wait for task to complete
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(counter.load(Ordering::Relaxed), 1);
        pool.shutdown().await;
    }

    #[tokio::test]
    async fn test_worker_pool_spawn() {
        let pool = WorkerPool::new(WorkerConfig::new("test", 2, 10));

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        pool.spawn(move || {
            counter_clone.fetch_add(1, Ordering::Relaxed);
        })
        .expect("spawn should succeed");

        // Wait for task to complete
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(counter.load(Ordering::Relaxed), 1);
        pool.shutdown().await;
    }

    #[tokio::test]
    async fn test_worker_pool_multiple_tasks() {
        let pool = WorkerPool::new(WorkerConfig::new("test", 4, 100));

        let counter = Arc::new(AtomicU32::new(0));

        for _ in 0..10 {
            let counter_clone = Arc::clone(&counter);
            pool.spawn(move || {
                counter_clone.fetch_add(1, Ordering::Relaxed);
            })
            .expect("spawn should succeed");
        }

        // Wait for tasks to complete
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        assert_eq!(counter.load(Ordering::Relaxed), 10);
        pool.shutdown().await;
    }

    #[tokio::test]
    async fn test_worker_pool_stats() {
        let pool = WorkerPool::new(WorkerConfig::new("test", 2, 10));

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        pool.execute(move || {
            counter_clone.fetch_add(1, Ordering::Relaxed);
        })
        .await
        .expect("execute should succeed");

        // Wait for task
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stats = pool.stats();
        assert_eq!(stats.name, "test");
        assert_eq!(stats.worker_count, 2);
        assert_eq!(stats.tasks_submitted, 1);
        assert_eq!(stats.tasks_completed, 1);
        assert_eq!(stats.tasks_rejected, 0);
        assert!(!stats.is_shutdown);

        pool.shutdown().await;
    }

    #[tokio::test]
    async fn test_worker_pool_shutdown() {
        let pool = WorkerPool::new(WorkerConfig::new("test", 2, 10));

        assert!(!pool.is_shutdown());

        pool.shutdown().await;
        // After shutdown, pool is consumed
    }

    #[tokio::test]
    async fn test_worker_pool_queue_depth() {
        let pool = WorkerPool::new(WorkerConfig::new("test", 1, 10));

        // Initially empty
        assert_eq!(pool.queue_depth(), 0);

        // Add some tasks
        for _ in 0..5 {
            pool.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(100));
            })
            .expect("spawn should succeed");
        }

        // Queue should have some depth now
        // Note: exact depth depends on timing
        let depth = pool.queue_depth();
        assert!(depth <= 5);

        pool.shutdown().await;
    }

    // =========================================================================
    // WorkerStats Tests
    // =========================================================================

    #[test]
    fn test_worker_stats_is_idle() {
        let stats = WorkerStats {
            name: "test".into(),
            worker_count: 4,
            active_workers: 0,
            queue_capacity: 100,
            queue_depth: 0,
            tasks_submitted: 10,
            tasks_completed: 10,
            tasks_rejected: 0,
            is_shutdown: false,
        };
        assert!(stats.is_idle());

        let active_stats = WorkerStats {
            active_workers: 1,
            ..stats.clone()
        };
        assert!(!active_stats.is_idle());
    }

    #[test]
    fn test_worker_stats_is_healthy() {
        let healthy = WorkerStats {
            name: "test".into(),
            worker_count: 4,
            active_workers: 2,
            queue_capacity: 100,
            queue_depth: 10,
            tasks_submitted: 100,
            tasks_completed: 90,
            tasks_rejected: 0,
            is_shutdown: false,
        };
        assert!(healthy.is_healthy());

        let shutdown = WorkerStats {
            is_shutdown: true,
            ..healthy.clone()
        };
        assert!(!shutdown.is_healthy());

        let rejected = WorkerStats {
            tasks_rejected: 5,
            ..healthy.clone()
        };
        assert!(!rejected.is_healthy());
    }

    // =========================================================================
    // SubmitOutcome Tests
    // =========================================================================

    #[test]
    fn test_submit_outcome_display() {
        assert_eq!(format!("{}", SubmitOutcome::Queued), "Queued");
        assert_eq!(format!("{}", SubmitOutcome::QueueFull), "QueueFull");
        assert_eq!(format!("{}", SubmitOutcome::Shutdown), "Shutdown");
    }

    #[test]
    fn test_preset_cpu_bound() {
        let config = WorkerConfig::cpu_bound("compute");
        assert_eq!(config.name_prefix, "compute");
        assert!(config.worker_count >= 1); // At least 1 CPU
        assert_eq!(config.queue_size, 1_000);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preset_io_bound() {
        let config = WorkerConfig::io_bound("io_workers");
        assert_eq!(config.name_prefix, "io_workers");
        assert!(config.worker_count >= 2); // At least 2x 1 CPU
        assert_eq!(config.queue_size, 10_000);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preset_single_threaded() {
        let config = WorkerConfig::single_threaded("sequential");
        assert_eq!(config.name_prefix, "sequential");
        assert_eq!(config.worker_count, 1);
        assert_eq!(config.queue_size, 1_000);
        assert!(config.validate().is_ok());
    }
}

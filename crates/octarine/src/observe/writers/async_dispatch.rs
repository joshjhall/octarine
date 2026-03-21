//! Async event dispatcher with bounded channels and configurable overflow handling
//!
//! Provides non-blocking event queuing with tokio backend, configurable capacity,
//! and multiple overflow strategies for backpressure handling.
//!
//! # Overflow Strategies
//!
//! - [`OverflowStrategy::DropNewest`]: Drop new events when queue is full (preserve history)
//! - [`OverflowStrategy::RetryThenDrop`]: Retry with jitter, then drop (default, balanced)
//! - [`OverflowStrategy::Block`]: Block caller until space available (for critical events)
//!
//! # Queue Sizing Guide
//!
//! | Use Case | Recommended Capacity | Strategy |
//! |----------|---------------------|----------|
//! | Development | 1,000 | RetryThenDrop |
//! | Production API | 10,000 | RetryThenDrop |
//! | High-volume logging | 50,000 | DropNewest |
//! | Critical audit | 10,000 | Block |
//!
//! # Example
//!
//! ```rust,ignore
//! use octarine::writers::{
//!     configure_dispatcher, DispatcherConfig, OverflowStrategy
//! };
//!
//! // Configure before first event is dispatched
//! configure_dispatcher(DispatcherConfig {
//!     capacity: 50_000,
//!     overflow_strategy: OverflowStrategy::DropNewest,
//!     overflow_callback: Some(Box::new(|count| {
//!         eprintln!("Warning: {} events dropped", count);
//!     })),
//!     ..Default::default()
//! });
//! ```

use crate::observe::types::Event;
use crate::primitives::runtime::r#async::{
    BackoffStrategyCore, BatchProcessor, interval, sleep_ms,
};
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use super::protected::ProtectedWriter;

// =============================================================================
// Configuration Types
// =============================================================================

/// Strategy for handling events when the queue is full
///
/// Choose based on your application's requirements:
/// - For high-volume, low-priority logs: use `DropNewest`
/// - For balanced performance: use `RetryThenDrop` (default)
/// - For critical audit events: use `Block`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverflowStrategy {
    /// Drop new events when queue is full (preserve history)
    ///
    /// Best for: High-volume logging where recent events can be sacrificed
    /// Latency: None (non-blocking)
    DropNewest,

    /// Retry with exponential backoff and jitter, then drop if still full
    ///
    /// Best for: Most applications - balances reliability with performance
    /// Latency: Up to ~100ms in worst case (3 retries with jitter)
    #[default]
    RetryThenDrop,

    /// Block the caller until space is available
    ///
    /// Best for: Critical audit events that must not be lost
    /// Warning: Can cause application slowdown if writers are slow
    /// Latency: Unbounded (waits for queue space)
    Block,
}

/// Callback invoked when events are dropped due to overflow
///
/// The callback receives the number of events dropped in this batch.
/// Use this for alerting or metrics collection.
pub type OverflowCallback = Box<dyn Fn(usize) + Send + Sync>;

/// Configuration for the event dispatcher
///
/// Use [`configure_dispatcher`] to apply configuration before the first event
/// is dispatched. Configuration cannot be changed after the dispatcher starts.
pub struct DispatcherConfig {
    /// Maximum number of events that can be queued
    ///
    /// Default: 10,000
    /// Recommended: 1,000 (dev), 10,000 (prod), 50,000 (high-volume)
    pub capacity: usize,

    /// Strategy for handling overflow when queue is full
    ///
    /// Default: [`OverflowStrategy::RetryThenDrop`]
    pub overflow_strategy: OverflowStrategy,

    /// Optional callback invoked when events are dropped
    ///
    /// Use for alerting or metrics. Called with count of dropped events.
    pub overflow_callback: Option<OverflowCallback>,

    /// Number of retry attempts for RetryThenDrop strategy
    ///
    /// Default: 3
    pub retry_attempts: u32,

    /// Batch size for processing events
    ///
    /// Default: 100
    pub batch_size: usize,

    /// Maximum time to hold events before flushing
    ///
    /// Default: 1 second
    pub flush_interval: Duration,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            capacity: 10_000,
            overflow_strategy: OverflowStrategy::RetryThenDrop,
            overflow_callback: None,
            retry_attempts: 3,
            batch_size: 100,
            flush_interval: Duration::from_secs(1),
        }
    }
}

impl DispatcherConfig {
    /// Create a configuration for development environments
    ///
    /// Uses smaller queue (1,000) with RetryThenDrop strategy.
    #[must_use]
    pub fn development() -> Self {
        Self {
            capacity: 1_000,
            ..Default::default()
        }
    }

    /// Create a configuration for production environments
    ///
    /// Uses default queue (10,000) with RetryThenDrop strategy.
    #[must_use]
    pub fn production() -> Self {
        Self::default()
    }

    /// Create a configuration for high-volume logging
    ///
    /// Uses larger queue (50,000) with DropNewest strategy.
    #[must_use]
    pub fn high_volume() -> Self {
        Self {
            capacity: 50_000,
            overflow_strategy: OverflowStrategy::DropNewest,
            ..Default::default()
        }
    }

    /// Create a configuration for critical audit events
    ///
    /// Uses default queue (10,000) with Block strategy.
    /// Warning: May cause application slowdown.
    #[must_use]
    pub fn critical() -> Self {
        Self {
            overflow_strategy: OverflowStrategy::Block,
            ..Default::default()
        }
    }
}

// =============================================================================
// Enhanced Statistics
// =============================================================================

/// Extended statistics about the event dispatcher
///
/// Provides comprehensive metrics for monitoring queue health.
#[derive(Debug, Clone)]
pub struct DispatcherStats {
    /// Approximate current queue size (may be slightly stale)
    pub current_size: usize,

    /// Maximum queue capacity
    pub capacity: usize,

    /// Total events successfully queued
    pub total_queued: u64,

    /// Total events dropped due to overflow
    pub total_dropped: u64,

    /// Total retry attempts (for RetryThenDrop strategy)
    pub total_retries: u64,

    /// Total events processed by writers
    pub total_processed: u64,

    /// Queue utilization as a percentage (0.0 to 1.0)
    pub utilization: f64,

    /// Drop rate as a percentage (0.0 to 1.0)
    pub drop_rate: f64,

    /// Retry rate as a percentage (0.0 to 1.0)
    pub retry_rate: f64,

    /// Time since dispatcher was initialized
    pub uptime: Duration,

    /// Overflow strategy in use
    pub overflow_strategy: OverflowStrategy,
}

impl DispatcherStats {
    /// Calculate health score (0.0 to 1.0)
    ///
    /// 1.0 = perfectly healthy, 0.0 = severely degraded
    #[must_use]
    pub fn health_score(&self) -> f64 {
        let success_rate = 1.0 - self.drop_rate;
        let retry_penalty = self.retry_rate.min(0.5) * 0.2;
        (success_rate - retry_penalty).max(0.0)
    }

    /// Check if dispatcher is healthy
    ///
    /// Returns true if drop rate is below 5%
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.drop_rate < 0.05
    }

    /// Check if dispatcher is degraded
    ///
    /// Returns true if drop rate exceeds 1% or retry rate exceeds 10%
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.drop_rate > 0.01 || self.retry_rate > 0.10
    }
}

// =============================================================================
// Event Dispatcher Implementation
// =============================================================================

/// Pending configuration (set before dispatcher starts)
static PENDING_CONFIG: RwLock<Option<DispatcherConfig>> = RwLock::new(None);

/// Event dispatcher state
struct EventDispatcher {
    sender: mpsc::Sender<Event>,
    /// Total events queued successfully
    total_queued: AtomicU64,
    /// Total events dropped due to backpressure
    total_dropped: AtomicU64,
    /// Total retry attempts
    total_retries: AtomicU64,
    /// Total events processed (shared with background thread)
    total_processed: Arc<AtomicU64>,
    /// Approximate current queue size (shared with background thread)
    approx_queue_size: Arc<AtomicUsize>,
    /// Channel capacity
    capacity: usize,
    /// Overflow strategy
    overflow_strategy: OverflowStrategy,
    /// Retry attempts for RetryThenDrop
    retry_attempts: u32,
    /// Backoff strategy for retries
    backoff: BackoffStrategyCore,
    /// Overflow callback
    overflow_callback: Mutex<Option<OverflowCallback>>,
    /// Dispatcher start time
    started_at: Instant,
}

/// Global event dispatcher (lazily initialized)
static EVENT_DISPATCHER: Lazy<Arc<EventDispatcher>> =
    Lazy::new(|| Arc::new(EventDispatcher::new()));

impl EventDispatcher {
    /// Create and initialize the event dispatcher
    fn new() -> Self {
        // Get pending configuration or use default
        let config = PENDING_CONFIG
            .write()
            .ok()
            .and_then(|mut guard| guard.take())
            .unwrap_or_default();

        let capacity = config.capacity;
        let overflow_strategy = config.overflow_strategy;
        let retry_attempts = config.retry_attempts;
        let batch_size = config.batch_size;
        let flush_interval = config.flush_interval;

        // Create tokio channel with configured capacity
        let (tx, mut rx) = mpsc::channel::<Event>(capacity);

        // Create counter for processed events (shared with background thread)
        let processed_counter = Arc::new(AtomicU64::new(0));
        let processed_clone = Arc::clone(&processed_counter);

        // Create queue size tracker (shared with background thread)
        let queue_size = Arc::new(AtomicUsize::new(0));
        let queue_size_clone = Arc::clone(&queue_size);

        // Spawn background thread with tokio runtime
        std::thread::spawn(move || {
            // Create tokio runtime for this thread
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => {
                    // Runtime creation failed - fall back to blocking receive
                    let writer = ProtectedWriter::new();
                    while let Some(event) = rx.blocking_recv() {
                        queue_size_clone.fetch_sub(1, Ordering::Relaxed);
                        writer.write_sync(&event);
                        processed_clone.fetch_add(1, Ordering::Relaxed);
                    }
                    return;
                }
            };

            // Run event processing loop with batching
            runtime.block_on(async move {
                let writer = ProtectedWriter::new();
                let mut batch = BatchProcessor::new(batch_size, flush_interval);
                let mut flush_timer = interval(flush_interval);

                loop {
                    tokio::select! {
                        Some(event) = rx.recv() => {
                            queue_size_clone.fetch_sub(1, Ordering::Relaxed);
                            if batch.add(event) {
                                let events = batch.take();
                                let count = events.len();
                                for event in events {
                                    writer.write_sync(&event);
                                }
                                processed_clone.fetch_add(count as u64, Ordering::Relaxed);
                            }
                        }

                        _ = flush_timer.tick() => {
                            if !batch.is_empty() {
                                let events = batch.take();
                                let count = events.len();
                                for event in events {
                                    writer.write_sync(&event);
                                }
                                processed_clone.fetch_add(count as u64, Ordering::Relaxed);
                            }
                        }
                    }
                }
            });
        });

        Self {
            sender: tx,
            total_queued: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
            total_retries: AtomicU64::new(0),
            total_processed: processed_counter,
            approx_queue_size: queue_size,
            capacity,
            overflow_strategy,
            retry_attempts,
            backoff: BackoffStrategyCore::DecorrelatedJitter {
                base: Duration::from_millis(1),
                max: Duration::from_millis(100),
            },
            overflow_callback: Mutex::new(config.overflow_callback),
            started_at: Instant::now(),
        }
    }

    /// Queue an event using the configured overflow strategy
    fn queue(&self, event: Event) {
        match self.overflow_strategy {
            OverflowStrategy::DropNewest => self.queue_drop_newest(event),
            OverflowStrategy::RetryThenDrop => self.queue_retry_then_drop(event),
            OverflowStrategy::Block => self.queue_blocking(event),
        }
    }

    /// Queue with DropNewest strategy - immediately drop if full
    fn queue_drop_newest(&self, event: Event) {
        match self.sender.try_send(event) {
            Ok(()) => {
                self.total_queued.fetch_add(1, Ordering::Relaxed);
                self.approx_queue_size.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.total_dropped.fetch_add(1, Ordering::Relaxed);
                self.notify_overflow(1);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.total_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Queue with RetryThenDrop strategy - retry with jitter, then drop
    fn queue_retry_then_drop(&self, event: Event) {
        match self.sender.try_send(event) {
            Ok(()) => {
                self.total_queued.fetch_add(1, Ordering::Relaxed);
                self.approx_queue_size.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(mut evt)) => {
                for attempt in 0..self.retry_attempts {
                    self.total_retries.fetch_add(1, Ordering::Relaxed);

                    let delay = self.backoff.delay(attempt);
                    std::thread::sleep(delay);

                    match self.sender.try_send(evt) {
                        Ok(()) => {
                            self.total_queued.fetch_add(1, Ordering::Relaxed);
                            self.approx_queue_size.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        Err(mpsc::error::TrySendError::Full(e)) => {
                            evt = e;
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            self.total_dropped.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    }
                }

                self.total_dropped.fetch_add(1, Ordering::Relaxed);
                self.notify_overflow(1);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.total_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Queue with Block strategy - wait until space available
    fn queue_blocking(&self, event: Event) {
        // First try non-blocking
        match self.sender.try_send(event) {
            Ok(()) => {
                self.total_queued.fetch_add(1, Ordering::Relaxed);
                self.approx_queue_size.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(evt)) => {
                // Block until we can send
                match self.sender.blocking_send(evt) {
                    Ok(()) => {
                        self.total_queued.fetch_add(1, Ordering::Relaxed);
                        self.approx_queue_size.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        // Channel closed
                        self.total_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.total_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Queue an event with async retry (for use within async context)
    #[allow(dead_code)]
    async fn queue_async(&self, event: Event) {
        match self.overflow_strategy {
            OverflowStrategy::DropNewest => self.queue_drop_newest(event),
            OverflowStrategy::RetryThenDrop => self.queue_retry_then_drop_async(event).await,
            OverflowStrategy::Block => self.queue_blocking_async(event).await,
        }
    }

    /// Async version of retry-then-drop
    async fn queue_retry_then_drop_async(&self, event: Event) {
        match self.sender.try_send(event) {
            Ok(()) => {
                self.total_queued.fetch_add(1, Ordering::Relaxed);
                self.approx_queue_size.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(mut evt)) => {
                for attempt in 0..self.retry_attempts {
                    self.total_retries.fetch_add(1, Ordering::Relaxed);

                    let delay = self.backoff.delay(attempt);
                    sleep_ms(delay.as_millis() as u64).await;

                    match self.sender.try_send(evt) {
                        Ok(()) => {
                            self.total_queued.fetch_add(1, Ordering::Relaxed);
                            self.approx_queue_size.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        Err(mpsc::error::TrySendError::Full(e)) => {
                            evt = e;
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            self.total_dropped.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    }
                }

                self.total_dropped.fetch_add(1, Ordering::Relaxed);
                self.notify_overflow(1);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.total_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Async version of blocking send
    async fn queue_blocking_async(&self, event: Event) {
        match self.sender.send(event).await {
            Ok(()) => {
                self.total_queued.fetch_add(1, Ordering::Relaxed);
                self.approx_queue_size.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.total_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Notify overflow callback
    fn notify_overflow(&self, count: usize) {
        if let Ok(guard) = self.overflow_callback.lock()
            && let Some(ref callback) = *guard
        {
            callback(count);
        }
    }

    /// Get extended statistics
    fn stats(&self) -> DispatcherStats {
        let total_queued = self.total_queued.load(Ordering::Relaxed);
        let total_dropped = self.total_dropped.load(Ordering::Relaxed);
        let total_retries = self.total_retries.load(Ordering::Relaxed);
        let total_processed = self.total_processed.load(Ordering::Relaxed);
        let current_size = self.approx_queue_size.load(Ordering::Relaxed);

        let total_attempted = total_queued.saturating_add(total_dropped);

        let drop_rate = if total_attempted > 0 {
            total_dropped as f64 / total_attempted as f64
        } else {
            0.0
        };

        let retry_rate = if total_attempted > 0 {
            total_retries as f64 / total_attempted as f64
        } else {
            0.0
        };

        // Clamp to [0.0, 1.0] since approx_queue_size can briefly exceed capacity due to race conditions
        let utilization = (current_size as f64 / self.capacity as f64).min(1.0);

        DispatcherStats {
            current_size,
            capacity: self.capacity,
            total_queued,
            total_dropped,
            total_retries,
            total_processed,
            utilization,
            drop_rate,
            retry_rate,
            uptime: self.started_at.elapsed(),
            overflow_strategy: self.overflow_strategy,
        }
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Configure the event dispatcher before it starts
///
/// **Important**: Must be called before any events are dispatched.
/// Configuration is locked once the dispatcher initializes.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::writers::{configure_dispatcher, DispatcherConfig, OverflowStrategy};
///
/// // Call early in main() before any logging
/// configure_dispatcher(DispatcherConfig {
///     capacity: 50_000,
///     overflow_strategy: OverflowStrategy::DropNewest,
///     overflow_callback: Some(Box::new(|count| {
///         eprintln!("Warning: {} events dropped due to queue overflow", count);
///     })),
///     ..Default::default()
/// });
/// ```
///
/// # Returns
///
/// `true` if configuration was accepted, `false` if dispatcher already started.
pub fn configure_dispatcher(config: DispatcherConfig) -> bool {
    // Check if dispatcher is already initialized
    if Lazy::get(&EVENT_DISPATCHER).is_some() {
        return false;
    }

    // Store configuration for when dispatcher starts
    if let Ok(mut guard) = PENDING_CONFIG.write() {
        *guard = Some(config);
        true
    } else {
        false
    }
}

/// Queue an event for async dispatch (non-blocking, synchronous API)
///
/// This function returns immediately. Events are queued to a bounded channel
/// and processed asynchronously in the background.
///
/// Overflow behavior depends on the configured [`OverflowStrategy`]:
/// - `DropNewest`: Returns immediately, may drop the event
/// - `RetryThenDrop`: May block briefly during retries (~100ms max)
/// - `Block`: May block indefinitely until queue space is available
pub(super) fn queue_event(event: Event) {
    EVENT_DISPATCHER.queue(event);
}

/// Get extended statistics about the event dispatcher
///
/// Returns comprehensive statistics including queue size, drop rate,
/// utilization, and health indicators.
pub fn dispatcher_stats_extended() -> DispatcherStats {
    EVENT_DISPATCHER.stats()
}

/// Get basic statistics about the event dispatcher
///
/// Returns statistics including total events queued and dropped.
/// For extended statistics, use [`dispatcher_stats_extended`].
pub fn dispatcher_stats() -> crate::primitives::collections::BufferStats {
    let stats = EVENT_DISPATCHER.stats();
    crate::primitives::collections::BufferStats {
        current_size: stats.current_size,
        capacity: stats.capacity,
        total_written: stats.total_queued as usize,
        total_dropped: stats.total_dropped as usize,
    }
}

/// Check if the event dispatcher is healthy
///
/// Returns true if the drop rate is below the 5% threshold.
pub fn dispatcher_is_healthy() -> bool {
    EVENT_DISPATCHER.stats().is_healthy()
}

/// Check if the event dispatcher is degraded
///
/// Returns true if the drop rate exceeds 1% or retry rate exceeds 10%.
pub fn dispatcher_is_degraded() -> bool {
    EVENT_DISPATCHER.stats().is_degraded()
}

/// Get the event dispatcher health score
///
/// Returns a value from 0.0 (completely degraded) to 1.0 (perfectly healthy).
pub fn dispatcher_health_score() -> f64 {
    EVENT_DISPATCHER.stats().health_score()
}

/// Get the current overflow strategy
pub fn dispatcher_overflow_strategy() -> OverflowStrategy {
    EVENT_DISPATCHER.overflow_strategy
}

/// Get the dispatcher capacity
pub fn dispatcher_capacity() -> usize {
    EVENT_DISPATCHER.capacity
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::observe::types::{Event, EventType};

    #[tokio::test]
    async fn test_event_queuing() {
        let event = Event::new(EventType::Debug, "test event");
        queue_event(event);

        // Give time for async processing
        crate::primitives::runtime::r#async::sleep_ms(10).await;
    }

    #[test]
    fn test_dispatcher_stats() {
        let stats = dispatcher_stats_extended();

        assert!(stats.capacity > 0);
        assert!(stats.utilization >= 0.0);
        assert!(stats.utilization <= 1.0);
        assert!(stats.drop_rate >= 0.0);
        assert!(stats.drop_rate <= 1.0);
    }

    #[test]
    fn test_overflow_strategy_default() {
        assert_eq!(OverflowStrategy::default(), OverflowStrategy::RetryThenDrop);
    }

    #[test]
    fn test_dispatcher_config_presets() {
        let dev = DispatcherConfig::development();
        assert_eq!(dev.capacity, 1_000);

        let prod = DispatcherConfig::production();
        assert_eq!(prod.capacity, 10_000);

        let high = DispatcherConfig::high_volume();
        assert_eq!(high.capacity, 50_000);
        assert_eq!(high.overflow_strategy, OverflowStrategy::DropNewest);

        let critical = DispatcherConfig::critical();
        assert_eq!(critical.overflow_strategy, OverflowStrategy::Block);
    }

    #[test]
    fn test_stats_health_indicators() {
        let stats = DispatcherStats {
            current_size: 0,
            capacity: 10_000,
            total_queued: 1000,
            total_dropped: 0,
            total_retries: 0,
            total_processed: 1000,
            utilization: 0.0,
            drop_rate: 0.0,
            retry_rate: 0.0,
            uptime: Duration::from_secs(60),
            overflow_strategy: OverflowStrategy::RetryThenDrop,
        };

        assert!(stats.is_healthy());
        assert!(!stats.is_degraded());
        assert!((stats.health_score() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_stats_degraded() {
        let stats = DispatcherStats {
            current_size: 5000,
            capacity: 10_000,
            total_queued: 900,
            total_dropped: 100,
            total_retries: 50,
            total_processed: 900,
            utilization: 0.5,
            drop_rate: 0.1, // 10% drop rate
            retry_rate: 0.05,
            uptime: Duration::from_secs(60),
            overflow_strategy: OverflowStrategy::RetryThenDrop,
        };

        assert!(!stats.is_healthy());
        assert!(stats.is_degraded());
        assert!(stats.health_score() < 1.0);
    }
}

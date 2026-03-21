//! Batch processor with observability
//!
//! Provides efficient batching for items with size/time thresholds
//! and comprehensive logging and metrics.

// Allow arithmetic operations - counters are bounded and safe
#![allow(clippy::arithmetic_side_effects)]

use crate::observe;
use crate::primitives::runtime::r#async::BatchProcessor as PrimitiveBatch;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Global batch statistics
static BATCH_STATS: BatchStats = BatchStats::new();

struct BatchStats {
    total_items: AtomicU64,
    total_batches: AtomicU64,
    total_flushes_size: AtomicU64,
    total_flushes_time: AtomicU64,
}

impl BatchStats {
    const fn new() -> Self {
        Self {
            total_items: AtomicU64::new(0),
            total_batches: AtomicU64::new(0),
            total_flushes_size: AtomicU64::new(0),
            total_flushes_time: AtomicU64::new(0),
        }
    }
}

/// Result of adding an item to a batch
#[derive(Debug)]
pub struct BatchResult {
    /// Whether the batch should be flushed
    should_flush: bool,
    /// Reason for flush (if applicable)
    flush_reason: Option<FlushReason>,
}

impl BatchResult {
    /// Check if the batch should be flushed
    pub fn should_flush(&self) -> bool {
        self.should_flush
    }

    /// Get the reason for flushing
    pub fn flush_reason(&self) -> Option<&FlushReason> {
        self.flush_reason.as_ref()
    }
}

/// Reason why a batch should be flushed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushReason {
    /// Batch reached size limit
    SizeLimit,
    /// Batch reached time limit
    TimeLimit,
    /// Manual flush requested
    Manual,
}

/// Statistics about batch operations
#[derive(Debug, Clone)]
pub struct BatchStatistics {
    /// Total items processed
    pub total_items: u64,
    /// Total batches flushed
    pub total_batches: u64,
    /// Flushes due to size limit
    pub total_flushes_size: u64,
    /// Flushes due to time limit
    pub total_flushes_time: u64,
    /// Average batch size
    pub avg_batch_size: f64,
}

/// Batch processor with observability
///
/// Collects items and determines when to flush based on size and time thresholds.
/// Provides comprehensive logging for batch operations.
pub struct BatchProcessor<T> {
    name: String,
    inner: PrimitiveBatch<T>,
    max_size: usize,
    items_added: u64,
    batches_flushed: u64,
}

impl<T> BatchProcessor<T> {
    /// Create a new batch processor
    ///
    /// # Arguments
    ///
    /// * `name` - Name for logging and metrics
    /// * `max_size` - Maximum items before automatic flush
    /// * `max_age` - Maximum time to hold items
    pub fn new(name: &str, max_size: usize, max_age: Duration) -> Self {
        observe::debug(
            "batch_processor_created",
            format!(
                "Batch processor '{}' created (size: {}, age: {:?})",
                name, max_size, max_age
            ),
        );

        Self {
            name: name.to_string(),
            inner: PrimitiveBatch::new(max_size, max_age),
            max_size,
            items_added: 0,
            batches_flushed: 0,
        }
    }

    /// Add an item to the batch
    ///
    /// Returns information about whether the batch should be flushed.
    pub fn add(&mut self, item: T) -> BatchResult {
        BATCH_STATS.total_items.fetch_add(1, Ordering::Relaxed);
        self.items_added += 1;

        let was_empty = self.inner.is_empty();
        let should_flush = self.inner.add(item);

        if was_empty {
            observe::trace(
                "batch_started",
                format!("Batch '{}' started collecting items", self.name),
            );
        }

        let flush_reason = if should_flush {
            let reason = if self.inner.len() >= self.max_size {
                FlushReason::SizeLimit
            } else {
                FlushReason::TimeLimit
            };

            observe::debug(
                "batch_flush_triggered",
                format!(
                    "Batch '{}' flush triggered: {:?} (size: {})",
                    self.name,
                    reason,
                    self.inner.len()
                ),
            );

            Some(reason)
        } else {
            None
        };

        BatchResult {
            should_flush,
            flush_reason,
        }
    }

    /// Take all items and reset the batch
    ///
    /// Returns the collected items and logs the flush.
    pub fn take(&mut self) -> Vec<T> {
        let items = self.inner.take();
        let count = items.len();

        if count > 0 {
            BATCH_STATS.total_batches.fetch_add(1, Ordering::Relaxed);
            self.batches_flushed += 1;

            observe::debug(
                "batch_flushed",
                format!(
                    "Batch '{}' flushed {} items (total batches: {})",
                    self.name, count, self.batches_flushed
                ),
            );
        }

        items
    }

    /// Poll for time-based flush requirement
    ///
    /// Call this periodically to ensure time-based flushes occur.
    pub fn poll_flush(&self) -> BatchResult {
        let should_flush = self.inner.should_flush();

        let flush_reason = if should_flush && self.inner.len() < self.max_size {
            BATCH_STATS
                .total_flushes_time
                .fetch_add(1, Ordering::Relaxed);
            Some(FlushReason::TimeLimit)
        } else if should_flush {
            BATCH_STATS
                .total_flushes_size
                .fetch_add(1, Ordering::Relaxed);
            Some(FlushReason::SizeLimit)
        } else {
            None
        };

        BatchResult {
            should_flush,
            flush_reason,
        }
    }

    /// Get current number of items in the batch
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get remaining capacity
    pub fn remaining_capacity(&self) -> usize {
        self.inner.remaining_capacity()
    }

    /// Get elapsed time since last flush
    pub fn elapsed(&self) -> Duration {
        self.inner.elapsed()
    }

    /// Clear the batch without returning items
    pub fn clear(&mut self) {
        let count = self.inner.len();
        self.inner.clear();

        if count > 0 {
            observe::debug(
                "batch_cleared",
                format!("Batch '{}' cleared {} items", self.name, count),
            );
        }
    }

    /// Get statistics for this batch processor
    pub fn stats(&self) -> BatchProcessorStats {
        BatchProcessorStats {
            name: self.name.clone(),
            items_added: self.items_added,
            batches_flushed: self.batches_flushed,
            current_size: self.inner.len(),
            avg_batch_size: if self.batches_flushed > 0 {
                self.items_added as f64 / self.batches_flushed as f64
            } else {
                0.0
            },
        }
    }
}

/// Statistics for a specific batch processor
#[derive(Debug, Clone)]
pub struct BatchProcessorStats {
    /// Processor name
    pub name: String,
    /// Total items added
    pub items_added: u64,
    /// Total batches flushed
    pub batches_flushed: u64,
    /// Current items in batch
    pub current_size: usize,
    /// Average batch size
    pub avg_batch_size: f64,
}

/// Get global batch statistics
pub fn batch_stats() -> BatchStatistics {
    let total_items = BATCH_STATS.total_items.load(Ordering::Relaxed);
    let total_batches = BATCH_STATS.total_batches.load(Ordering::Relaxed);
    let total_flushes_size = BATCH_STATS.total_flushes_size.load(Ordering::Relaxed);
    let total_flushes_time = BATCH_STATS.total_flushes_time.load(Ordering::Relaxed);

    let avg_batch_size = if total_batches > 0 {
        total_items as f64 / total_batches as f64
    } else {
        0.0
    };

    BatchStatistics {
        total_items,
        total_batches,
        total_flushes_size,
        total_flushes_time,
        avg_batch_size,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_batch_processor_basic() {
        let mut batch = BatchProcessor::new("test", 3, Duration::from_secs(60));

        assert!(!batch.add(1).should_flush());
        assert!(!batch.add(2).should_flush());
        assert!(batch.add(3).should_flush()); // Should trigger flush

        let items = batch.take();
        assert_eq!(items, vec![1, 2, 3]);
        assert!(batch.is_empty());
    }

    #[test]
    fn test_batch_processor_flush_reason() {
        let mut batch = BatchProcessor::new("test", 2, Duration::from_secs(60));

        batch.add(1);
        let result = batch.add(2);

        assert!(result.should_flush());
        assert_eq!(result.flush_reason(), Some(&FlushReason::SizeLimit));
    }

    #[test]
    #[ignore = "timing-sensitive test - run manually with: cargo test -p octarine test_batch_processor_time_flush -- --ignored"]
    fn test_batch_processor_time_flush() {
        let mut batch = BatchProcessor::new("test", 100, Duration::from_millis(50));

        batch.add("item");
        assert!(!batch.poll_flush().should_flush());

        std::thread::sleep(Duration::from_millis(60));
        let result = batch.poll_flush();
        assert!(result.should_flush());
        assert_eq!(result.flush_reason(), Some(&FlushReason::TimeLimit));
    }

    #[test]
    fn test_batch_processor_stats() {
        let mut batch = BatchProcessor::new("stats_test", 2, Duration::from_secs(60));

        batch.add(1);
        batch.add(2);
        batch.take();

        let stats = batch.stats();
        assert_eq!(stats.items_added, 2);
        assert_eq!(stats.batches_flushed, 1);
        assert_eq!(stats.avg_batch_size, 2.0);
    }

    #[test]
    fn test_batch_processor_clear() {
        let mut batch = BatchProcessor::new("clear_test", 10, Duration::from_secs(60));

        batch.add(1);
        batch.add(2);
        assert_eq!(batch.len(), 2);

        batch.clear();
        assert!(batch.is_empty());
    }

    #[test]
    fn test_global_stats() {
        let stats = batch_stats();
        // Just verify it doesn't panic
        assert!(stats.avg_batch_size >= 0.0);
    }
}

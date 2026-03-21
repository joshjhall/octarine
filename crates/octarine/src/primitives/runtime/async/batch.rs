//! Batch processor for efficient event/metric processing
//!
//! Provides batching functionality for collecting items and flushing them
//! based on size or time thresholds.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::BatchProcessor;
//! use std::time::Duration;
//!
//! // Create a batch that flushes after 100 items or 1 second
//! let mut batch = BatchProcessor::new(100, Duration::from_secs(1));
//!
//! // Add items - returns true when batch should be flushed
//! if batch.add(event) {
//!     let items = batch.take();
//!     process_batch(items);
//! }
//! ```

use std::time::{Duration, Instant};

/// Batch processor for efficient writes
///
/// Collects items and determines when they should be flushed based on:
/// - Maximum batch size (flush when full)
/// - Maximum age (flush after time limit)
///
/// This is a primitive with no observe dependencies.
pub struct BatchProcessor<T> {
    items: Vec<T>,
    max_size: usize,
    max_age: Duration,
    last_flush: Instant,
}

impl<T> BatchProcessor<T> {
    /// Create a new batch processor
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum number of items before automatic flush
    /// * `max_age` - Maximum time to hold items before flush
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::BatchProcessor;
    /// use std::time::Duration;
    ///
    /// let batch = BatchProcessor::<String>::new(100, Duration::from_secs(1));
    /// ```
    pub fn new(max_size: usize, max_age: Duration) -> Self {
        Self {
            items: Vec::with_capacity(max_size),
            max_size,
            max_age,
            last_flush: Instant::now(),
        }
    }

    /// Add an item to the batch
    ///
    /// Returns `true` if the batch should be flushed (size or age threshold met).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut batch = BatchProcessor::new(3, Duration::from_secs(60));
    ///
    /// assert!(!batch.add("first"));
    /// assert!(!batch.add("second"));
    /// assert!(batch.add("third")); // Returns true - batch is full
    /// ```
    pub fn add(&mut self, item: T) -> bool {
        self.items.push(item);
        self.should_flush()
    }

    /// Check if batch should be flushed
    ///
    /// Returns true if:
    /// - Batch size >= max_size
    /// - Time since last flush >= max_age
    pub fn should_flush(&self) -> bool {
        self.items.len() >= self.max_size || self.last_flush.elapsed() >= self.max_age
    }

    /// Take all items and reset the batch
    ///
    /// Returns the collected items and resets the flush timer.
    pub fn take(&mut self) -> Vec<T> {
        self.last_flush = Instant::now();
        std::mem::take(&mut self.items)
    }

    /// Get the current number of items in the batch
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Get remaining capacity before flush
    pub fn remaining_capacity(&self) -> usize {
        self.max_size.saturating_sub(self.items.len())
    }

    /// Get elapsed time since last flush
    pub fn elapsed(&self) -> Duration {
        self.last_flush.elapsed()
    }

    /// Clear the batch without returning items
    pub fn clear(&mut self) {
        self.items.clear();
        self.last_flush = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_batch_processor_basic() {
        let mut batch = BatchProcessor::new(3, Duration::from_secs(60));

        assert!(!batch.add(1));
        assert!(!batch.add(2));
        assert!(batch.add(3)); // Should trigger flush

        let items = batch.take();
        assert_eq!(items, vec![1, 2, 3]);
        assert_eq!(batch.len(), 0);
    }

    #[test]
    fn test_batch_processor_age() {
        let mut batch = BatchProcessor::new(10, Duration::from_millis(50));

        batch.add("test");
        assert!(!batch.should_flush());

        std::thread::sleep(Duration::from_millis(60));
        assert!(batch.should_flush());
    }

    #[test]
    fn test_batch_processor_is_empty() {
        let mut batch = BatchProcessor::<i32>::new(10, Duration::from_secs(60));
        assert!(batch.is_empty());

        batch.add(1);
        assert!(!batch.is_empty());

        batch.take();
        assert!(batch.is_empty());
    }

    #[test]
    fn test_batch_processor_remaining_capacity() {
        let mut batch = BatchProcessor::new(5, Duration::from_secs(60));
        assert_eq!(batch.remaining_capacity(), 5);

        batch.add(1);
        batch.add(2);
        assert_eq!(batch.remaining_capacity(), 3);

        batch.take();
        assert_eq!(batch.remaining_capacity(), 5);
    }

    #[test]
    fn test_batch_processor_clear() {
        let mut batch = BatchProcessor::new(10, Duration::from_secs(60));
        batch.add(1);
        batch.add(2);

        batch.clear();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
    }

    #[test]
    fn test_batch_processor_elapsed() {
        let batch = BatchProcessor::<i32>::new(10, Duration::from_secs(60));
        std::thread::sleep(Duration::from_millis(10));
        assert!(batch.elapsed().as_millis() >= 10);
    }

    #[test]
    fn test_batch_processor_zero_max_size() {
        // Edge case: max_size of 0 means always flush immediately
        let mut batch = BatchProcessor::new(0, Duration::from_secs(60));
        assert!(batch.add(1)); // Should trigger flush immediately
    }

    #[test]
    fn test_batch_processor_zero_max_age() {
        // Edge case: max_age of 0 means always flush immediately
        let mut batch = BatchProcessor::new(1000, Duration::ZERO);
        batch.add(1);
        assert!(batch.should_flush()); // Should always be ready to flush
    }

    #[test]
    fn test_batch_processor_take_resets_timer() {
        let mut batch = BatchProcessor::new(10, Duration::from_millis(50));
        batch.add(1);

        // Wait for age threshold
        std::thread::sleep(Duration::from_millis(60));
        assert!(batch.should_flush());

        // Take items - should reset timer
        let _ = batch.take();
        assert!(!batch.should_flush()); // Timer reset, not yet elapsed
    }

    #[test]
    fn test_batch_processor_multiple_flushes() {
        let mut batch = BatchProcessor::new(2, Duration::from_secs(60));

        // First batch
        batch.add(1);
        assert!(batch.add(2));
        let items = batch.take();
        assert_eq!(items, vec![1, 2]);

        // Second batch
        batch.add(3);
        assert!(batch.add(4));
        let items = batch.take();
        assert_eq!(items, vec![3, 4]);
    }

    #[test]
    fn test_batch_processor_len() {
        let mut batch = BatchProcessor::new(10, Duration::from_secs(60));
        assert_eq!(batch.len(), 0);

        batch.add("a");
        assert_eq!(batch.len(), 1);

        batch.add("b");
        batch.add("c");
        assert_eq!(batch.len(), 3);
    }

    #[test]
    fn test_batch_processor_with_structs() {
        #[derive(Debug, PartialEq)]
        struct Event {
            id: u32,
        }

        let mut batch = BatchProcessor::new(2, Duration::from_secs(60));
        batch.add(Event { id: 1 });
        assert!(batch.add(Event { id: 2 }));

        let items = batch.take();
        assert_eq!(items, vec![Event { id: 1 }, Event { id: 2 }]);
    }
}

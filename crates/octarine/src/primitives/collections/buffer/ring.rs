//! Thread-safe ring buffer implementation
//!
//! A fixed-size circular buffer that automatically overwrites the oldest
//! entries when full, preventing unbounded memory growth.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use super::error::BufferError;
use super::stats::BufferStats;

/// A thread-safe ring buffer with fixed capacity
///
/// Automatically overwrites the oldest items when full, providing bounded memory
/// usage with automatic overflow handling. Perfect for event queues, log buffers,
/// and other scenarios where you need FIFO semantics with a size limit.
///
/// # Thread Safety
///
/// Uses `Arc<RwLock<>>` internally, allowing cheap cloning and safe concurrent access.
/// Multiple threads can push/pop simultaneously.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::collections::buffer::RingBuffer;
///
/// let buffer = RingBuffer::new(100);
///
/// // Thread-safe: can clone and share
/// let buffer_clone = buffer.clone();
///
/// buffer.push("event 1").unwrap();
/// buffer_clone.push("event 2").unwrap();
///
/// assert_eq!(buffer.len().unwrap(), 2);
/// ```
#[derive(Clone)]
#[allow(dead_code)] // Used by higher layers
pub struct RingBuffer<T: Clone> {
    inner: Arc<RwLock<RingBufferInner<T>>>,
    capacity: usize,
}

#[allow(dead_code)] // Used by higher layers
struct RingBufferInner<T> {
    data: VecDeque<T>,
    total_written: usize,
    total_dropped: usize,
}

#[allow(dead_code)] // Used by higher layers
impl<T: Clone> RingBuffer<T> {
    /// Create a new ring buffer with specified capacity
    ///
    /// # Panics
    ///
    /// Panics if capacity is 0.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::collections::buffer::RingBuffer;
    ///
    /// let buffer: RingBuffer<String> = RingBuffer::new(100);
    /// assert_eq!(buffer.len().unwrap(), 0);
    /// ```
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "Buffer capacity must be greater than 0");

        Self {
            inner: Arc::new(RwLock::new(RingBufferInner {
                data: VecDeque::with_capacity(capacity),
                total_written: 0,
                total_dropped: 0,
            })),
            capacity,
        }
    }

    /// Push an item into the buffer
    ///
    /// If the buffer is full, the oldest item is automatically dropped to make room.
    /// This ensures the buffer never grows beyond its capacity.
    ///
    /// # Errors
    ///
    /// Returns `BufferError::LockPoisoned` if the lock is poisoned (rare).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::collections::buffer::RingBuffer;
    ///
    /// let buffer = RingBuffer::new(2);
    ///
    /// buffer.push(1).unwrap();
    /// buffer.push(2).unwrap();
    /// buffer.push(3).unwrap();  // Drops oldest (1)
    ///
    /// assert_eq!(buffer.pop().unwrap(), Some(2));
    /// ```
    pub fn push(&self, item: T) -> Result<(), BufferError> {
        let mut inner = self.inner.write().map_err(|_| BufferError::LockPoisoned)?;

        if inner.data.len() >= self.capacity {
            // Buffer full, drop oldest
            inner.data.pop_front();
            inner.total_dropped = inner.total_dropped.saturating_add(1);
        }

        inner.data.push_back(item);
        inner.total_written = inner.total_written.saturating_add(1);

        Ok(())
    }

    /// Pop the oldest item from the buffer
    pub fn pop(&self) -> Result<Option<T>, BufferError> {
        let mut inner = self.inner.write().map_err(|_| BufferError::LockPoisoned)?;

        Ok(inner.data.pop_front())
    }

    /// Get the current size of the buffer
    pub fn len(&self) -> Result<usize, BufferError> {
        let inner = self.inner.read().map_err(|_| BufferError::LockPoisoned)?;

        Ok(inner.data.len())
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> Result<bool, BufferError> {
        let inner = self.inner.read().map_err(|_| BufferError::LockPoisoned)?;

        Ok(inner.data.is_empty())
    }

    /// Check if the buffer is full
    pub fn is_full(&self) -> Result<bool, BufferError> {
        let inner = self.inner.read().map_err(|_| BufferError::LockPoisoned)?;

        Ok(inner.data.len() >= self.capacity)
    }

    /// Clear the buffer
    pub fn clear(&self) -> Result<(), BufferError> {
        let mut inner = self.inner.write().map_err(|_| BufferError::LockPoisoned)?;

        inner.data.clear();
        Ok(())
    }

    /// Get a snapshot of all items in the buffer
    pub fn snapshot(&self) -> Result<Vec<T>, BufferError> {
        let inner = self.inner.read().map_err(|_| BufferError::LockPoisoned)?;

        Ok(inner.data.iter().cloned().collect())
    }

    /// Get buffer statistics
    pub fn stats(&self) -> Result<BufferStats, BufferError> {
        let inner = self.inner.read().map_err(|_| BufferError::LockPoisoned)?;

        Ok(BufferStats {
            current_size: inner.data.len(),
            capacity: self.capacity,
            total_written: inner.total_written,
            total_dropped: inner.total_dropped,
        })
    }

    /// Drain up to n items from the buffer
    pub fn drain(&self, n: usize) -> Result<Vec<T>, BufferError> {
        let mut inner = self.inner.write().map_err(|_| BufferError::LockPoisoned)?;

        let drain_count = n.min(inner.data.len());
        let mut result = Vec::with_capacity(drain_count);

        for _ in 0..drain_count {
            if let Some(item) = inner.data.pop_front() {
                result.push(item);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_buffer_push_pop() {
        let buffer: RingBuffer<i32> = RingBuffer::new(3);

        buffer.push(1).expect("Should push first value to buffer");
        buffer.push(2).expect("Should push second value to buffer");
        buffer.push(3).expect("Should push third value to buffer");

        assert_eq!(buffer.len().expect("Should get buffer length"), 3);
        assert!(buffer.is_full().expect("Should check if buffer is full"));

        assert_eq!(buffer.pop().expect("Should pop first value"), Some(1));
        assert_eq!(buffer.pop().expect("Should pop second value"), Some(2));
        assert_eq!(buffer.pop().expect("Should pop third value"), Some(3));
        assert_eq!(buffer.pop().expect("Should pop from empty buffer"), None);

        assert!(buffer.is_empty().expect("Should check if buffer is empty"));
    }

    #[test]
    fn test_buffer_overflow() {
        let buffer: RingBuffer<&str> = RingBuffer::new(2);

        buffer
            .push("first")
            .expect("Should push first value to buffer");
        buffer
            .push("second")
            .expect("Should push second value to buffer");
        buffer
            .push("third")
            .expect("Should push third value and overflow"); // Should drop "first"

        let snapshot = buffer.snapshot().expect("Should get buffer snapshot");
        assert_eq!(snapshot, vec!["second", "third"]);

        let stats = buffer.stats().expect("Should get buffer stats");
        assert_eq!(stats.total_written, 3);
        assert_eq!(stats.total_dropped, 1);
        // Use approximate comparison for floating point
        let drop_rate = stats.drop_rate();
        assert!((drop_rate - 33.333333).abs() < 0.001);
    }

    #[test]
    fn test_buffer_drain() {
        let buffer: RingBuffer<i32> = RingBuffer::new(5);

        for i in 1..=5 {
            buffer.push(i).expect("Should push value to buffer");
        }

        let drained = buffer.drain(3).expect("Should drain values from buffer");
        assert_eq!(drained, vec![1, 2, 3]);
        assert_eq!(buffer.len().expect("Should get buffer length"), 2);

        let remaining = buffer.snapshot().expect("Should get buffer snapshot");
        assert_eq!(remaining, vec![4, 5]);
    }

    #[test]
    fn test_buffer_thread_safety() {
        use std::thread;

        let buffer: RingBuffer<i32> = RingBuffer::new(100);
        let buffer_clone = buffer.clone();

        let producer = thread::spawn(move || {
            for i in 0..50 {
                buffer_clone.push(i).expect("Should push value to buffer");
            }
        });

        let consumer = thread::spawn(move || {
            let mut count = 0;
            while count < 50 {
                if buffer
                    .pop()
                    .expect("Should pop value from buffer")
                    .is_some()
                {
                    count += 1;
                }
                thread::yield_now();
            }
            count
        });

        producer
            .join()
            .expect("Producer thread should complete successfully");
        let consumed = consumer
            .join()
            .expect("Consumer thread should complete successfully");

        assert_eq!(consumed, 50);
    }
}

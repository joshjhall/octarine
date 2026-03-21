//! Ring buffer channel implementation
//!
//! Internal ring buffer for DropOldest semantics.

use std::collections::VecDeque;
use std::sync::Mutex;
use tokio::sync::Notify;

/// A ring buffer channel that supports drop-oldest semantics
///
/// This uses a shared ring buffer with mutex protection and async notification.
/// When the buffer is full, the oldest item is dropped to make room for the new one.
pub(super) struct RingBufferChannel<T> {
    buffer: Mutex<VecDeque<T>>,
    capacity: usize,
    notify: Notify,
    closed: std::sync::atomic::AtomicBool,
}

impl<T> RingBufferChannel<T> {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            buffer: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            notify: Notify::new(),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Send an item, dropping the oldest if full
    ///
    /// Returns true if an item was dropped to make room
    pub(super) fn send(&self, item: T) -> std::result::Result<bool, ()> {
        use std::sync::atomic::Ordering;

        if self.closed.load(Ordering::Relaxed) {
            return Err(());
        }

        let dropped = {
            let mut buffer = self.buffer.lock().map_err(|_| ())?;

            let dropped = if buffer.len() >= self.capacity {
                buffer.pop_front();
                true
            } else {
                false
            };

            buffer.push_back(item);
            dropped
        };

        // Notify waiting receivers
        self.notify.notify_one();

        Ok(dropped)
    }

    /// Receive an item, waiting if empty
    pub(super) async fn recv(&self) -> Option<T> {
        use std::sync::atomic::Ordering;

        loop {
            // Check for item
            {
                let mut buffer = self.buffer.lock().ok()?;
                if let Some(item) = buffer.pop_front() {
                    return Some(item);
                }

                // Check if closed and empty
                if self.closed.load(Ordering::Relaxed) && buffer.is_empty() {
                    return None;
                }
            }

            // Wait for notification
            self.notify.notified().await;
        }
    }

    /// Try to receive without waiting
    pub(super) fn try_recv(&self) -> Option<T> {
        let mut buffer = self.buffer.lock().ok()?;
        buffer.pop_front()
    }

    /// Get current buffer length
    pub(super) fn len(&self) -> usize {
        self.buffer.lock().map(|b| b.len()).unwrap_or(0)
    }

    /// Check if channel is closed
    pub(super) fn is_closed(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.closed.load(Ordering::Relaxed)
    }

    /// Close the channel
    pub(super) fn close(&self) {
        use std::sync::atomic::Ordering;
        self.closed.store(true, Ordering::Relaxed);
        self.notify.notify_waiters();
    }
}

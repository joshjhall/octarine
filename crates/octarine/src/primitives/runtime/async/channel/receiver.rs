//! Channel receiver implementation
//!
//! Receiver half of a bounded channel.

use std::fmt;
use std::sync::Arc;
use tokio::sync::mpsc;

use super::config::ChannelConfig;
use super::metrics::ChannelMetrics;
use super::ring_buffer::RingBufferChannel;
use super::stats::ChannelStats;
use crate::primitives::{Problem, Result};

/// Internal receiver type - either mpsc or ring buffer
pub(super) enum ReceiverInner<T> {
    Mpsc(mpsc::Receiver<T>),
    RingBuffer(Arc<RingBufferChannel<T>>),
}

/// Receiver half of a bounded channel
///
/// Cannot be cloned - only one receiver per channel.
pub struct ChannelReceiver<T> {
    pub(super) inner: ReceiverInner<T>,
    pub(super) config: ChannelConfig,
    pub(super) metrics: Arc<ChannelMetrics>,
}

impl<T> ChannelReceiver<T> {
    /// Create a new receiver (internal use only)
    pub(super) fn new(
        inner: ReceiverInner<T>,
        config: ChannelConfig,
        metrics: Arc<ChannelMetrics>,
    ) -> Self {
        Self {
            inner,
            config,
            metrics,
        }
    }

    /// Receive an item from the channel
    ///
    /// Returns `None` if the channel is closed and empty.
    pub async fn recv(&mut self) -> Option<T> {
        let result = match &mut self.inner {
            ReceiverInner::Mpsc(rx) => rx.recv().await,
            ReceiverInner::RingBuffer(rb) => rb.recv().await,
        };
        if result.is_some() {
            self.metrics.increment_received();
        }
        result
    }

    /// Try to receive without blocking
    ///
    /// Returns error if channel is empty or closed.
    pub fn try_recv(&mut self) -> Result<T> {
        match &mut self.inner {
            ReceiverInner::Mpsc(rx) => match rx.try_recv() {
                Ok(item) => {
                    self.metrics.increment_received();
                    Ok(item)
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    Err(Problem::Runtime("Channel empty".into()))
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    Err(Problem::Runtime("Channel disconnected".into()))
                }
            },
            ReceiverInner::RingBuffer(rb) => match rb.try_recv() {
                Some(item) => {
                    self.metrics.increment_received();
                    Ok(item)
                }
                None => {
                    if rb.is_closed() {
                        Err(Problem::Runtime("Channel disconnected".into()))
                    } else {
                        Err(Problem::Runtime("Channel empty".into()))
                    }
                }
            },
        }
    }

    /// Close the receiver
    ///
    /// Prevents new items from being sent. Already queued items can still
    /// be received.
    pub fn close(&mut self) {
        match &mut self.inner {
            ReceiverInner::Mpsc(rx) => rx.close(),
            ReceiverInner::RingBuffer(rb) => rb.close(),
        }
    }

    /// Get current channel statistics
    pub fn stats(&self) -> ChannelStats {
        let current_size = match &self.inner {
            ReceiverInner::RingBuffer(rb) => rb.len(),
            ReceiverInner::Mpsc(_) => 0, // Can't get size from receiver side
        };
        self.metrics.snapshot(self.config.capacity, current_size)
    }

    /// Get the channel name
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Get the channel capacity
    pub fn capacity(&self) -> usize {
        self.config.capacity
    }
}

impl<T> fmt::Debug for ChannelReceiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelReceiver")
            .field("name", &self.config.name)
            .field("capacity", &self.config.capacity)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::super::bounded::BoundedChannel;

    #[test]
    fn test_channel_try_recv_empty() {
        let channel: BoundedChannel<i32> = BoundedChannel::with_capacity(10);
        let (_tx, mut rx) = channel.split();

        let result = rx.try_recv();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_channel_close() {
        let channel: BoundedChannel<i32> = BoundedChannel::with_capacity(10);
        let (tx, mut rx) = channel.split();

        // Close receiver
        rx.close();

        // Sender should see channel as closed
        assert!(tx.is_closed());
    }

    #[test]
    fn test_receiver_debug() {
        let channel: BoundedChannel<i32> = BoundedChannel::with_capacity(10);
        let (_tx, rx) = channel.split();
        let debug = format!("{:?}", rx);
        assert!(debug.contains("ChannelReceiver"));
    }
}

//! Bounded channel implementation
//!
//! Core bounded channel with configurable overflow handling.

use std::fmt;
use std::sync::Arc;
use tokio::sync::mpsc;

use super::super::config::OverflowPolicy;
use super::config::ChannelConfig;
use super::metrics::ChannelMetrics;
use super::receiver::{ChannelReceiver, ReceiverInner};
use super::ring_buffer::RingBufferChannel;
use super::sender::{ChannelSender, SenderInner};
use super::stats::ChannelStats;

/// A bounded channel with configurable overflow handling
///
/// This is a primitive implementation without observability. Use the
/// `runtime::Channel` wrapper for logging and metrics.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::channel::{BoundedChannel, ChannelConfig};
///
/// let config = ChannelConfig::new("events", 100);
/// let channel = BoundedChannel::new(config);
/// let (tx, mut rx) = channel.split();
///
/// // Send from one task
/// tx.send("event").await;
///
/// // Receive from another
/// if let Some(msg) = rx.recv().await {
///     println!("Got: {}", msg);
/// }
/// ```
pub struct BoundedChannel<T> {
    sender_inner: SenderInner<T>,
    receiver_inner: Option<ReceiverInner<T>>,
    config: ChannelConfig,
    metrics: Arc<ChannelMetrics>,
}

impl<T> BoundedChannel<T> {
    /// Create a new bounded channel with the given configuration
    pub fn new(config: ChannelConfig) -> Self {
        let metrics = Arc::new(ChannelMetrics::default());

        match config.overflow_policy {
            OverflowPolicy::DropOldest => {
                // Use ring buffer channel for DropOldest
                let rb = Arc::new(RingBufferChannel::new(config.capacity));
                Self {
                    sender_inner: SenderInner::RingBuffer(Arc::clone(&rb)),
                    receiver_inner: Some(ReceiverInner::RingBuffer(rb)),
                    config,
                    metrics,
                }
            }
            _ => {
                // Use mpsc for other policies
                let (tx, rx) = mpsc::channel(config.capacity);
                Self {
                    sender_inner: SenderInner::Mpsc(tx),
                    receiver_inner: Some(ReceiverInner::Mpsc(rx)),
                    config,
                    metrics,
                }
            }
        }
    }

    /// Create a channel with default configuration and specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self::new(ChannelConfig::new("unnamed", capacity))
    }

    /// Split the channel into sender and receiver
    ///
    /// This consumes the channel and returns separate handles that can be
    /// moved to different tasks/threads.
    ///
    /// # Panics
    ///
    /// Panics if called more than once (channel already split).
    pub fn split(mut self) -> (ChannelSender<T>, ChannelReceiver<T>) {
        // Safe to unwrap: receiver_inner is always Some after construction
        // and this method consumes self, so it can only be called once.
        #[allow(clippy::expect_used)]
        let receiver_inner = self
            .receiver_inner
            .take()
            .expect("split called on already-split channel");

        let sender = ChannelSender::new(
            self.sender_inner,
            self.config.clone(),
            Arc::clone(&self.metrics),
        );
        let receiver = ChannelReceiver::new(receiver_inner, self.config, self.metrics);
        (sender, receiver)
    }

    /// Get current channel statistics
    pub fn stats(&self) -> ChannelStats {
        let current_size = match &self.sender_inner {
            SenderInner::RingBuffer(rb) => rb.len(),
            SenderInner::Mpsc(tx) => self.config.capacity.saturating_sub(tx.capacity()),
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

impl<T> fmt::Debug for BoundedChannel<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedChannel")
            .field("name", &self.config.name)
            .field("capacity", &self.config.capacity)
            .field("overflow_policy", &self.config.overflow_policy)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_bounded_channel_new() {
        let config = ChannelConfig::new("test", 10);
        let channel: BoundedChannel<i32> = BoundedChannel::new(config);
        assert_eq!(channel.name(), "test");
        assert_eq!(channel.capacity(), 10);
    }

    #[test]
    fn test_bounded_channel_with_capacity() {
        let channel: BoundedChannel<i32> = BoundedChannel::with_capacity(50);
        assert_eq!(channel.capacity(), 50);
        assert_eq!(channel.name(), "unnamed");
    }

    #[test]
    fn test_bounded_channel_debug() {
        let channel: BoundedChannel<i32> = BoundedChannel::with_capacity(10);
        let debug = format!("{:?}", channel);
        assert!(debug.contains("BoundedChannel"));
        assert!(debug.contains("capacity: 10"));
    }
}

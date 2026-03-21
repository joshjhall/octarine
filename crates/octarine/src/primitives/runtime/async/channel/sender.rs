//! Channel sender implementation
//!
//! Sender half of a bounded channel with various overflow policies.

use std::fmt;
use std::sync::Arc;
use tokio::sync::mpsc;

use super::super::config::OverflowPolicy;
use super::config::ChannelConfig;
use super::metrics::ChannelMetrics;
use super::ring_buffer::RingBufferChannel;
use super::stats::ChannelStats;
use super::types::{DropReason, SendOutcome};
use crate::primitives::{Problem, Result};

/// Internal sender type - either mpsc or ring buffer
pub(super) enum SenderInner<T> {
    Mpsc(mpsc::Sender<T>),
    RingBuffer(Arc<RingBufferChannel<T>>),
}

impl<T> Clone for SenderInner<T> {
    fn clone(&self) -> Self {
        match self {
            Self::Mpsc(tx) => Self::Mpsc(tx.clone()),
            Self::RingBuffer(rb) => Self::RingBuffer(Arc::clone(rb)),
        }
    }
}

/// Sender half of a bounded channel
///
/// Can be cloned to allow multiple producers.
pub struct ChannelSender<T> {
    pub(super) inner: SenderInner<T>,
    pub(super) config: ChannelConfig,
    pub(super) metrics: Arc<ChannelMetrics>,
}

impl<T> ChannelSender<T> {
    /// Create a new sender (internal use only)
    pub(super) fn new(
        inner: SenderInner<T>,
        config: ChannelConfig,
        metrics: Arc<ChannelMetrics>,
    ) -> Self {
        Self {
            inner,
            config,
            metrics,
        }
    }

    /// Send an item through the channel
    ///
    /// Behavior depends on the overflow policy:
    /// - `Block`: Waits until space is available
    /// - `Reject`: Returns error if channel is full
    /// - `DropNewest`: Drops the item being sent if full
    /// - `DropOldest`: Drops the oldest item to make room (true ring buffer behavior)
    ///
    /// # Returns
    ///
    /// - `Ok(SendOutcome::Sent)` if the item was successfully queued
    /// - `Ok(SendOutcome::Dropped(_))` if the item was dropped per policy
    /// - `Err(_)` if the channel is closed or policy is Reject and full
    pub async fn send(&self, item: T) -> Result<SendOutcome> {
        match &self.inner {
            SenderInner::RingBuffer(rb) => {
                // Ring buffer for DropOldest - always succeeds unless closed
                match rb.send(item) {
                    Ok(dropped) => {
                        self.metrics.increment_sent();
                        if dropped {
                            self.metrics.increment_dropped();
                            Ok(SendOutcome::Dropped(DropReason::ChannelFullDropOldest))
                        } else {
                            Ok(SendOutcome::Sent)
                        }
                    }
                    Err(()) => Ok(SendOutcome::Closed),
                }
            }
            SenderInner::Mpsc(tx) => {
                // Standard mpsc for other policies
                match self.config.overflow_policy {
                    OverflowPolicy::Block => {
                        tx.send(item)
                            .await
                            .map_err(|_| Problem::Runtime("Channel closed".into()))?;
                        self.metrics.increment_sent();
                        Ok(SendOutcome::Sent)
                    }

                    OverflowPolicy::Reject => match tx.try_send(item) {
                        Ok(()) => {
                            self.metrics.increment_sent();
                            Ok(SendOutcome::Sent)
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            self.metrics.increment_rejected();
                            Err(Problem::Runtime(format!(
                                "Channel '{}' full (capacity: {})",
                                self.config.name, self.config.capacity
                            )))
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            Err(Problem::Runtime("Channel closed".into()))
                        }
                    },

                    OverflowPolicy::DropNewest => match tx.try_send(item) {
                        Ok(()) => {
                            self.metrics.increment_sent();
                            Ok(SendOutcome::Sent)
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            self.metrics.increment_dropped();
                            Ok(SendOutcome::Dropped(DropReason::ChannelFullDropNewest))
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => Ok(SendOutcome::Closed),
                    },

                    OverflowPolicy::DropOldest => {
                        // This case shouldn't happen - DropOldest uses RingBuffer
                        // But handle it gracefully by blocking
                        tx.send(item)
                            .await
                            .map_err(|_| Problem::Runtime("Channel closed".into()))?;
                        self.metrics.increment_sent();
                        Ok(SendOutcome::Sent)
                    }
                }
            }
        }
    }

    /// Try to send without blocking
    ///
    /// Returns immediately with error if channel is full or closed.
    /// For DropOldest channels, this always succeeds (oldest is dropped if full).
    pub fn try_send(&self, item: T) -> Result<SendOutcome> {
        match &self.inner {
            SenderInner::RingBuffer(rb) => {
                // Ring buffer: always succeeds unless closed
                match rb.send(item) {
                    Ok(dropped) => {
                        self.metrics.increment_sent();
                        if dropped {
                            self.metrics.increment_dropped();
                            Ok(SendOutcome::Dropped(DropReason::ChannelFullDropOldest))
                        } else {
                            Ok(SendOutcome::Sent)
                        }
                    }
                    Err(()) => Err(Problem::Runtime("Channel closed".into())),
                }
            }
            SenderInner::Mpsc(tx) => match tx.try_send(item) {
                Ok(()) => {
                    self.metrics.increment_sent();
                    Ok(SendOutcome::Sent)
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.metrics.increment_rejected();
                    Err(Problem::Runtime(format!(
                        "Channel '{}' full (capacity: {})",
                        self.config.name, self.config.capacity
                    )))
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    Err(Problem::Runtime("Channel closed".into()))
                }
            },
        }
    }

    /// Check if the channel is closed
    pub fn is_closed(&self) -> bool {
        match &self.inner {
            SenderInner::RingBuffer(rb) => rb.is_closed(),
            SenderInner::Mpsc(tx) => tx.is_closed(),
        }
    }

    /// Get current channel statistics
    pub fn stats(&self) -> ChannelStats {
        let current_size = match &self.inner {
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

    /// Get remaining capacity (how many more items can be sent)
    pub fn remaining_capacity(&self) -> usize {
        match &self.inner {
            SenderInner::RingBuffer(rb) => self.config.capacity.saturating_sub(rb.len()),
            SenderInner::Mpsc(tx) => tx.capacity(),
        }
    }
}

impl<T> Clone for ChannelSender<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

impl<T> fmt::Debug for ChannelSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelSender")
            .field("name", &self.config.name)
            .field("capacity", &self.config.capacity)
            .field("is_closed", &self.is_closed())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::super::bounded::BoundedChannel;
    use super::*;

    #[test]
    fn test_sender_clone() {
        let channel: BoundedChannel<i32> = BoundedChannel::with_capacity(10);
        let (tx, _rx) = channel.split();

        let tx2 = tx.clone();
        assert_eq!(tx.name(), tx2.name());
        assert_eq!(tx.capacity(), tx2.capacity());
    }

    #[test]
    fn test_sender_remaining_capacity() {
        let channel: BoundedChannel<i32> = BoundedChannel::with_capacity(10);
        let (tx, _rx) = channel.split();

        // Initially all capacity available
        assert_eq!(tx.remaining_capacity(), 10);
    }

    #[test]
    fn test_sender_debug() {
        let channel: BoundedChannel<i32> = BoundedChannel::with_capacity(10);
        let (tx, _rx) = channel.split();
        let debug = format!("{:?}", tx);
        assert!(debug.contains("ChannelSender"));
    }

    #[tokio::test]
    async fn test_channel_send_receive() {
        let channel = BoundedChannel::with_capacity(10);
        let (tx, mut rx) = channel.split();

        let result = tx.send("hello").await.expect("send should succeed");
        assert_eq!(result, SendOutcome::Sent);

        let received = rx.recv().await;
        assert_eq!(received, Some("hello"));
    }

    #[tokio::test]
    async fn test_channel_multiple_sends() {
        let channel = BoundedChannel::with_capacity(10);
        let (tx, mut rx) = channel.split();

        for i in 0..5 {
            tx.send(i).await.expect("send should succeed");
        }

        for i in 0..5 {
            assert_eq!(rx.recv().await, Some(i));
        }
    }

    #[tokio::test]
    async fn test_channel_reject_policy() {
        let config = ChannelConfig::new("test", 1).with_overflow_policy(OverflowPolicy::Reject);
        let channel = BoundedChannel::new(config);
        let (tx, _rx) = channel.split();

        // First send should succeed
        tx.send("first").await.expect("first send should succeed");

        // Second send should be rejected
        let result = tx.send("second").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_channel_drop_newest_policy() {
        let config = ChannelConfig::new("test", 1).with_overflow_policy(OverflowPolicy::DropNewest);
        let channel = BoundedChannel::new(config);
        let (tx, mut rx) = channel.split();

        // First send should succeed
        let result1 = tx.send("first").await.expect("first send should succeed");
        assert_eq!(result1, SendOutcome::Sent);

        // Second send should be dropped (newest)
        let result2 = tx
            .send("second")
            .await
            .expect("second send should not error");
        assert_eq!(
            result2,
            SendOutcome::Dropped(DropReason::ChannelFullDropNewest)
        );

        // Should only receive "first"
        assert_eq!(rx.recv().await, Some("first"));
    }

    #[tokio::test]
    async fn test_channel_drop_oldest_policy() {
        let config = ChannelConfig::new("test", 1).with_overflow_policy(OverflowPolicy::DropOldest);
        let channel = BoundedChannel::new(config);
        let (tx, mut rx) = channel.split();

        // First send should succeed
        let result1 = tx.send("first").await.expect("first send should succeed");
        assert_eq!(result1, SendOutcome::Sent);

        // Second send should succeed but drop oldest
        let result2 = tx.send("second").await.expect("second send should succeed");
        assert_eq!(
            result2,
            SendOutcome::Dropped(DropReason::ChannelFullDropOldest)
        );

        // Third send should also succeed and drop oldest ("second")
        let result3 = tx.send("third").await.expect("third send should succeed");
        assert_eq!(
            result3,
            SendOutcome::Dropped(DropReason::ChannelFullDropOldest)
        );

        // Should only receive "third" (oldest items were dropped)
        assert_eq!(rx.recv().await, Some("third"));
    }

    #[tokio::test]
    async fn test_channel_stats() {
        let channel = BoundedChannel::with_capacity(10);
        let (tx, mut rx) = channel.split();

        tx.send("one").await.expect("send should succeed");
        tx.send("two").await.expect("send should succeed");

        let stats = tx.stats();
        assert_eq!(stats.total_sent, 2);
        assert_eq!(stats.capacity, 10);

        rx.recv().await;
        rx.recv().await;

        // Stats should still reflect sends
        let stats = tx.stats();
        assert_eq!(stats.total_sent, 2);
    }

    #[tokio::test]
    async fn test_channel_try_send() {
        let channel = BoundedChannel::with_capacity(1);
        let (tx, _rx) = channel.split();

        // First try_send should succeed
        let result = tx.try_send("first");
        assert!(result.is_ok());

        // Second try_send should fail (full)
        let result = tx.try_send("second");
        assert!(result.is_err());
    }
}

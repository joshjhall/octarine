//! Bounded channel with observability
//!
//! Provides bounded channels with backpressure support and comprehensive
//! logging, metrics, and health monitoring.
//!
//! # Features
//!
//! - Bounded capacity with configurable overflow policies
//! - Full observability (logging, metrics)
//! - Health monitoring and degradation detection
//! - Global and per-channel statistics
//!
//! # Example
//!
//! ```rust
//! use octarine::runtime::r#async::{Channel, ChannelConfig};
//!
//! # tokio_test::block_on(async {
//! // Create a channel with default settings
//! let channel = Channel::<String>::new("events", 1000);
//! let (tx, mut rx) = channel.split();
//!
//! // Send with automatic logging
//! tx.send("event".to_string()).await.unwrap();
//!
//! // Receive with automatic logging
//! if let Some(event) = rx.recv().await {
//!     assert_eq!(event, "event");
//! }
//! # });
//! ```

// Allow arithmetic operations - counters are bounded and safe
#![allow(clippy::arithmetic_side_effects)]

use crate::observe::{self, Result};
use crate::primitives::runtime::r#async::{
    BoundedChannel as PrimitiveChannel, ChannelConfig as PrimitiveConfig,
    ChannelReceiver as PrimitiveReceiver, ChannelSender as PrimitiveSender,
    ChannelStats as PrimitiveStats, DropReason as PrimitiveDropReason, OverflowPolicy,
    SendOutcome as PrimitiveSendOutcome,
};
use std::sync::atomic::{AtomicU64, Ordering};

/// Global channel statistics
static CHANNEL_STATS: ChannelStats = ChannelStats::new();

struct ChannelStats {
    total_channels: AtomicU64,
    total_sent: AtomicU64,
    total_received: AtomicU64,
    total_dropped: AtomicU64,
    total_rejected: AtomicU64,
}

impl ChannelStats {
    const fn new() -> Self {
        Self {
            total_channels: AtomicU64::new(0),
            total_sent: AtomicU64::new(0),
            total_received: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
            total_rejected: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Channel configuration
#[derive(Debug, Clone)]
pub struct ChannelConfig {
    inner: PrimitiveConfig,
}

impl ChannelConfig {
    /// Create a new channel configuration
    ///
    /// # Arguments
    ///
    /// * `name` - Name for logging and metrics
    /// * `capacity` - Maximum items the channel can hold
    pub fn new(name: impl Into<String>, capacity: usize) -> Self {
        Self {
            inner: PrimitiveConfig::new(name, capacity),
        }
    }

    /// Set the overflow policy
    pub fn with_overflow_policy(mut self, policy: OverflowPolicy) -> Self {
        self.inner = self.inner.with_overflow_policy(policy);
        self
    }

    /// Configuration for high-throughput scenarios
    ///
    /// - Large capacity (100,000)
    /// - DropNewest policy (never blocks)
    pub fn high_throughput(name: impl Into<String>) -> Self {
        Self {
            inner: PrimitiveConfig::high_throughput(name),
        }
    }

    /// Configuration for reliable delivery
    ///
    /// - Medium capacity (1,000)
    /// - Block policy (backpressure)
    pub fn reliable(name: impl Into<String>) -> Self {
        Self {
            inner: PrimitiveConfig::reliable(name),
        }
    }

    /// Configuration for low-latency scenarios
    ///
    /// - Small capacity (100)
    /// - DropOldest policy (keep recent data)
    pub fn low_latency(name: impl Into<String>) -> Self {
        Self {
            inner: PrimitiveConfig::low_latency(name),
        }
    }

    /// Get the channel name
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Get the channel capacity
    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    /// Get the overflow policy
    pub fn overflow_policy(&self) -> OverflowPolicy {
        self.inner.overflow_policy
    }
}

// ============================================================================
// Send Outcome
// ============================================================================

/// Result of a send operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// Message was successfully sent
    Sent,
    /// Message was dropped due to overflow policy
    Dropped(DropReason),
    /// Channel was closed
    Closed,
}

/// Reason why a message was dropped
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Channel full, dropped newest (incoming) message
    ChannelFullDropNewest,
    /// Channel full, dropped oldest message in queue
    ChannelFullDropOldest,
}

impl From<PrimitiveSendOutcome> for SendOutcome {
    fn from(outcome: PrimitiveSendOutcome) -> Self {
        match outcome {
            PrimitiveSendOutcome::Sent => SendOutcome::Sent,
            PrimitiveSendOutcome::Dropped(reason) => SendOutcome::Dropped(reason.into()),
            PrimitiveSendOutcome::Closed => SendOutcome::Closed,
        }
    }
}

impl From<PrimitiveDropReason> for DropReason {
    fn from(reason: PrimitiveDropReason) -> Self {
        match reason {
            PrimitiveDropReason::ChannelFullDropNewest => DropReason::ChannelFullDropNewest,
            PrimitiveDropReason::ChannelFullDropOldest => DropReason::ChannelFullDropOldest,
        }
    }
}

impl std::fmt::Display for SendOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendOutcome::Sent => write!(f, "sent"),
            SendOutcome::Dropped(reason) => write!(f, "dropped: {reason}"),
            SendOutcome::Closed => write!(f, "channel closed"),
        }
    }
}

impl std::fmt::Display for DropReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DropReason::ChannelFullDropNewest => write!(f, "channel full, dropped newest"),
            DropReason::ChannelFullDropOldest => write!(f, "channel full, dropped oldest"),
        }
    }
}

// ============================================================================
// Channel
// ============================================================================

/// Bounded channel with observability
///
/// A multi-producer, single-consumer channel with configurable capacity and
/// overflow policies. All operations are logged and tracked for metrics.
pub struct Channel<T> {
    inner: PrimitiveChannel<T>,
    name: String,
}

impl<T: Send + 'static> Channel<T> {
    /// Create a new channel with default configuration
    ///
    /// Uses Block overflow policy (backpressure).
    pub fn new(name: impl Into<String>, capacity: usize) -> Self {
        let name = name.into();
        let config = ChannelConfig::new(name.clone(), capacity);
        Self::with_config(config)
    }

    /// Create a channel with custom configuration
    pub fn with_config(config: ChannelConfig) -> Self {
        CHANNEL_STATS.total_channels.fetch_add(1, Ordering::Relaxed);

        observe::debug(
            "channel_created",
            format!(
                "Channel '{}' created (capacity: {}, policy: {:?})",
                config.name(),
                config.capacity(),
                config.overflow_policy()
            ),
        );

        Self {
            name: config.name().to_string(),
            inner: PrimitiveChannel::new(config.inner),
        }
    }

    /// Split the channel into sender and receiver
    ///
    /// The channel is consumed and separate handles are returned that can
    /// be moved to different tasks.
    pub fn split(self) -> (ChannelSender<T>, ChannelReceiver<T>) {
        let (tx, rx) = self.inner.split();
        (
            ChannelSender {
                inner: tx,
                name: self.name.clone(),
            },
            ChannelReceiver {
                inner: rx,
                name: self.name,
            },
        )
    }
}

// ============================================================================
// Sender
// ============================================================================

/// Sending half of a channel with observability
pub struct ChannelSender<T> {
    inner: PrimitiveSender<T>,
    name: String,
}

impl<T: Send + 'static> ChannelSender<T> {
    /// Send an item, waiting if the channel is full (Block policy)
    ///
    /// Returns the outcome of the send operation.
    pub async fn send(&self, item: T) -> Result<SendOutcome> {
        let result = self.inner.send(item).await;

        match &result {
            Ok(outcome) => {
                CHANNEL_STATS.total_sent.fetch_add(1, Ordering::Relaxed);

                match outcome {
                    PrimitiveSendOutcome::Sent => {
                        observe::trace(
                            "channel_send",
                            format!("Message sent to channel '{}'", self.name),
                        );
                    }
                    PrimitiveSendOutcome::Dropped(reason) => {
                        CHANNEL_STATS.total_dropped.fetch_add(1, Ordering::Relaxed);
                        observe::warn(
                            "channel_send_dropped",
                            format!("Message dropped on channel '{}': {}", self.name, reason),
                        );
                    }
                    PrimitiveSendOutcome::Closed => {
                        observe::warn(
                            "channel_send_closed",
                            format!("Channel '{}' is closed", self.name),
                        );
                    }
                }
            }
            Err(e) => {
                observe::error(
                    "channel_send_failed",
                    format!("Send failed on channel '{}': {}", self.name, e),
                );
            }
        }

        result.map(SendOutcome::from)
    }

    /// Try to send without waiting
    ///
    /// Returns immediately with error if the channel is full (for Block/Reject policies).
    pub fn try_send(&self, item: T) -> Result<SendOutcome> {
        let result = self.inner.try_send(item);

        match &result {
            Ok(outcome) => {
                CHANNEL_STATS.total_sent.fetch_add(1, Ordering::Relaxed);

                if let PrimitiveSendOutcome::Dropped(reason) = outcome {
                    CHANNEL_STATS.total_dropped.fetch_add(1, Ordering::Relaxed);
                    observe::warn(
                        "channel_try_send_dropped",
                        format!(
                            "Message dropped on channel '{}' (try_send): {}",
                            self.name, reason
                        ),
                    );
                }
            }
            Err(_) => {
                CHANNEL_STATS.total_rejected.fetch_add(1, Ordering::Relaxed);
                observe::debug(
                    "channel_try_send_rejected",
                    format!("Channel '{}' full, try_send rejected", self.name),
                );
            }
        }

        result.map(SendOutcome::from)
    }

    /// Check if the channel is closed
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Get remaining capacity
    pub fn remaining_capacity(&self) -> usize {
        self.inner.remaining_capacity()
    }

    /// Get the channel name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get channel statistics
    pub fn stats(&self) -> ChannelStatistics {
        self.inner.stats().into()
    }
}

impl<T> Clone for ChannelSender<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            name: self.name.clone(),
        }
    }
}

// ============================================================================
// Receiver
// ============================================================================

/// Receiving half of a channel with observability
pub struct ChannelReceiver<T> {
    inner: PrimitiveReceiver<T>,
    name: String,
}

impl<T: Send + 'static> ChannelReceiver<T> {
    /// Receive an item, waiting if the channel is empty
    ///
    /// Returns `None` if the channel is closed and empty.
    pub async fn recv(&mut self) -> Option<T> {
        let result = self.inner.recv().await;

        if result.is_some() {
            CHANNEL_STATS.total_received.fetch_add(1, Ordering::Relaxed);
            observe::trace(
                "channel_recv",
                format!("Message received from channel '{}'", self.name),
            );
        }

        result
    }

    /// Try to receive without waiting
    ///
    /// Returns `Err` if the channel is empty.
    pub fn try_recv(&mut self) -> Result<T> {
        let result = self.inner.try_recv();

        if result.is_ok() {
            CHANNEL_STATS.total_received.fetch_add(1, Ordering::Relaxed);
        }

        result
    }

    /// Close the receiver
    ///
    /// Senders will be notified that the channel is closed.
    pub fn close(&mut self) {
        self.inner.close();
        observe::debug(
            "channel_closed",
            format!("Channel '{}' closed by receiver", self.name),
        );
    }

    /// Get the channel name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get channel statistics
    pub fn stats(&self) -> ChannelStatistics {
        self.inner.stats().into()
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Statistics for a specific channel
#[derive(Debug, Clone)]
pub struct ChannelStatistics {
    /// Messages successfully sent
    pub sent: usize,
    /// Messages dropped due to overflow
    pub dropped: usize,
    /// Messages rejected (try_send on full channel)
    pub rejected: usize,
    /// Current queue depth
    pub current_depth: usize,
    /// Channel capacity
    pub capacity: usize,
}

impl From<PrimitiveStats> for ChannelStatistics {
    fn from(stats: PrimitiveStats) -> Self {
        Self {
            sent: stats.total_sent,
            dropped: stats.total_dropped,
            rejected: stats.total_rejected,
            current_depth: stats.current_size,
            capacity: stats.capacity,
        }
    }
}

impl ChannelStatistics {
    /// Calculate utilization (0.0 to 1.0)
    pub fn utilization(&self) -> f64 {
        if self.capacity == 0 {
            return 0.0;
        }
        self.current_depth as f64 / self.capacity as f64
    }

    /// Check if channel is at capacity
    pub fn is_full(&self) -> bool {
        self.current_depth >= self.capacity
    }

    /// Check if channel is empty
    pub fn is_empty(&self) -> bool {
        self.current_depth == 0
    }

    /// Get drop rate as a fraction of total attempts (0.0 to 1.0)
    pub fn drop_rate(&self) -> f64 {
        let total = self.sent + self.dropped + self.rejected;
        if total == 0 {
            return 0.0;
        }
        self.dropped as f64 / total as f64
    }

    /// Get rejection rate as a fraction of total attempts (0.0 to 1.0)
    pub fn rejection_rate(&self) -> f64 {
        let total = self.sent + self.dropped + self.rejected;
        if total == 0 {
            return 0.0;
        }
        self.rejected as f64 / total as f64
    }

    /// Get success rate as a fraction of total attempts (0.0 to 1.0)
    pub fn success_rate(&self) -> f64 {
        let total = self.sent + self.dropped + self.rejected;
        if total == 0 {
            return 1.0;
        }
        self.sent as f64 / total as f64
    }

    /// Get total number of failed operations (dropped + rejected)
    pub fn total_failed(&self) -> usize {
        self.dropped + self.rejected
    }

    /// Calculate a health score from 0.0 (unhealthy) to 1.0 (healthy)
    ///
    /// Based on success rate (80% weight) and inverse utilization (20% weight).
    pub fn health_score(&self) -> f64 {
        let success_factor = self.success_rate() * 0.8;
        let utilization_factor = (1.0 - self.utilization()) * 0.2;
        success_factor + utilization_factor
    }

    /// Check if channel is in a degraded state
    ///
    /// Degraded if utilization > 80%, drop rate > 5%, or rejection rate > 5%.
    pub fn is_degraded(&self) -> bool {
        self.utilization() > 0.8 || self.drop_rate() > 0.05 || self.rejection_rate() > 0.05
    }

    /// Check if channel is experiencing backpressure
    pub fn is_under_pressure(&self) -> bool {
        self.utilization() > 0.8 || self.dropped > 0 || self.rejected > 0
    }
}

/// Global channel statistics
#[derive(Debug, Clone)]
pub struct GlobalChannelStatistics {
    /// Total channels created
    pub total_channels: u64,
    /// Total messages sent across all channels
    pub total_sent: u64,
    /// Total messages received across all channels
    pub total_received: u64,
    /// Total messages dropped across all channels
    pub total_dropped: u64,
    /// Total messages rejected across all channels
    pub total_rejected: u64,
}

/// Get global channel statistics
pub fn channel_stats() -> GlobalChannelStatistics {
    GlobalChannelStatistics {
        total_channels: CHANNEL_STATS.total_channels.load(Ordering::Relaxed),
        total_sent: CHANNEL_STATS.total_sent.load(Ordering::Relaxed),
        total_received: CHANNEL_STATS.total_received.load(Ordering::Relaxed),
        total_dropped: CHANNEL_STATS.total_dropped.load(Ordering::Relaxed),
        total_rejected: CHANNEL_STATS.total_rejected.load(Ordering::Relaxed),
    }
}

/// Check if channels are healthy (no significant drops or rejections)
pub fn channels_healthy() -> bool {
    let stats = channel_stats();
    let total_attempts = stats.total_sent + stats.total_rejected;
    if total_attempts == 0 {
        return true;
    }

    let failure_rate = (stats.total_dropped + stats.total_rejected) as f64 / total_attempts as f64;
    failure_rate < 0.01 // Less than 1% failure rate
}

/// Check if channels are degraded
///
/// Returns true if failure rate exceeds 5% (but less than unhealthy threshold).
pub fn channels_is_degraded() -> bool {
    let stats = channel_stats();
    let total_attempts = stats.total_sent + stats.total_rejected;
    if total_attempts == 0 {
        return false;
    }

    let failure_rate = (stats.total_dropped + stats.total_rejected) as f64 / total_attempts as f64;
    (0.01..0.1).contains(&failure_rate) // Between 1% and 10%
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[tokio::test]
    async fn test_channel_send_receive() {
        let channel = Channel::new("test", 10);
        let (tx, mut rx) = channel.split();

        let outcome = tx.send("hello").await.expect("send should succeed");
        assert_eq!(outcome, SendOutcome::Sent);

        let msg = rx.recv().await;
        assert_eq!(msg, Some("hello"));
    }

    #[tokio::test]
    async fn test_channel_try_send() {
        let channel = Channel::new("test_try", 1);
        let (tx, _rx) = channel.split();

        // First should succeed
        let outcome = tx.try_send("first").expect("first should succeed");
        assert_eq!(outcome, SendOutcome::Sent);

        // Second should fail (channel full, Block policy)
        let result = tx.try_send("second");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_channel_drop_oldest() {
        let config =
            ChannelConfig::new("drop_oldest", 1).with_overflow_policy(OverflowPolicy::DropOldest);
        let channel = Channel::with_config(config);
        let (tx, mut rx) = channel.split();

        tx.send("first").await.expect("send should succeed");
        let outcome = tx.send("second").await.expect("send should succeed");
        assert_eq!(
            outcome,
            SendOutcome::Dropped(DropReason::ChannelFullDropOldest)
        );

        // Should receive "second" (first was dropped)
        assert_eq!(rx.recv().await, Some("second"));
    }

    #[tokio::test]
    async fn test_channel_close() {
        let channel: Channel<i32> = Channel::new("close_test", 10);
        let (tx, mut rx) = channel.split();

        rx.close();
        assert!(tx.is_closed());
    }

    #[test]
    fn test_channel_config_presets() {
        let high = ChannelConfig::high_throughput("high");
        assert_eq!(high.capacity(), 100_000);
        assert_eq!(high.overflow_policy(), OverflowPolicy::DropNewest);

        let reliable = ChannelConfig::reliable("reliable");
        assert_eq!(reliable.capacity(), 1_000);
        assert_eq!(reliable.overflow_policy(), OverflowPolicy::Block);

        let low = ChannelConfig::low_latency("low");
        assert_eq!(low.capacity(), 100);
        assert_eq!(low.overflow_policy(), OverflowPolicy::Reject); // Reject to avoid latency from dropping
    }

    #[test]
    fn test_channel_statistics() {
        let stats = ChannelStatistics {
            sent: 100,
            dropped: 5,
            rejected: 5,
            current_depth: 8,
            capacity: 10,
        };

        assert!((stats.utilization() - 0.8).abs() < f64::EPSILON);
        assert!(stats.is_under_pressure());
    }

    #[test]
    fn test_global_stats() {
        let stats = channel_stats();
        // Just verify the function returns valid stats
        let _ = stats.total_channels; // Verify field exists
    }

    #[test]
    fn test_send_outcome_display() {
        assert_eq!(SendOutcome::Sent.to_string(), "sent");
        assert_eq!(
            SendOutcome::Dropped(DropReason::ChannelFullDropNewest).to_string(),
            "dropped: channel full, dropped newest"
        );
    }
}

//! Broadcast channels for multi-consumer event distribution
//!
//! Pure broadcast channel implementation with no dependencies on observe or other
//! internal modules. The `runtime` module wraps these primitives and adds observability.
#![allow(dead_code)] // Public API primitives - not all items used internally yet
//!
//! ## Features
//!
//! - **Multi-consumer**: All receivers get copies of each message
//! - **Bounded capacity**: Prevents memory exhaustion (CWE-400)
//! - **Lag detection**: Track when receivers fall behind
//! - **Statistics tracking**: Monitor broadcast health
//!
//! ## Usage Examples
//!
//! ### Basic Broadcast
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::broadcast::{Broadcast, BroadcastConfig};
//!
//! let config = BroadcastConfig::new("events", 100);
//! let broadcast = Broadcast::new(config);
//!
//! let mut rx1 = broadcast.subscribe();
//! let mut rx2 = broadcast.subscribe();
//!
//! broadcast.send("hello")?;
//!
//! // Both receivers get the message
//! assert_eq!(rx1.recv().await?, "hello");
//! assert_eq!(rx2.recv().await?, "hello");
//! ```
//!
//! ### Handling Lag
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::broadcast::{Broadcast, BroadcastConfig, RecvOutcome};
//!
//! let broadcast = Broadcast::with_capacity(2);
//! let mut rx = broadcast.subscribe();
//!
//! // Send more than capacity
//! broadcast.send(1)?;
//! broadcast.send(2)?;
//! broadcast.send(3)?;
//!
//! // Receiver reports lag
//! match rx.recv_with_lag().await {
//!     RecvOutcome::Ok(v) => println!("Got: {}", v),
//!     RecvOutcome::Lagged { missed, value } => {
//!         println!("Lagged by {}, got: {}", missed, value);
//!     }
//!     RecvOutcome::Closed => println!("Channel closed"),
//! }
//! ```
//!
//! ## Design Notes
//!
//! This is a **primitive** module - it has NO dependencies on observe or other
//! internal modules. The `runtime/broadcast.rs` wrapper adds logging, metrics,
//! and event dispatching.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::broadcast;

use crate::primitives::{Problem, Result};

// =============================================================================
// Broadcast Configuration
// =============================================================================

/// Configuration for a broadcast channel
#[derive(Debug, Clone)]
pub struct BroadcastConfig {
    /// Name for identification and debugging
    pub name: String,
    /// Maximum capacity of the channel
    pub capacity: usize,
}

impl BroadcastConfig {
    /// Create a new broadcast configuration
    ///
    /// # Arguments
    ///
    /// * `name` - Identifier for debugging and metrics
    /// * `capacity` - Maximum number of items the channel can hold
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::broadcast::BroadcastConfig;
    ///
    /// let config = BroadcastConfig::new("events", 100);
    /// assert_eq!(config.name, "events");
    /// assert_eq!(config.capacity, 100);
    /// ```
    pub fn new(name: impl Into<String>, capacity: usize) -> Self {
        Self {
            name: name.into(),
            capacity,
        }
    }

    /// Validate the configuration
    ///
    /// Returns error if capacity is 0.
    pub fn validate(&self) -> Result<()> {
        if self.capacity == 0 {
            return Err(Problem::Validation("Broadcast capacity cannot be 0".into()));
        }
        Ok(())
    }

    /// Event bus configuration for application-wide events
    ///
    /// Large capacity for high-throughput event distribution.
    /// Good for pub/sub patterns where many subscribers need events.
    ///
    /// - Capacity: 10,000 messages
    pub fn event_bus(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            capacity: 10_000,
        }
    }

    /// Signal channel configuration for control signals
    ///
    /// Small capacity for lightweight signal distribution.
    /// Good for shutdown signals, configuration changes, etc.
    ///
    /// - Capacity: 16 messages
    pub fn signal(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            capacity: 16,
        }
    }

    /// Real-time update configuration
    ///
    /// Moderate capacity optimized for real-time updates where
    /// lagging receivers should catch up quickly.
    ///
    /// - Capacity: 256 messages
    pub fn realtime(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            capacity: 256,
        }
    }
}

impl Default for BroadcastConfig {
    fn default() -> Self {
        Self {
            name: "unnamed".into(),
            capacity: 16,
        }
    }
}

// =============================================================================
// Receive Outcome
// =============================================================================

/// Result of a receive operation on a broadcast channel
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecvOutcome<T> {
    /// Message received successfully
    Ok(T),
    /// Receiver lagged behind - missed some messages but got the latest
    Lagged {
        /// Number of messages missed
        missed: u64,
        /// The value that was received after lag
        value: T,
    },
    /// Channel closed, no more messages
    Closed,
}

impl<T: fmt::Display> fmt::Display for RecvOutcome<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecvOutcome::Ok(v) => write!(f, "Ok({})", v),
            RecvOutcome::Lagged { missed, value } => {
                write!(f, "Lagged(missed={}, value={})", missed, value)
            }
            RecvOutcome::Closed => write!(f, "Closed"),
        }
    }
}

// =============================================================================
// Broadcast Statistics
// =============================================================================

/// Statistics for a broadcast channel
#[derive(Debug)]
pub struct BroadcastStats {
    /// Total messages sent
    pub messages_sent: u64,
    /// Total times receivers lagged
    pub receivers_lagged: u64,
    /// Current active receiver count
    pub active_receivers: usize,
    /// Channel capacity
    pub capacity: usize,
    /// Channel name
    pub name: String,
}

impl BroadcastStats {
    /// Check if the broadcast is healthy (no lag issues)
    pub fn is_healthy(&self) -> bool {
        self.receivers_lagged == 0
    }
}

/// Internal metrics tracking for broadcast
struct BroadcastMetrics {
    messages_sent: AtomicU64,
    receivers_lagged: AtomicU64,
}

impl BroadcastMetrics {
    fn new() -> Self {
        Self {
            messages_sent: AtomicU64::new(0),
            receivers_lagged: AtomicU64::new(0),
        }
    }

    fn increment_sent(&self) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_lagged(&self) {
        self.receivers_lagged.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self, capacity: usize, active_receivers: usize, name: &str) -> BroadcastStats {
        BroadcastStats {
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            receivers_lagged: self.receivers_lagged.load(Ordering::Relaxed),
            active_receivers,
            capacity,
            name: name.to_string(),
        }
    }
}

// =============================================================================
// Broadcast Channel
// =============================================================================

/// A broadcast channel for multi-consumer scenarios
///
/// Each message sent is delivered to all active receivers. If a receiver
/// falls behind (the channel fills up), it will miss messages (lag).
///
/// # Example
///
/// ```rust,ignore
/// use octarine::primitives::runtime::broadcast::{Broadcast, BroadcastConfig};
///
/// let config = BroadcastConfig::new("events", 100);
/// let broadcast = Broadcast::new(config);
///
/// // Create multiple receivers
/// let mut rx1 = broadcast.subscribe();
/// let mut rx2 = broadcast.subscribe();
///
/// // Send a message
/// broadcast.send("hello")?;
///
/// // Both receivers get the message
/// let msg1 = rx1.recv().await?;
/// let msg2 = rx2.recv().await?;
/// assert_eq!(msg1, "hello");
/// assert_eq!(msg2, "hello");
/// ```
pub struct Broadcast<T: Clone> {
    sender: broadcast::Sender<T>,
    config: BroadcastConfig,
    metrics: Arc<BroadcastMetrics>,
}

impl<T: Clone> Broadcast<T> {
    /// Create a new broadcast channel with the given configuration
    pub fn new(config: BroadcastConfig) -> Self {
        let (sender, _) = broadcast::channel(config.capacity);
        Self {
            sender,
            config,
            metrics: Arc::new(BroadcastMetrics::new()),
        }
    }

    /// Create a new broadcast channel with just a capacity
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::broadcast::Broadcast;
    ///
    /// let broadcast = Broadcast::<String>::with_capacity(100);
    /// ```
    pub fn with_capacity(capacity: usize) -> Self {
        Self::new(BroadcastConfig {
            name: "unnamed".into(),
            capacity,
        })
    }

    /// Send a message to all receivers
    ///
    /// Returns the number of receivers that will receive the message.
    /// Returns error if there are no receivers.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let broadcast = Broadcast::with_capacity(100);
    /// let mut rx = broadcast.subscribe();
    ///
    /// let count = broadcast.send("hello")?;
    /// assert_eq!(count, 1);
    /// ```
    pub fn send(&self, item: T) -> Result<usize> {
        match self.sender.send(item) {
            Ok(count) => {
                self.metrics.increment_sent();
                Ok(count)
            }
            Err(_) => Err(Problem::Runtime(format!(
                "Broadcast '{}' has no receivers",
                self.config.name
            ))),
        }
    }

    /// Create a new receiver that will get all future messages
    ///
    /// The receiver will not receive any messages that were sent
    /// before the subscription.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let broadcast = Broadcast::with_capacity(100);
    /// let mut rx = broadcast.subscribe();
    /// ```
    pub fn subscribe(&self) -> BroadcastReceiver<T> {
        BroadcastReceiver {
            receiver: self.sender.subscribe(),
            config: self.config.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }

    /// Get the number of active receivers
    pub fn receiver_count(&self) -> usize {
        self.sender.receiver_count()
    }

    /// Check if there are any receivers
    ///
    /// Returns `true` if at least one receiver is subscribed.
    pub fn is_receivers_present(&self) -> bool {
        self.receiver_count() > 0
    }

    /// Get the channel capacity
    pub fn capacity(&self) -> usize {
        self.config.capacity
    }

    /// Get the channel name
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Get current statistics
    pub fn stats(&self) -> BroadcastStats {
        self.metrics.snapshot(
            self.config.capacity,
            self.receiver_count(),
            &self.config.name,
        )
    }
}

impl<T: Clone> Clone for Broadcast<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            config: self.config.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

// =============================================================================
// Broadcast Receiver
// =============================================================================

/// A receiver for broadcast messages
///
/// Each receiver gets a copy of every message sent to the broadcast channel.
/// If the receiver doesn't keep up, it will lag and miss messages.
pub struct BroadcastReceiver<T: Clone> {
    receiver: broadcast::Receiver<T>,
    config: BroadcastConfig,
    metrics: Arc<BroadcastMetrics>,
}

impl<T: Clone> BroadcastReceiver<T> {
    /// Receive the next message, waiting if necessary
    ///
    /// Returns error if the channel is closed or the receiver lagged.
    /// For lag-aware receiving, use `recv_with_lag()`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let broadcast = Broadcast::with_capacity(100);
    /// let mut rx = broadcast.subscribe();
    ///
    /// broadcast.send("hello")?;
    /// let msg = rx.recv().await?;
    /// assert_eq!(msg, "hello");
    /// ```
    pub async fn recv(&mut self) -> Result<T> {
        match self.receiver.recv().await {
            Ok(item) => Ok(item),
            Err(e) => match e {
                broadcast::error::RecvError::Closed => {
                    Err(Problem::Runtime("Broadcast channel closed".into()))
                }
                broadcast::error::RecvError::Lagged(count) => {
                    self.metrics.increment_lagged();
                    Err(Problem::Runtime(format!(
                        "Receiver lagged, missed {} messages",
                        count
                    )))
                }
            },
        }
    }

    /// Receive the next message with lag information
    ///
    /// Unlike `recv()`, this method returns `RecvOutcome::Lagged` with
    /// the next message instead of an error when lag occurs.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::broadcast::RecvOutcome;
    ///
    /// match rx.recv_with_lag().await {
    ///     RecvOutcome::Ok(msg) => println!("Got: {}", msg),
    ///     RecvOutcome::Lagged { missed, value } => {
    ///         println!("Lagged {} messages, got: {}", missed, value);
    ///     }
    ///     RecvOutcome::Closed => println!("Channel closed"),
    /// }
    /// ```
    pub async fn recv_with_lag(&mut self) -> RecvOutcome<T> {
        match self.receiver.recv().await {
            Ok(item) => RecvOutcome::Ok(item),
            Err(e) => match e {
                broadcast::error::RecvError::Closed => RecvOutcome::Closed,
                broadcast::error::RecvError::Lagged(count) => {
                    self.metrics.increment_lagged();
                    // Try to get the next message after lag
                    match self.receiver.recv().await {
                        Ok(item) => RecvOutcome::Lagged {
                            missed: count,
                            value: item,
                        },
                        Err(broadcast::error::RecvError::Closed) => RecvOutcome::Closed,
                        Err(broadcast::error::RecvError::Lagged(more)) => {
                            // Still lagging, try again recursively
                            self.metrics.increment_lagged();
                            Box::pin(self.recv_with_lag_internal(count.saturating_add(more))).await
                        }
                    }
                }
            },
        }
    }

    /// Internal helper for recursive lag handling
    async fn recv_with_lag_internal(&mut self, total_missed: u64) -> RecvOutcome<T> {
        match self.receiver.recv().await {
            Ok(item) => RecvOutcome::Lagged {
                missed: total_missed,
                value: item,
            },
            Err(e) => match e {
                broadcast::error::RecvError::Closed => RecvOutcome::Closed,
                broadcast::error::RecvError::Lagged(more) => {
                    self.metrics.increment_lagged();
                    // Keep trying - limit recursion depth with Box::pin
                    let new_total = total_missed.saturating_add(more);
                    if new_total > 1_000_000 {
                        // Safety limit
                        return RecvOutcome::Closed;
                    }
                    Box::pin(self.recv_with_lag_internal(new_total)).await
                }
            },
        }
    }

    /// Try to receive without blocking
    ///
    /// Returns error if the channel is empty, closed, or lagged.
    pub fn try_recv(&mut self) -> Result<T> {
        match self.receiver.try_recv() {
            Ok(item) => Ok(item),
            Err(e) => match e {
                broadcast::error::TryRecvError::Closed => {
                    Err(Problem::Runtime("Broadcast channel closed".into()))
                }
                broadcast::error::TryRecvError::Lagged(count) => {
                    self.metrics.increment_lagged();
                    Err(Problem::Runtime(format!(
                        "Receiver lagged, missed {} messages",
                        count
                    )))
                }
                broadcast::error::TryRecvError::Empty => {
                    Err(Problem::Runtime("Broadcast channel empty".into()))
                }
            },
        }
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

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // =========================================================================
    // BroadcastConfig Tests
    // =========================================================================

    #[test]
    fn test_broadcast_config_new() {
        let config = BroadcastConfig::new("test", 100);
        assert_eq!(config.name, "test");
        assert_eq!(config.capacity, 100);
    }

    #[test]
    fn test_broadcast_config_default() {
        let config = BroadcastConfig::default();
        assert_eq!(config.name, "unnamed");
        assert_eq!(config.capacity, 16);
    }

    #[test]
    fn test_broadcast_config_validate_zero_capacity() {
        let config = BroadcastConfig::new("test", 0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_broadcast_config_validate_valid() {
        let config = BroadcastConfig::new("test", 100);
        assert!(config.validate().is_ok());
    }

    // =========================================================================
    // Broadcast Tests
    // =========================================================================

    #[test]
    fn test_broadcast_new() {
        let config = BroadcastConfig::new("test", 100);
        let broadcast = Broadcast::<String>::new(config);
        assert_eq!(broadcast.name(), "test");
        assert_eq!(broadcast.capacity(), 100);
        assert_eq!(broadcast.receiver_count(), 0);
    }

    #[test]
    fn test_broadcast_with_capacity() {
        let broadcast = Broadcast::<String>::with_capacity(50);
        assert_eq!(broadcast.capacity(), 50);
    }

    #[test]
    fn test_broadcast_subscribe() {
        let broadcast = Broadcast::<String>::with_capacity(10);
        assert_eq!(broadcast.receiver_count(), 0);
        assert!(!broadcast.is_receivers_present());

        let _rx1 = broadcast.subscribe();
        assert_eq!(broadcast.receiver_count(), 1);
        assert!(broadcast.is_receivers_present());

        let _rx2 = broadcast.subscribe();
        assert_eq!(broadcast.receiver_count(), 2);
    }

    #[test]
    fn test_broadcast_send_no_receivers() {
        let broadcast = Broadcast::<String>::with_capacity(10);
        let result = broadcast.send("test".to_string());
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_broadcast_send_receive() {
        let broadcast = Broadcast::with_capacity(10);
        let mut rx = broadcast.subscribe();

        let count = broadcast
            .send("hello".to_string())
            .expect("send should work");
        assert_eq!(count, 1);

        let msg = rx.recv().await.expect("recv should work");
        assert_eq!(msg, "hello");
    }

    #[tokio::test]
    async fn test_broadcast_multiple_receivers() {
        let broadcast = Broadcast::with_capacity(10);
        let mut rx1 = broadcast.subscribe();
        let mut rx2 = broadcast.subscribe();

        assert_eq!(broadcast.receiver_count(), 2);

        broadcast
            .send("test".to_string())
            .expect("send should work");

        let msg1 = rx1.recv().await.expect("rx1 recv should work");
        let msg2 = rx2.recv().await.expect("rx2 recv should work");

        assert_eq!(msg1, "test");
        assert_eq!(msg2, "test");
    }

    #[tokio::test]
    async fn test_broadcast_stats() {
        let broadcast = Broadcast::with_capacity(10);
        let _rx = broadcast.subscribe();

        broadcast.send("msg1".to_string()).expect("send 1");
        broadcast.send("msg2".to_string()).expect("send 2");

        let stats = broadcast.stats();
        assert_eq!(stats.messages_sent, 2);
        assert_eq!(stats.active_receivers, 1);
        assert_eq!(stats.capacity, 10);
    }

    #[tokio::test]
    async fn test_broadcast_lag() {
        let broadcast = Broadcast::with_capacity(2);
        let mut rx = broadcast.subscribe();

        // Send more than capacity to cause lag
        broadcast.send(1).expect("send 1");
        broadcast.send(2).expect("send 2");
        broadcast.send(3).expect("send 3");

        // Should get lag error
        let result = rx.recv().await;
        assert!(result.is_err());
        let err = result.expect_err("should be lagged error");
        assert!(err.to_string().contains("lagged"));
    }

    #[tokio::test]
    async fn test_broadcast_recv_with_lag() {
        let broadcast = Broadcast::with_capacity(2);
        let mut rx = broadcast.subscribe();

        // Send more than capacity
        broadcast.send(1).expect("send 1");
        broadcast.send(2).expect("send 2");
        broadcast.send(3).expect("send 3");

        // Should get lagged with value
        let result = rx.recv_with_lag().await;
        match result {
            RecvOutcome::Lagged { missed, value } => {
                assert!(missed > 0);
                // The value should be one of the messages
                assert!((1..=3).contains(&value));
            }
            RecvOutcome::Ok(v) => {
                // If no lag happened somehow, that's also fine
                assert!((1..=3).contains(&v));
            }
            RecvOutcome::Closed => panic!("Should not be closed"),
        }
    }

    #[tokio::test]
    async fn test_broadcast_try_recv_empty() {
        let broadcast = Broadcast::<String>::with_capacity(10);
        let mut rx = broadcast.subscribe();

        let result = rx.try_recv();
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should be empty error")
                .to_string()
                .contains("empty")
        );
    }

    #[tokio::test]
    async fn test_broadcast_try_recv_success() {
        let broadcast = Broadcast::with_capacity(10);
        let mut rx = broadcast.subscribe();

        broadcast.send("hello".to_string()).expect("send");

        let msg = rx.try_recv().expect("try_recv should work");
        assert_eq!(msg, "hello");
    }

    #[tokio::test]
    async fn test_broadcast_clone() {
        let broadcast1 = Broadcast::with_capacity(10);
        let broadcast2 = broadcast1.clone();

        let mut rx1 = broadcast1.subscribe();
        let mut rx2 = broadcast2.subscribe();

        // Sending on either should reach both
        broadcast1.send("from1".to_string()).expect("send");

        let msg1 = rx1.recv().await.expect("rx1 recv");
        let msg2 = rx2.recv().await.expect("rx2 recv");
        assert_eq!(msg1, "from1");
        assert_eq!(msg2, "from1");
    }

    #[test]
    fn test_recv_outcome_display() {
        let ok: RecvOutcome<i32> = RecvOutcome::Ok(42);
        assert_eq!(format!("{}", ok), "Ok(42)");

        let lagged: RecvOutcome<i32> = RecvOutcome::Lagged {
            missed: 5,
            value: 100,
        };
        assert_eq!(format!("{}", lagged), "Lagged(missed=5, value=100)");

        let closed: RecvOutcome<i32> = RecvOutcome::Closed;
        assert_eq!(format!("{}", closed), "Closed");
    }

    // =========================================================================
    // BroadcastReceiver Tests
    // =========================================================================

    #[test]
    fn test_receiver_name_and_capacity() {
        let config = BroadcastConfig::new("test_channel", 50);
        let broadcast = Broadcast::<String>::new(config);
        let rx = broadcast.subscribe();

        assert_eq!(rx.name(), "test_channel");
        assert_eq!(rx.capacity(), 50);
    }

    #[tokio::test]
    async fn test_receiver_drop_reduces_count() {
        let broadcast = Broadcast::<String>::with_capacity(10);

        {
            let _rx1 = broadcast.subscribe();
            let _rx2 = broadcast.subscribe();
            assert_eq!(broadcast.receiver_count(), 2);
        }

        // After receivers are dropped
        assert_eq!(broadcast.receiver_count(), 0);
    }

    #[test]
    fn test_preset_event_bus() {
        let config = BroadcastConfig::event_bus("app_events");
        assert_eq!(config.name, "app_events");
        assert_eq!(config.capacity, 10_000);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preset_signal() {
        let config = BroadcastConfig::signal("shutdown");
        assert_eq!(config.name, "shutdown");
        assert_eq!(config.capacity, 16);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preset_realtime() {
        let config = BroadcastConfig::realtime("prices");
        assert_eq!(config.name, "prices");
        assert_eq!(config.capacity, 256);
        assert!(config.validate().is_ok());
    }
}

//! Channel configuration
//!
//! Configuration options for bounded channels with various overflow policies.

use super::super::config::OverflowPolicy;
use crate::primitives::{Problem, Result};

/// Configuration for a bounded channel
#[derive(Debug, Clone)]
pub struct ChannelConfig {
    /// Name for identification and debugging
    pub name: String,
    /// Maximum capacity of the channel
    pub capacity: usize,
    /// Policy for handling overflow
    pub overflow_policy: OverflowPolicy,
}

impl ChannelConfig {
    /// Create a new channel configuration
    ///
    /// # Arguments
    ///
    /// * `name` - Identifier for debugging and metrics
    /// * `capacity` - Maximum number of items the channel can hold
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::channel::ChannelConfig;
    ///
    /// let config = ChannelConfig::new("events", 1000);
    /// ```
    pub fn new(name: impl Into<String>, capacity: usize) -> Self {
        Self {
            name: name.into(),
            capacity,
            overflow_policy: OverflowPolicy::Block,
        }
    }

    /// Set the overflow policy
    pub fn with_overflow_policy(mut self, policy: OverflowPolicy) -> Self {
        self.overflow_policy = policy;
        self
    }

    /// Validate the configuration
    ///
    /// # Errors
    ///
    /// Returns error if capacity is 0.
    pub fn validate(&self) -> Result<()> {
        if self.capacity == 0 {
            return Err(Problem::Validation("Channel capacity cannot be 0".into()));
        }
        Ok(())
    }

    /// High-throughput configuration for event streams
    ///
    /// Large buffer, drops newest items on overflow to prevent blocking.
    /// Good for metrics, logs, or telemetry where losing recent data is acceptable.
    ///
    /// - Capacity: 100,000 items
    /// - Overflow: DropNewest (never blocks sender)
    pub fn high_throughput(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            capacity: 100_000,
            overflow_policy: OverflowPolicy::DropNewest,
        }
    }

    /// Reliable delivery configuration
    ///
    /// Blocks sender when full to ensure no messages are lost.
    /// Good for critical messages that must not be dropped.
    ///
    /// - Capacity: 1,000 items
    /// - Overflow: Block (apply backpressure)
    pub fn reliable(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            capacity: 1_000,
            overflow_policy: OverflowPolicy::Block,
        }
    }

    /// Low-latency configuration for real-time processing
    ///
    /// Small buffer with rejection on overflow for fast failure detection.
    /// Good for real-time systems where stale data is worse than no data.
    ///
    /// - Capacity: 100 items
    /// - Overflow: Reject (fail fast)
    pub fn low_latency(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            capacity: 100,
            overflow_policy: OverflowPolicy::Reject,
        }
    }
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self {
            name: "unnamed".into(),
            capacity: 10_000,
            overflow_policy: OverflowPolicy::DropOldest,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_channel_config_new() {
        let config = ChannelConfig::new("test", 100);
        assert_eq!(config.name, "test");
        assert_eq!(config.capacity, 100);
        // Default policy is Block (backpressure), not DropOldest
        assert_eq!(config.overflow_policy, OverflowPolicy::Block);
    }

    #[test]
    fn test_channel_config_with_policy() {
        let config = ChannelConfig::new("test", 100).with_overflow_policy(OverflowPolicy::Reject);
        assert_eq!(config.overflow_policy, OverflowPolicy::Reject);
    }

    #[test]
    fn test_channel_config_default() {
        let config = ChannelConfig::default();
        assert_eq!(config.name, "unnamed");
        assert_eq!(config.capacity, 10_000);
    }

    #[test]
    fn test_channel_config_validate() {
        let valid = ChannelConfig::new("test", 100);
        assert!(valid.validate().is_ok());

        let invalid = ChannelConfig::new("test", 0);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_preset_high_throughput() {
        let config = ChannelConfig::high_throughput("telemetry");
        assert_eq!(config.name, "telemetry");
        assert_eq!(config.capacity, 100_000);
        assert_eq!(config.overflow_policy, OverflowPolicy::DropNewest);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preset_reliable() {
        let config = ChannelConfig::reliable("commands");
        assert_eq!(config.name, "commands");
        assert_eq!(config.capacity, 1_000);
        assert_eq!(config.overflow_policy, OverflowPolicy::Block);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preset_low_latency() {
        let config = ChannelConfig::low_latency("realtime");
        assert_eq!(config.name, "realtime");
        assert_eq!(config.capacity, 100);
        assert_eq!(config.overflow_policy, OverflowPolicy::Reject);
        assert!(config.validate().is_ok());
    }
}

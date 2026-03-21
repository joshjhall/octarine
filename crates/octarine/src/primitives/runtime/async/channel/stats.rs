//! Channel statistics
//!
//! Statistics and health metrics for bounded channels.

use crate::primitives::{Problem, Result};

/// Statistics for a bounded channel
///
/// Provides a snapshot of current channel state and counters.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::channel::ChannelStats;
///
/// let stats = ChannelStats {
///     capacity: 100,
///     current_size: 50,
///     total_sent: 1000,
///     total_dropped: 5,
///     total_rejected: 10,
/// };
///
/// assert_eq!(stats.utilization(), 0.5);
/// assert_eq!(stats.drop_rate(), 0.005);
/// ```
#[derive(Debug, Clone)]
pub struct ChannelStats {
    /// Maximum capacity of the channel
    pub capacity: usize,

    /// Current number of items in the channel
    pub current_size: usize,

    /// Total number of items successfully sent
    pub total_sent: usize,

    /// Total number of items dropped (DropOldest/DropNewest policies)
    pub total_dropped: usize,

    /// Total number of items rejected (Reject policy when full)
    pub total_rejected: usize,
}

impl ChannelStats {
    /// Get current utilization as a fraction (0.0 to 1.0)
    pub fn utilization(&self) -> f64 {
        if self.capacity == 0 {
            0.0
        } else {
            self.current_size as f64 / self.capacity as f64
        }
    }

    /// Check if channel is at capacity
    pub fn is_full(&self) -> bool {
        self.current_size >= self.capacity
    }

    /// Check if channel is empty
    pub fn is_empty(&self) -> bool {
        self.current_size == 0
    }

    /// Get drop rate as a fraction of total attempts
    pub fn drop_rate(&self) -> f64 {
        let total_attempts = self
            .total_sent
            .saturating_add(self.total_dropped)
            .saturating_add(self.total_rejected);
        if total_attempts == 0 {
            0.0
        } else {
            self.total_dropped as f64 / total_attempts as f64
        }
    }

    /// Get rejection rate as a fraction of total attempts
    pub fn rejection_rate(&self) -> f64 {
        let total_attempts = self
            .total_sent
            .saturating_add(self.total_dropped)
            .saturating_add(self.total_rejected);
        if total_attempts == 0 {
            0.0
        } else {
            self.total_rejected as f64 / total_attempts as f64
        }
    }

    /// Get success rate as a fraction of total attempts
    pub fn success_rate(&self) -> f64 {
        let total_attempts = self
            .total_sent
            .saturating_add(self.total_dropped)
            .saturating_add(self.total_rejected);
        if total_attempts == 0 {
            1.0
        } else {
            self.total_sent as f64 / total_attempts as f64
        }
    }

    /// Get total number of failed operations (dropped + rejected)
    pub fn total_failed(&self) -> usize {
        self.total_dropped.saturating_add(self.total_rejected)
    }

    /// Validate the statistics for consistency
    ///
    /// Checks for invalid states that indicate corruption or misuse.
    /// This is primarily for debugging and testing purposes.
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if:
    /// - `current_size` exceeds `capacity` (invalid state)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::channel::ChannelStats;
    ///
    /// // Valid stats
    /// let stats = ChannelStats {
    ///     capacity: 100,
    ///     current_size: 50,
    ///     total_sent: 100,
    ///     total_dropped: 0,
    ///     total_rejected: 0,
    /// };
    /// assert!(stats.validate().is_ok());
    ///
    /// // Invalid - current_size > capacity
    /// let invalid = ChannelStats {
    ///     capacity: 100,
    ///     current_size: 150,
    ///     total_sent: 0,
    ///     total_dropped: 0,
    ///     total_rejected: 0,
    /// };
    /// assert!(invalid.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<()> {
        if self.current_size > self.capacity {
            return Err(Problem::Validation(format!(
                "current_size ({}) exceeds capacity ({}) - invalid state",
                self.current_size, self.capacity
            )));
        }

        Ok(())
    }

    /// Calculate a health score from 0.0 (unhealthy) to 1.0 (healthy)
    ///
    /// The score is based on:
    /// - Success rate (primary factor)
    /// - Inverse utilization (secondary factor, 20% weight)
    ///
    /// Higher scores indicate better channel health.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::channel::ChannelStats;
    ///
    /// let stats = ChannelStats {
    ///     capacity: 100,
    ///     current_size: 20,
    ///     total_sent: 100,
    ///     total_dropped: 0,
    ///     total_rejected: 0,
    /// };
    /// let score = stats.health_score();
    /// assert!(score > 0.9); // High success rate, low utilization
    /// ```
    pub fn health_score(&self) -> f64 {
        // Success rate is primary factor (80% weight)
        let success_factor = self.success_rate() * 0.8;

        // Inverse utilization is secondary factor (20% weight)
        // Lower utilization = better health
        let utilization_factor = (1.0 - self.utilization()) * 0.2;

        success_factor + utilization_factor
    }

    /// Check if the channel is in a degraded state
    ///
    /// A channel is considered degraded if:
    /// - Utilization is above 80%, OR
    /// - Drop rate is above 5%, OR
    /// - Rejection rate is above 5%
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::channel::ChannelStats;
    ///
    /// let stats = ChannelStats {
    ///     capacity: 100,
    ///     current_size: 90, // 90% utilization
    ///     total_sent: 100,
    ///     total_dropped: 0,
    ///     total_rejected: 0,
    /// };
    /// assert!(stats.is_degraded()); // High utilization
    /// ```
    pub fn is_degraded(&self) -> bool {
        self.utilization() > 0.8 || self.drop_rate() > 0.05 || self.rejection_rate() > 0.05
    }

    /// Estimate throughput based on success rate
    ///
    /// Returns a value from 0.0 to 1.0 indicating effective throughput
    /// relative to attempted operations. This is essentially the success rate
    /// but semantically represents how much work is actually getting through.
    pub fn effective_throughput(&self) -> f64 {
        self.success_rate()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_utilization() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 50,
            total_sent: 0,
            total_dropped: 0,
            total_rejected: 0,
        };
        assert!((stats.utilization() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_utilization_zero_capacity() {
        let stats = ChannelStats {
            capacity: 0,
            current_size: 0,
            total_sent: 0,
            total_dropped: 0,
            total_rejected: 0,
        };
        assert_eq!(stats.utilization(), 0.0);
    }

    #[test]
    fn test_is_full() {
        let full = ChannelStats {
            capacity: 10,
            current_size: 10,
            total_sent: 0,
            total_dropped: 0,
            total_rejected: 0,
        };
        assert!(full.is_full());

        let not_full = ChannelStats {
            capacity: 10,
            current_size: 5,
            total_sent: 0,
            total_dropped: 0,
            total_rejected: 0,
        };
        assert!(!not_full.is_full());
    }

    #[test]
    fn test_is_empty() {
        let empty = ChannelStats {
            capacity: 10,
            current_size: 0,
            total_sent: 0,
            total_dropped: 0,
            total_rejected: 0,
        };
        assert!(empty.is_empty());

        let not_empty = ChannelStats {
            capacity: 10,
            current_size: 1,
            total_sent: 0,
            total_dropped: 0,
            total_rejected: 0,
        };
        assert!(!not_empty.is_empty());
    }

    #[test]
    fn test_drop_rate() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 0,
            total_sent: 90,
            total_dropped: 10,
            total_rejected: 0,
        };
        assert!((stats.drop_rate() - 0.1).abs() < 0.001);
    }

    #[test]
    fn test_rejection_rate() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 0,
            total_sent: 80,
            total_dropped: 0,
            total_rejected: 20,
        };
        assert!((stats.rejection_rate() - 0.2).abs() < 0.001);
    }

    #[test]
    fn test_success_rate() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 0,
            total_sent: 80,
            total_dropped: 10,
            total_rejected: 10,
        };
        assert!((stats.success_rate() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_rates_zero_attempts() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 0,
            total_sent: 0,
            total_dropped: 0,
            total_rejected: 0,
        };
        assert_eq!(stats.drop_rate(), 0.0);
        assert_eq!(stats.rejection_rate(), 0.0);
        assert_eq!(stats.success_rate(), 1.0);
    }

    #[test]
    fn test_total_failed() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 0,
            total_sent: 80,
            total_dropped: 10,
            total_rejected: 5,
        };
        assert_eq!(stats.total_failed(), 15);
    }

    #[test]
    fn test_stats_clone() {
        let stats1 = ChannelStats {
            capacity: 100,
            current_size: 50,
            total_sent: 1000,
            total_dropped: 5,
            total_rejected: 10,
        };
        let stats2 = stats1.clone();
        assert_eq!(stats1.capacity, stats2.capacity);
        assert_eq!(stats1.total_sent, stats2.total_sent);
    }

    #[test]
    fn test_stats_validate_valid() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 50,
            total_sent: 1000,
            total_dropped: 5,
            total_rejected: 10,
        };
        assert!(stats.validate().is_ok());
    }

    #[test]
    fn test_stats_validate_at_capacity() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 100,
            total_sent: 0,
            total_dropped: 0,
            total_rejected: 0,
        };
        assert!(stats.validate().is_ok());
    }

    #[test]
    fn test_stats_validate_exceeds_capacity() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 150,
            total_sent: 0,
            total_dropped: 0,
            total_rejected: 0,
        };
        let result = stats.validate();
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error")
                .to_string()
                .contains("exceeds capacity")
        );
    }

    #[test]
    fn test_stats_zero_capacity() {
        // Zero capacity channel - edge case
        let stats = ChannelStats {
            capacity: 0,
            current_size: 0,
            total_sent: 0,
            total_dropped: 0,
            total_rejected: 0,
        };
        assert!(stats.validate().is_ok());
        assert_eq!(stats.utilization(), 0.0);
        assert!(stats.is_full()); // 0 >= 0
        assert!(stats.is_empty());
    }

    #[test]
    fn test_stats_large_values() {
        // Very large values - near overflow
        let stats = ChannelStats {
            capacity: usize::MAX,
            current_size: usize::MAX / 2,
            total_sent: usize::MAX,
            total_dropped: usize::MAX / 4,
            total_rejected: usize::MAX / 4,
        };
        assert!(stats.validate().is_ok());
        // total_failed should saturate, not overflow
        let failed = stats.total_failed();
        assert!(failed > 0);
    }

    #[test]
    fn test_rates_at_extremes() {
        // All dropped
        let stats = ChannelStats {
            capacity: 100,
            current_size: 0,
            total_sent: 0,
            total_dropped: 100,
            total_rejected: 0,
        };
        assert_eq!(stats.drop_rate(), 1.0);
        assert_eq!(stats.success_rate(), 0.0);

        // All rejected
        let stats = ChannelStats {
            capacity: 100,
            current_size: 0,
            total_sent: 0,
            total_dropped: 0,
            total_rejected: 100,
        };
        assert_eq!(stats.rejection_rate(), 1.0);
        assert_eq!(stats.success_rate(), 0.0);

        // All successful
        let stats = ChannelStats {
            capacity: 100,
            current_size: 0,
            total_sent: 100,
            total_dropped: 0,
            total_rejected: 0,
        };
        assert_eq!(stats.success_rate(), 1.0);
        assert_eq!(stats.drop_rate(), 0.0);
        assert_eq!(stats.rejection_rate(), 0.0);
    }

    #[test]
    fn test_health_score_perfect() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 0,
            total_sent: 100,
            total_dropped: 0,
            total_rejected: 0,
        };
        // 100% success + 0% utilization = 0.8 + 0.2 = 1.0
        assert!((stats.health_score() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_health_score_degraded() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 100, // 100% utilization
            total_sent: 50,
            total_dropped: 50,
            total_rejected: 0,
        };
        // 50% success = 0.4, 0% inverse utilization = 0.0
        let score = stats.health_score();
        assert!((score - 0.4).abs() < 0.001);
    }

    #[test]
    fn test_is_degraded_high_utilization() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 85, // 85% utilization
            total_sent: 100,
            total_dropped: 0,
            total_rejected: 0,
        };
        assert!(stats.is_degraded());
    }

    #[test]
    fn test_is_degraded_high_drop_rate() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 10,
            total_sent: 90,
            total_dropped: 10, // 10% drop rate
            total_rejected: 0,
        };
        assert!(stats.is_degraded());
    }

    #[test]
    fn test_is_degraded_high_rejection_rate() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 10,
            total_sent: 90,
            total_dropped: 0,
            total_rejected: 10, // 10% rejection rate
        };
        assert!(stats.is_degraded());
    }

    #[test]
    fn test_is_not_degraded() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 50, // 50% utilization
            total_sent: 96,
            total_dropped: 2,  // 2% drop
            total_rejected: 2, // 2% rejection
        };
        assert!(!stats.is_degraded());
    }

    #[test]
    fn test_effective_throughput() {
        let stats = ChannelStats {
            capacity: 100,
            current_size: 0,
            total_sent: 80,
            total_dropped: 10,
            total_rejected: 10,
        };
        assert!((stats.effective_throughput() - 0.8).abs() < 0.001);
    }
}

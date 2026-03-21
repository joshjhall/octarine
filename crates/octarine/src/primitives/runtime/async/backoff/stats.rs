//! Retry statistics
//!
//! Statistics capturing metrics about retry attempts.

use std::time::Duration;

/// Statistics from a retry operation
///
/// Captures metrics about retry attempts including timing, success/failure counts,
/// and individual attempt durations. This is returned as part of `RetryOutcome`.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::backoff::RetryStats;
/// use std::time::Duration;
///
/// let mut stats = RetryStats::new();
/// stats.record_attempt(Duration::from_millis(100));
/// stats.record_attempt(Duration::from_millis(50));
/// stats.mark_succeeded();
///
/// assert_eq!(stats.attempts, 2);
/// assert_eq!(stats.total_duration, Duration::from_millis(150));
/// assert!(stats.succeeded);
/// ```
#[derive(Debug, Clone, Default)]
pub struct RetryStats {
    /// Total number of attempts made
    pub attempts: u32,

    /// Total time spent across all attempts (excluding backoff delays)
    pub total_duration: Duration,

    /// Whether the operation ultimately succeeded
    pub succeeded: bool,

    /// Individual attempt durations
    pub attempt_durations: Vec<Duration>,
}

impl RetryStats {
    /// Create new empty stats
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an attempt duration
    pub fn record_attempt(&mut self, duration: Duration) {
        self.attempts = self.attempts.saturating_add(1);
        self.total_duration = self.total_duration.saturating_add(duration);
        self.attempt_durations.push(duration);
    }

    /// Mark the operation as succeeded
    pub fn mark_succeeded(&mut self) {
        self.succeeded = true;
    }

    /// Get the average attempt duration
    #[must_use]
    pub fn average_duration(&self) -> Option<Duration> {
        if self.attempts == 0 {
            None
        } else {
            // Division is safe: we checked attempts != 0 above
            #[allow(clippy::arithmetic_side_effects)]
            Some(self.total_duration / self.attempts)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_retry_stats_new() {
        let stats = RetryStats::new();

        assert_eq!(stats.attempts, 0);
        assert_eq!(stats.total_duration, Duration::ZERO);
        assert!(!stats.succeeded);
        assert!(stats.attempt_durations.is_empty());
    }

    #[test]
    fn test_retry_stats_record_attempt() {
        let mut stats = RetryStats::new();

        stats.record_attempt(Duration::from_millis(100));
        stats.record_attempt(Duration::from_millis(200));

        assert_eq!(stats.attempts, 2);
        assert_eq!(stats.total_duration, Duration::from_millis(300));
        assert_eq!(stats.attempt_durations.len(), 2);
        assert_eq!(
            stats.attempt_durations.first(),
            Some(&Duration::from_millis(100))
        );
        assert_eq!(
            stats.attempt_durations.get(1),
            Some(&Duration::from_millis(200))
        );
    }

    #[test]
    fn test_retry_stats_mark_succeeded() {
        let mut stats = RetryStats::new();
        assert!(!stats.succeeded);

        stats.mark_succeeded();
        assert!(stats.succeeded);
    }

    #[test]
    fn test_retry_stats_average_duration() {
        let mut stats = RetryStats::new();

        // Empty stats should return None
        assert!(stats.average_duration().is_none());

        stats.record_attempt(Duration::from_millis(100));
        stats.record_attempt(Duration::from_millis(200));
        stats.record_attempt(Duration::from_millis(300));

        // Average of 100, 200, 300 = 200
        assert_eq!(stats.average_duration(), Some(Duration::from_millis(200)));
    }
}

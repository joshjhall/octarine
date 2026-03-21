//! Retry policy configuration (primitives layer)
//!
//! Defines retry behavior including number of attempts, backoff strategy,
//! and timeout settings.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with no observe dependencies.
//! The public API is `octarine::runtime::r#async::RetryPolicy`.

use std::time::Duration;

use super::strategy::BackoffStrategyCore;
use crate::primitives::{Problem, Result};

/// Internal retry policy type (primitives layer)
///
/// This is the internal representation. The public API is
/// `octarine::runtime::r#async::RetryPolicy`.
///
/// Defines the retry behavior including number of attempts, backoff strategy,
/// and timeout settings.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of attempts (including initial)
    pub max_attempts: u32,

    /// Backoff strategy between retries
    pub backoff: BackoffStrategyCore,

    /// Maximum total time for all retries
    pub max_total_time: Option<Duration>,

    /// Add jitter to prevent thundering herd
    ///
    /// When enabled, adds random variation to delays to prevent
    /// multiple clients from retrying at exactly the same time.
    pub jitter: bool,

    /// Function to determine if error is retryable
    ///
    /// By default, all errors are retryable. Customize this to
    /// skip retries for permanent errors (e.g., 4xx HTTP status).
    pub is_retryable: fn(&dyn std::error::Error) -> bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            backoff: BackoffStrategyCore::Exponential {
                base: Duration::from_millis(100),
                max: Duration::from_secs(30),
            },
            max_total_time: Some(Duration::from_secs(60)),
            jitter: true,
            is_retryable: |_| true, // Retry all errors by default
        }
    }
}

impl RetryPolicy {
    /// Create a new retry policy with fixed backoff
    pub fn fixed(attempts: u32, delay: Duration) -> Self {
        Self {
            max_attempts: attempts,
            backoff: BackoffStrategyCore::Fixed(delay),
            ..Default::default()
        }
    }

    /// Create a new retry policy with exponential backoff
    pub fn exponential(attempts: u32) -> Self {
        Self {
            max_attempts: attempts,
            ..Default::default()
        }
    }

    /// Builder-style method to set max attempts
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts;
        self
    }

    /// Builder-style method to set backoff strategy
    pub fn with_backoff(mut self, backoff: BackoffStrategyCore) -> Self {
        self.backoff = backoff;
        self
    }

    /// Builder-style method to enable/disable jitter
    pub fn with_jitter(mut self, jitter: bool) -> Self {
        self.jitter = jitter;
        self
    }

    /// Builder-style method to set max total time
    pub fn with_max_total_time(mut self, duration: Option<Duration>) -> Self {
        self.max_total_time = duration;
        self
    }

    /// Builder-style method to set retryable predicate
    pub fn with_retryable(mut self, predicate: fn(&dyn std::error::Error) -> bool) -> Self {
        self.is_retryable = predicate;
        self
    }

    /// Create a policy optimized for network calls
    ///
    /// Uses exponential backoff with jitter, appropriate for API calls.
    /// - 5 attempts
    /// - 100ms base, 30s max
    /// - Jitter enabled
    /// - 2 minute total timeout
    pub fn network() -> Self {
        Self {
            max_attempts: 5,
            backoff: BackoffStrategyCore::Exponential {
                base: Duration::from_millis(100),
                max: Duration::from_secs(30),
            },
            max_total_time: Some(Duration::from_secs(120)),
            jitter: true,
            is_retryable: |_| true,
        }
    }

    /// Create a policy optimized for database operations
    ///
    /// Fewer attempts with longer delays for database reconnection.
    /// - 3 attempts
    /// - 1s base, 10s max
    /// - Jitter enabled
    /// - 30 second total timeout
    pub fn database() -> Self {
        Self {
            max_attempts: 3,
            backoff: BackoffStrategyCore::Exponential {
                base: Duration::from_secs(1),
                max: Duration::from_secs(10),
            },
            max_total_time: Some(Duration::from_secs(30)),
            jitter: true,
            is_retryable: |_| true,
        }
    }

    /// Create a policy for quick, aggressive retries
    ///
    /// Fast retries for operations expected to succeed quickly.
    /// - 10 attempts
    /// - 10ms fixed delay
    /// - No jitter
    /// - 1 second total timeout
    pub fn aggressive() -> Self {
        Self {
            max_attempts: 10,
            backoff: BackoffStrategyCore::Fixed(Duration::from_millis(10)),
            max_total_time: Some(Duration::from_secs(1)),
            jitter: false,
            is_retryable: |_| true,
        }
    }

    /// Create a policy with no retries (fail immediately)
    ///
    /// Useful for operations that should not be retried.
    pub fn no_retry() -> Self {
        Self {
            max_attempts: 1,
            backoff: BackoffStrategyCore::Fixed(Duration::ZERO),
            max_total_time: None,
            jitter: false,
            is_retryable: |_| false,
        }
    }

    /// Validate the retry policy for correctness
    ///
    /// Checks for invalid configurations that would cause runtime failures
    /// or unexpected behavior.
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if:
    /// - `max_attempts` is 0 (would always fail without trying)
    /// - `max_total_time` is Some(Duration::ZERO) (instant timeout)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::backoff::RetryPolicy;
    ///
    /// // Valid policy
    /// let policy = RetryPolicy::default();
    /// assert!(policy.validate().is_ok());
    ///
    /// // Invalid - zero attempts
    /// let invalid = RetryPolicy::default().with_max_attempts(0);
    /// assert!(invalid.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<()> {
        if self.max_attempts == 0 {
            return Err(Problem::Validation(
                "max_attempts cannot be 0 - would always fail without trying".into(),
            ));
        }

        if let Some(max_time) = self.max_total_time
            && max_time == Duration::ZERO
        {
            return Err(Problem::Validation(
                "max_total_time cannot be zero - would cause instant timeout".into(),
            ));
        }

        Ok(())
    }

    /// Calculate the delay for a given attempt, optionally with jitter
    ///
    /// The jitter_value should be a random number between 0.0 and 1.0.
    /// If jitter is disabled in the policy, jitter_value is ignored.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::backoff::RetryPolicy;
    ///
    /// let policy = RetryPolicy::default().with_jitter(true);
    ///
    /// // With 0.0 jitter value, uses base delay
    /// let delay = policy.delay_for_attempt(0, 0.0);
    ///
    /// // With 1.0 jitter value, adds maximum jitter
    /// let delay = policy.delay_for_attempt(0, 1.0);
    /// ```
    pub fn delay_for_attempt(&self, attempt: u32, jitter_value: f64) -> Duration {
        if self.jitter {
            self.backoff.delay_with_jitter(attempt, jitter_value)
        } else {
            self.backoff.delay(attempt)
        }
    }

    /// Estimate the maximum total time for all retry attempts
    ///
    /// Calculates the worst-case total time assuming all attempts fail.
    /// This does not include jitter or the time spent executing the operation.
    ///
    /// Returns `None` if the total time would overflow or if using a Custom backoff.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::backoff::RetryPolicy;
    /// use std::time::Duration;
    ///
    /// let policy = RetryPolicy::fixed(3, Duration::from_millis(100));
    /// // 3 attempts = 2 delays (first attempt has no delay)
    /// // 2 * 100ms = 200ms
    /// assert_eq!(policy.estimated_total_time(), Some(Duration::from_millis(200)));
    /// ```
    pub fn estimated_total_time(&self) -> Option<Duration> {
        // Custom backoff cannot be estimated
        // DecorrelatedJitter returns upper bound (same as exponential)
        if matches!(self.backoff, BackoffStrategyCore::Custom(_)) {
            return None;
        }

        if self.max_attempts <= 1 {
            return Some(Duration::ZERO);
        }

        let mut total = Duration::ZERO;
        // Delays occur between attempts (N attempts = N-1 delays)
        for attempt in 0..self.max_attempts.saturating_sub(1) {
            let delay = self.backoff.delay(attempt);
            total = total.checked_add(delay)?;
        }

        // If max_total_time is set, return the minimum
        if let Some(max_time) = self.max_total_time {
            Some(std::cmp::min(total, max_time))
        } else {
            Some(total)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_policy_defaults() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_attempts, 3);
        assert!(policy.jitter);
        assert_eq!(policy.max_total_time, Some(Duration::from_secs(60)));
        // Test is_retryable returns true for any error
        let err: Box<dyn std::error::Error> = "test".into();
        assert!((policy.is_retryable)(err.as_ref()));
    }

    #[test]
    fn test_policy_fixed() {
        let policy = RetryPolicy::fixed(5, Duration::from_millis(200));
        assert_eq!(policy.max_attempts, 5);
        match policy.backoff {
            BackoffStrategyCore::Fixed(d) => assert_eq!(d, Duration::from_millis(200)),
            _ => panic!("Expected Fixed backoff"),
        }
    }

    #[test]
    fn test_policy_exponential() {
        let policy = RetryPolicy::exponential(7);
        assert_eq!(policy.max_attempts, 7);
        match policy.backoff {
            BackoffStrategyCore::Exponential { .. } => {}
            _ => panic!("Expected Exponential backoff"),
        }
    }

    #[test]
    fn test_policy_builder() {
        let policy = RetryPolicy::default()
            .with_max_attempts(10)
            .with_jitter(false)
            .with_max_total_time(Some(Duration::from_secs(120)))
            .with_backoff(BackoffStrategyCore::Linear {
                base: Duration::from_millis(50),
            });

        assert_eq!(policy.max_attempts, 10);
        assert!(!policy.jitter);
        assert_eq!(policy.max_total_time, Some(Duration::from_secs(120)));
        match policy.backoff {
            BackoffStrategyCore::Linear { base } => assert_eq!(base, Duration::from_millis(50)),
            _ => panic!("Expected Linear backoff"),
        }
    }

    #[test]
    fn test_policy_validate_default() {
        let policy = RetryPolicy::default();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_policy_validate_zero_attempts() {
        let policy = RetryPolicy::default().with_max_attempts(0);
        let result = policy.validate();
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error")
                .to_string()
                .contains("max_attempts cannot be 0")
        );
    }

    #[test]
    fn test_policy_validate_zero_total_time() {
        let policy = RetryPolicy::default().with_max_total_time(Some(Duration::ZERO));
        let result = policy.validate();
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error")
                .to_string()
                .contains("max_total_time cannot be zero")
        );
    }

    #[test]
    fn test_policy_validate_none_total_time() {
        // None for max_total_time should be valid (no timeout)
        let policy = RetryPolicy::default().with_max_total_time(None);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_policy_validate_edge_values() {
        // Very small valid values
        let policy = RetryPolicy::default()
            .with_max_attempts(1)
            .with_max_total_time(Some(Duration::from_nanos(1)));
        assert!(policy.validate().is_ok());

        // Very large values
        let policy = RetryPolicy::default()
            .with_max_attempts(u32::MAX)
            .with_max_total_time(Some(Duration::MAX));
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_estimated_total_time_fixed() {
        let policy = RetryPolicy::fixed(3, Duration::from_millis(100));
        // 3 attempts = 2 delays
        let estimated = policy.estimated_total_time();
        assert_eq!(estimated, Some(Duration::from_millis(200)));
    }

    #[test]
    fn test_estimated_total_time_exponential() {
        let policy = RetryPolicy::default()
            .with_max_attempts(4)
            .with_backoff(BackoffStrategyCore::Exponential {
                base: Duration::from_millis(100),
                max: Duration::from_secs(10),
            })
            .with_max_total_time(None);
        // 4 attempts = 3 delays: 100ms + 200ms + 400ms = 700ms
        let estimated = policy.estimated_total_time();
        assert_eq!(estimated, Some(Duration::from_millis(700)));
    }

    #[test]
    fn test_estimated_total_time_single_attempt() {
        let policy = RetryPolicy::default().with_max_attempts(1);
        // 1 attempt = no delays
        let estimated = policy.estimated_total_time();
        assert_eq!(estimated, Some(Duration::ZERO));
    }

    #[test]
    fn test_estimated_total_time_custom_backoff() {
        let policy = RetryPolicy::default()
            .with_backoff(BackoffStrategyCore::Custom(|_| Duration::from_secs(1)));
        // Custom backoff cannot be estimated
        let estimated = policy.estimated_total_time();
        assert_eq!(estimated, None);
    }

    #[test]
    fn test_estimated_total_time_capped_by_max() {
        let policy = RetryPolicy::default()
            .with_max_attempts(10)
            .with_backoff(BackoffStrategyCore::Fixed(Duration::from_secs(1)))
            .with_max_total_time(Some(Duration::from_secs(3)));
        // 10 attempts = 9 delays of 1s each = 9s, but capped at 3s
        let estimated = policy.estimated_total_time();
        assert_eq!(estimated, Some(Duration::from_secs(3)));
    }

    #[test]
    fn test_delay_for_attempt_with_jitter() {
        let policy = RetryPolicy::default().with_jitter(true);

        // With 0.0 jitter value, uses minimum multiplier (0.5x)
        let delay = policy.delay_for_attempt(0, 0.0);
        assert_eq!(delay, Duration::from_millis(50)); // 100ms * 0.5

        // With 1.0 jitter value, uses maximum multiplier (1.5x)
        let delay = policy.delay_for_attempt(0, 1.0);
        assert_eq!(delay, Duration::from_millis(150)); // 100ms * 1.5
    }

    #[test]
    fn test_delay_for_attempt_without_jitter() {
        let policy = RetryPolicy::default().with_jitter(false);

        // Without jitter, jitter_value is ignored
        let delay1 = policy.delay_for_attempt(0, 0.0);
        let delay2 = policy.delay_for_attempt(0, 1.0);
        assert_eq!(delay1, delay2);
        assert_eq!(delay1, Duration::from_millis(100));
    }
}

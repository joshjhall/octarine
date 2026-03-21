//! Backoff strategies and retry policies
//!
//! Provides configurable backoff algorithms and retry policies for resilient
//! operation execution with comprehensive logging, metrics, and error context.
//!
//! # Strategies
//!
//! - **Fixed**: Constant delay between retries
//! - **Linear**: Delay increases linearly (base * attempt)
//! - **Exponential**: Delay doubles each attempt (base * 2^attempt)
//! - **Fibonacci**: Delay follows fibonacci sequence
//! - **DecorrelatedJitter**: AWS-recommended jitter for distributed systems
//! - **Custom**: User-provided delay function
//!
//! # Examples
//!
//! ```rust
//! use octarine::runtime::r#async::{BackoffStrategy, RetryPolicy};
//! use std::time::Duration;
//!
//! // Fixed delay of 100ms
//! let fixed = BackoffStrategy::Fixed(Duration::from_millis(100));
//! assert_eq!(fixed.delay(0), Duration::from_millis(100));
//!
//! // Exponential backoff with cap
//! let exp = BackoffStrategy::Exponential {
//!     base: Duration::from_millis(100),
//!     max: Duration::from_secs(10),
//! };
//! assert_eq!(exp.delay(0), Duration::from_millis(100));
//! assert_eq!(exp.delay(3), Duration::from_millis(800));
//!
//! // Retry policy with builder
//! let policy = RetryPolicy::default()
//!     .with_max_attempts(5)
//!     .with_backoff(BackoffStrategy::Linear {
//!         base: Duration::from_millis(50),
//!     })
//!     .with_jitter(true);
//! ```

use crate::observe::{Problem, Result};
use std::time::Duration;

// =============================================================================
// BackoffStrategy
// =============================================================================

/// Backoff strategy for retries
///
/// Determines how long to wait between retry attempts. Each strategy provides
/// different delay patterns suitable for various use cases.
///
/// # Examples
///
/// ```rust
/// use octarine::runtime::r#async::BackoffStrategy;
/// use std::time::Duration;
///
/// // Fixed: Same delay every time
/// let fixed = BackoffStrategy::Fixed(Duration::from_millis(100));
///
/// // Exponential: Doubles each time up to max
/// let exp = BackoffStrategy::Exponential {
///     base: Duration::from_millis(100),
///     max: Duration::from_secs(30),
/// };
/// ```
#[derive(Debug, Clone)]
pub enum BackoffStrategy {
    /// Fixed delay between retries
    ///
    /// Always waits the same duration, regardless of attempt number.
    /// Good for simple cases where consistent timing is desired.
    Fixed(Duration),

    /// Linear backoff (delay * attempt_number)
    ///
    /// Delay increases linearly: base, 2*base, 3*base, etc.
    /// More gradual than exponential, suitable for moderate load scenarios.
    Linear {
        /// Base delay duration
        base: Duration,
    },

    /// Exponential backoff (base * 2^attempt)
    ///
    /// Delay doubles each attempt: base, 2*base, 4*base, 8*base, etc.
    /// Standard choice for distributed systems to reduce thundering herd.
    /// The `max` field caps the maximum delay.
    Exponential {
        /// Base delay duration
        base: Duration,
        /// Maximum delay cap
        max: Duration,
    },

    /// Fibonacci backoff
    ///
    /// Delay follows fibonacci sequence: base, base, 2*base, 3*base, 5*base, etc.
    /// Slower growth than exponential, faster than linear.
    Fibonacci {
        /// Base delay duration
        base: Duration,
        /// Maximum delay cap
        max: Duration,
    },

    /// Custom backoff function
    ///
    /// User-provided function that takes attempt number (0-based) and returns delay.
    /// Allows complete control over backoff timing.
    Custom(fn(u32) -> Duration),

    /// Decorrelated jitter (AWS recommended)
    ///
    /// Each delay is random between base and 3*previous_delay.
    /// This prevents thundering herd by decorrelating retry times.
    /// See: <https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/>
    ///
    /// Note: Since this is stateless, we simulate with exponential * random factor.
    /// For true decorrelated jitter, use the `delay_with_jitter` method at runtime.
    DecorrelatedJitter {
        /// Base delay duration
        base: Duration,
        /// Maximum delay cap
        max: Duration,
    },
}

impl BackoffStrategy {
    /// Calculate delay for given attempt number (0-based)
    ///
    /// Returns the duration to wait before the next retry attempt.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use octarine::runtime::r#async::BackoffStrategy;
    /// use std::time::Duration;
    ///
    /// let exp = BackoffStrategy::Exponential {
    ///     base: Duration::from_millis(100),
    ///     max: Duration::from_secs(1),
    /// };
    ///
    /// assert_eq!(exp.delay(0), Duration::from_millis(100));
    /// assert_eq!(exp.delay(2), Duration::from_millis(400));
    /// assert_eq!(exp.delay(10), Duration::from_secs(1)); // Capped at max
    /// ```
    pub fn delay(&self, attempt: u32) -> Duration {
        match self {
            BackoffStrategy::Fixed(d) => *d,

            BackoffStrategy::Linear { base } => base.saturating_mul(attempt.saturating_add(1)),

            BackoffStrategy::Exponential { base, max } => {
                let delay = base.saturating_mul(2_u32.saturating_pow(attempt));
                std::cmp::min(delay, *max)
            }

            BackoffStrategy::Fibonacci { base, max } => {
                let fib = Self::fibonacci(attempt.saturating_add(1));
                let delay = base.saturating_mul(fib);
                std::cmp::min(delay, *max)
            }

            BackoffStrategy::Custom(f) => f(attempt),

            BackoffStrategy::DecorrelatedJitter { base, max } => {
                // For deterministic behavior without state, we use exponential
                // as the "expected" value. True decorrelated jitter needs state.
                let delay = base.saturating_mul(2_u32.saturating_pow(attempt));
                std::cmp::min(delay, *max)
            }
        }
    }

    /// Calculate delay with jitter applied
    ///
    /// Adds random jitter to the base delay to prevent thundering herd.
    /// The jitter factor is between 0.5 and 1.5 of the base delay.
    ///
    /// # Arguments
    ///
    /// * `attempt` - The attempt number (0-based)
    /// * `jitter_factor` - A value between 0.0 and 1.0 representing randomness
    pub fn delay_with_jitter(&self, attempt: u32, jitter_factor: f64) -> Duration {
        let base_delay = self.delay(attempt);

        // Clamp jitter factor to 0.0-1.0
        let factor = jitter_factor.clamp(0.0, 1.0);

        // Apply jitter: delay * (0.5 + factor)
        // This gives range of 0.5x to 1.5x the base delay
        let multiplier = 0.5 + factor;
        let nanos = base_delay.as_nanos() as f64 * multiplier;

        Duration::from_nanos(nanos as u64)
    }

    /// Calculate fibonacci number (internal helper)
    fn fibonacci(n: u32) -> u32 {
        match n {
            0 => 0,
            1 => 1,
            _ => {
                let mut a: u32 = 0;
                let mut b: u32 = 1;
                for _ in 2..=n {
                    let tmp = a.saturating_add(b);
                    a = b;
                    b = tmp;
                }
                b
            }
        }
    }
}

impl Default for BackoffStrategy {
    /// Default backoff strategy: Exponential with 100ms base and 30s max
    ///
    /// This is the recommended default for most distributed systems as it
    /// provides good protection against thundering herd while allowing
    /// quick retries initially.
    fn default() -> Self {
        Self::Exponential {
            base: Duration::from_millis(100),
            max: Duration::from_secs(30),
        }
    }
}

// =============================================================================
// RetryPolicy
// =============================================================================

/// Retry policy configuration
///
/// Defines the retry behavior including number of attempts, backoff strategy,
/// and timeout settings.
///
/// # Examples
///
/// ```rust
/// use octarine::runtime::r#async::{BackoffStrategy, RetryPolicy};
/// use std::time::Duration;
///
/// // Default policy: 3 attempts, exponential backoff
/// let default = RetryPolicy::default();
///
/// // Fixed delay policy
/// let fixed = RetryPolicy::fixed(5, Duration::from_millis(200));
///
/// // Custom policy with builder
/// let custom = RetryPolicy::default()
///     .with_max_attempts(10)
///     .with_jitter(true);
/// ```
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of attempts (including initial)
    pub max_attempts: u32,

    /// Backoff strategy between retries
    pub backoff: BackoffStrategy,

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
            backoff: BackoffStrategy::Exponential {
                base: Duration::from_millis(100),
                max: Duration::from_secs(30),
            },
            max_total_time: Some(Duration::from_secs(60)),
            jitter: true,
            is_retryable: |_| true,
        }
    }
}

impl RetryPolicy {
    /// Create a new retry policy with fixed backoff
    pub fn fixed(attempts: u32, delay: Duration) -> Self {
        Self {
            max_attempts: attempts,
            backoff: BackoffStrategy::Fixed(delay),
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
    pub fn with_backoff(mut self, backoff: BackoffStrategy) -> Self {
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
            backoff: BackoffStrategy::Exponential {
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
            backoff: BackoffStrategy::Exponential {
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
            backoff: BackoffStrategy::Fixed(Duration::from_millis(10)),
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
            backoff: BackoffStrategy::Fixed(Duration::ZERO),
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
    pub fn estimated_total_time(&self) -> Option<Duration> {
        // Custom backoff cannot be estimated
        if matches!(self.backoff, BackoffStrategy::Custom(_)) {
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

    // BackoffStrategy tests

    #[test]
    fn test_fixed_backoff() {
        let fixed = BackoffStrategy::Fixed(Duration::from_millis(100));
        assert_eq!(fixed.delay(0), Duration::from_millis(100));
        assert_eq!(fixed.delay(5), Duration::from_millis(100));
    }

    #[test]
    fn test_exponential_backoff() {
        let exp = BackoffStrategy::Exponential {
            base: Duration::from_millis(100),
            max: Duration::from_secs(1),
        };
        assert_eq!(exp.delay(0), Duration::from_millis(100));
        assert_eq!(exp.delay(1), Duration::from_millis(200));
        assert_eq!(exp.delay(2), Duration::from_millis(400));
        assert_eq!(exp.delay(10), Duration::from_secs(1)); // Capped
    }

    #[test]
    fn test_linear_backoff() {
        let linear = BackoffStrategy::Linear {
            base: Duration::from_millis(100),
        };
        assert_eq!(linear.delay(0), Duration::from_millis(100));
        assert_eq!(linear.delay(1), Duration::from_millis(200));
        assert_eq!(linear.delay(2), Duration::from_millis(300));
    }

    #[test]
    fn test_backoff_default() {
        let default = BackoffStrategy::default();
        assert_eq!(default.delay(0), Duration::from_millis(100));
    }

    // RetryPolicy tests

    #[test]
    fn test_policy_defaults() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_attempts, 3);
        assert!(policy.jitter);
        assert_eq!(policy.max_total_time, Some(Duration::from_secs(60)));
    }

    #[test]
    fn test_policy_fixed() {
        let policy = RetryPolicy::fixed(5, Duration::from_millis(200));
        assert_eq!(policy.max_attempts, 5);
        match policy.backoff {
            BackoffStrategy::Fixed(d) => assert_eq!(d, Duration::from_millis(200)),
            _ => panic!("Expected Fixed backoff"),
        }
    }

    #[test]
    fn test_policy_builder() {
        let policy = RetryPolicy::default()
            .with_max_attempts(10)
            .with_jitter(false)
            .with_backoff(BackoffStrategy::Linear {
                base: Duration::from_millis(50),
            });

        assert_eq!(policy.max_attempts, 10);
        assert!(!policy.jitter);
    }

    #[test]
    fn test_policy_validate() {
        assert!(RetryPolicy::default().validate().is_ok());
        assert!(
            RetryPolicy::default()
                .with_max_attempts(0)
                .validate()
                .is_err()
        );
        assert!(
            RetryPolicy::default()
                .with_max_total_time(Some(Duration::ZERO))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn test_estimated_total_time() {
        let policy = RetryPolicy::fixed(3, Duration::from_millis(100));
        // 3 attempts = 2 delays
        assert_eq!(
            policy.estimated_total_time(),
            Some(Duration::from_millis(200))
        );
    }

    #[test]
    fn test_preset_policies() {
        let _network = RetryPolicy::network();
        let _db = RetryPolicy::database();
        let _aggressive = RetryPolicy::aggressive();
        let _no_retry = RetryPolicy::no_retry();
    }
}

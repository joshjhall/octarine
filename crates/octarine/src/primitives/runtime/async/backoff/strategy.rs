//! Backoff strategies for retry operations (primitives layer)
//!
//! Provides various backoff algorithms for calculating retry delays.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with no observe dependencies.
//! The public API is `octarine::runtime::r#async::BackoffStrategy`.

use std::time::Duration;

/// Backoff strategy type (primitives layer)
///
/// Determines how long to wait between retry attempts. Each strategy provides
/// different delay patterns suitable for various use cases.
///
/// The public API re-exports this as `octarine::runtime::r#async::BackoffStrategy`.
#[derive(Debug, Clone)]
pub enum BackoffStrategyCore {
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

#[allow(dead_code)] // Internal API - not all methods used in primitives
impl BackoffStrategyCore {
    /// Calculate delay for given attempt number (0-based)
    ///
    /// Returns the duration to wait before the next retry attempt.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::backoff::BackoffStrategy;
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
            BackoffStrategyCore::Fixed(d) => *d,

            BackoffStrategyCore::Linear { base } => base.saturating_mul(attempt.saturating_add(1)),

            BackoffStrategyCore::Exponential { base, max } => {
                let delay = base.saturating_mul(2_u32.saturating_pow(attempt));
                std::cmp::min(delay, *max)
            }

            BackoffStrategyCore::Fibonacci { base, max } => {
                let fib = Self::fibonacci(attempt.saturating_add(1));
                let delay = base.saturating_mul(fib);
                std::cmp::min(delay, *max)
            }

            BackoffStrategyCore::Custom(f) => f(attempt),

            BackoffStrategyCore::DecorrelatedJitter { base, max } => {
                // For deterministic behavior without state, we use exponential
                // as the "expected" value. True decorrelated jitter needs state.
                // This gives the upper bound of what the delay could be.
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
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::backoff::BackoffStrategy;
    /// use std::time::Duration;
    ///
    /// let exp = BackoffStrategy::Exponential {
    ///     base: Duration::from_millis(100),
    ///     max: Duration::from_secs(10),
    /// };
    ///
    /// // With 50% jitter factor, delay is between 50ms and 150ms for attempt 0
    /// let delay = exp.delay_with_jitter(0, 0.5);
    /// ```
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

    /// Calculate fibonacci number
    ///
    /// Uses iterative approach to avoid stack overflow for large n.
    pub(crate) fn fibonacci(n: u32) -> u32 {
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

impl Default for BackoffStrategyCore {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_fixed_backoff() {
        let fixed = BackoffStrategyCore::Fixed(Duration::from_millis(100));
        assert_eq!(fixed.delay(0), Duration::from_millis(100));
        assert_eq!(fixed.delay(5), Duration::from_millis(100));
        assert_eq!(fixed.delay(100), Duration::from_millis(100));
    }

    #[test]
    fn test_backoff_strategy_default() {
        let default = BackoffStrategyCore::default();
        // Default is exponential with 100ms base, 30s max
        assert_eq!(default.delay(0), Duration::from_millis(100));
        assert_eq!(default.delay(1), Duration::from_millis(200));
        assert_eq!(default.delay(2), Duration::from_millis(400));
        // Should be capped at 30s for high attempt numbers
        assert!(default.delay(100) <= Duration::from_secs(30));
    }

    #[test]
    fn test_linear_backoff() {
        let linear = BackoffStrategyCore::Linear {
            base: Duration::from_millis(100),
        };
        assert_eq!(linear.delay(0), Duration::from_millis(100)); // 1 * 100
        assert_eq!(linear.delay(1), Duration::from_millis(200)); // 2 * 100
        assert_eq!(linear.delay(2), Duration::from_millis(300)); // 3 * 100
        assert_eq!(linear.delay(9), Duration::from_millis(1000)); // 10 * 100
    }

    #[test]
    fn test_exponential_backoff() {
        let exp = BackoffStrategyCore::Exponential {
            base: Duration::from_millis(100),
            max: Duration::from_secs(1),
        };
        assert_eq!(exp.delay(0), Duration::from_millis(100)); // 100 * 2^0
        assert_eq!(exp.delay(1), Duration::from_millis(200)); // 100 * 2^1
        assert_eq!(exp.delay(2), Duration::from_millis(400)); // 100 * 2^2
        assert_eq!(exp.delay(3), Duration::from_millis(800)); // 100 * 2^3
        assert_eq!(exp.delay(10), Duration::from_secs(1)); // Capped at max
    }

    #[test]
    fn test_fibonacci_backoff() {
        let fib = BackoffStrategyCore::Fibonacci {
            base: Duration::from_millis(100),
            max: Duration::from_secs(10),
        };
        // Fibonacci: 1, 1, 2, 3, 5, 8, 13...
        assert_eq!(fib.delay(0), Duration::from_millis(100)); // fib(1) = 1
        assert_eq!(fib.delay(1), Duration::from_millis(100)); // fib(2) = 1
        assert_eq!(fib.delay(2), Duration::from_millis(200)); // fib(3) = 2
        assert_eq!(fib.delay(3), Duration::from_millis(300)); // fib(4) = 3
        assert_eq!(fib.delay(4), Duration::from_millis(500)); // fib(5) = 5
    }

    #[test]
    fn test_custom_backoff() {
        let custom =
            BackoffStrategyCore::Custom(|attempt| Duration::from_millis((attempt * 50) as u64));
        assert_eq!(custom.delay(0), Duration::from_millis(0));
        assert_eq!(custom.delay(2), Duration::from_millis(100));
        assert_eq!(custom.delay(10), Duration::from_millis(500));
    }

    #[test]
    fn test_decorrelated_jitter_backoff() {
        let jitter = BackoffStrategyCore::DecorrelatedJitter {
            base: Duration::from_millis(100),
            max: Duration::from_secs(10),
        };
        // Acts like exponential for upper bound
        assert_eq!(jitter.delay(0), Duration::from_millis(100));
        assert_eq!(jitter.delay(1), Duration::from_millis(200));
        assert_eq!(jitter.delay(2), Duration::from_millis(400));
        // Capped at max
        assert_eq!(jitter.delay(20), Duration::from_secs(10));
    }

    #[test]
    fn test_delay_with_jitter() {
        let exp = BackoffStrategyCore::Exponential {
            base: Duration::from_millis(100),
            max: Duration::from_secs(10),
        };

        // With jitter_factor = 0.0, delay is 0.5x base
        let delay = exp.delay_with_jitter(0, 0.0);
        assert_eq!(delay, Duration::from_millis(50));

        // With jitter_factor = 1.0, delay is 1.5x base
        let delay = exp.delay_with_jitter(0, 1.0);
        assert_eq!(delay, Duration::from_millis(150));

        // With jitter_factor = 0.5, delay is 1.0x base
        let delay = exp.delay_with_jitter(0, 0.5);
        assert_eq!(delay, Duration::from_millis(100));
    }

    #[test]
    fn test_delay_with_jitter_clamping() {
        let fixed = BackoffStrategyCore::Fixed(Duration::from_millis(100));

        // Jitter factor clamped to 0.0-1.0
        let delay = fixed.delay_with_jitter(0, -1.0);
        assert_eq!(delay, Duration::from_millis(50)); // Clamped to 0.0

        let delay = fixed.delay_with_jitter(0, 2.0);
        assert_eq!(delay, Duration::from_millis(150)); // Clamped to 1.0
    }

    #[test]
    fn test_fibonacci_algorithm() {
        assert_eq!(BackoffStrategyCore::fibonacci(0), 0);
        assert_eq!(BackoffStrategyCore::fibonacci(1), 1);
        assert_eq!(BackoffStrategyCore::fibonacci(2), 1);
        assert_eq!(BackoffStrategyCore::fibonacci(3), 2);
        assert_eq!(BackoffStrategyCore::fibonacci(4), 3);
        assert_eq!(BackoffStrategyCore::fibonacci(5), 5);
        assert_eq!(BackoffStrategyCore::fibonacci(10), 55);
    }

    #[test]
    fn test_backoff_saturation() {
        // Test that saturating operations don't overflow
        let exp = BackoffStrategyCore::Exponential {
            base: Duration::from_secs(u64::MAX),
            max: Duration::from_secs(30),
        };
        // Should be capped at max
        assert_eq!(exp.delay(100), Duration::from_secs(30));

        let linear = BackoffStrategyCore::Linear {
            base: Duration::from_secs(u64::MAX),
        };
        // Should saturate instead of overflowing
        let delay = linear.delay(u32::MAX);
        assert!(delay >= Duration::from_secs(1)); // Some non-zero value
    }

    #[test]
    fn test_backoff_zero_duration_base() {
        // Zero duration base should still work (immediate retries)
        let fixed = BackoffStrategyCore::Fixed(Duration::ZERO);
        assert_eq!(fixed.delay(0), Duration::ZERO);
        assert_eq!(fixed.delay(100), Duration::ZERO);

        let linear = BackoffStrategyCore::Linear {
            base: Duration::ZERO,
        };
        assert_eq!(linear.delay(0), Duration::ZERO);
        assert_eq!(linear.delay(100), Duration::ZERO);

        let exp = BackoffStrategyCore::Exponential {
            base: Duration::ZERO,
            max: Duration::from_secs(10),
        };
        assert_eq!(exp.delay(0), Duration::ZERO);
        assert_eq!(exp.delay(100), Duration::ZERO);
    }

    #[test]
    fn test_fibonacci_large_numbers() {
        // Ensure fibonacci doesn't overflow for reasonable attempts
        let fib = BackoffStrategyCore::Fibonacci {
            base: Duration::from_millis(100),
            max: Duration::from_secs(60),
        };

        // Should cap at max for large attempt numbers
        let delay = fib.delay(50);
        assert_eq!(delay, Duration::from_secs(60));
    }
}

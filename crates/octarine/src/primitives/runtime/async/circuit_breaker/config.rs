//! Circuit breaker configuration
//!
//! Controls the thresholds and timings for circuit breaker behavior.

use std::time::Duration;

use crate::primitives::{Problem, Result};

/// Configuration for circuit breaker
///
/// Controls the thresholds and timings for circuit breaker behavior.
/// Use the builder methods for convenient configuration.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::circuit_breaker::CircuitBreakerConfig;
/// use std::time::Duration;
///
/// // Default configuration
/// let default = CircuitBreakerConfig::default();
///
/// // Custom configuration with builder
/// let custom = CircuitBreakerConfig::default()
///     .with_failure_threshold(3)
///     .with_reset_timeout(Duration::from_secs(60));
/// ```
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    ///
    /// When failure count reaches this threshold within the window,
    /// the circuit opens and rejects all requests.
    pub failure_threshold: u32,

    /// Success rate threshold (0.0 to 1.0)
    ///
    /// In HalfOpen state, when success rate reaches this threshold
    /// (after min_requests), the circuit closes.
    pub success_threshold: f32,

    /// Time window for counting failures
    ///
    /// Failures are counted within this rolling window.
    /// When the window expires, counts are reset.
    pub window_duration: Duration,

    /// How long to wait before trying half-open
    ///
    /// After opening, the circuit waits this long before
    /// transitioning to HalfOpen to test recovery.
    pub reset_timeout: Duration,

    /// Minimum number of requests before evaluating
    ///
    /// In HalfOpen state, wait for this many requests before
    /// evaluating success rate to make a decision.
    pub min_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 0.5,
            window_duration: Duration::from_secs(60),
            reset_timeout: Duration::from_secs(30),
            min_requests: 10,
        }
    }
}

impl CircuitBreakerConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style method to set failure threshold
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::circuit_breaker::CircuitBreakerConfig;
    ///
    /// let config = CircuitBreakerConfig::new().with_failure_threshold(3);
    /// assert_eq!(config.failure_threshold, 3);
    /// ```
    pub fn with_failure_threshold(mut self, threshold: u32) -> Self {
        self.failure_threshold = threshold;
        self
    }

    /// Builder-style method to set success threshold
    ///
    /// Value should be between 0.0 and 1.0.
    pub fn with_success_threshold(mut self, threshold: f32) -> Self {
        self.success_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Builder-style method to set window duration
    pub fn with_window_duration(mut self, duration: Duration) -> Self {
        self.window_duration = duration;
        self
    }

    /// Builder-style method to set reset timeout
    pub fn with_reset_timeout(mut self, duration: Duration) -> Self {
        self.reset_timeout = duration;
        self
    }

    /// Builder-style method to set minimum requests
    pub fn with_min_requests(mut self, min: u32) -> Self {
        self.min_requests = min;
        self
    }

    /// Validate the configuration for correctness
    ///
    /// Checks for invalid configurations that would cause runtime failures
    /// or unexpected behavior in the circuit breaker.
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if:
    /// - `failure_threshold` is 0 (circuit would always be open)
    /// - `min_requests` is 0 (division by zero in success rate calculation)
    /// - `reset_timeout` is zero (defeats purpose of circuit breaker)
    /// - `window_duration` is zero (window would always be expired)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::circuit_breaker::CircuitBreakerConfig;
    ///
    /// // Valid config
    /// let config = CircuitBreakerConfig::default();
    /// assert!(config.validate().is_ok());
    ///
    /// // Invalid - zero failure threshold
    /// let invalid = CircuitBreakerConfig::new().with_failure_threshold(0);
    /// assert!(invalid.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<()> {
        if self.failure_threshold == 0 {
            return Err(Problem::Validation(
                "failure_threshold cannot be 0 - circuit would always be open".into(),
            ));
        }

        if self.min_requests == 0 {
            return Err(Problem::Validation(
                "min_requests cannot be 0 - would cause division by zero in success rate".into(),
            ));
        }

        if self.reset_timeout == Duration::ZERO {
            return Err(Problem::Validation(
                "reset_timeout cannot be zero - defeats purpose of circuit breaker".into(),
            ));
        }

        if self.window_duration == Duration::ZERO {
            return Err(Problem::Validation(
                "window_duration cannot be zero - window would always be expired".into(),
            ));
        }

        Ok(())
    }

    /// Create a high-availability configuration
    ///
    /// Quick to open (sensitive to failures), slow to recover.
    /// Good for critical services where availability is paramount.
    ///
    /// - Opens after 3 failures
    /// - Needs 80% success rate to close
    /// - 60 second reset timeout
    pub fn high_availability() -> Self {
        Self {
            failure_threshold: 3,
            success_threshold: 0.8,
            window_duration: Duration::from_secs(30),
            reset_timeout: Duration::from_secs(60),
            min_requests: 5,
        }
    }

    /// Create a fault-tolerant configuration
    ///
    /// More tolerant of failures, faster recovery.
    /// Good for non-critical services or those with expected transient failures.
    ///
    /// - Opens after 10 failures
    /// - Needs 50% success rate to close
    /// - 15 second reset timeout
    pub fn fault_tolerant() -> Self {
        Self {
            failure_threshold: 10,
            success_threshold: 0.5,
            window_duration: Duration::from_secs(60),
            reset_timeout: Duration::from_secs(15),
            min_requests: 10,
        }
    }

    /// Create an aggressive configuration
    ///
    /// Very sensitive to failures, very slow to recover.
    /// Good for services where failures are expensive or dangerous.
    ///
    /// - Opens after 1 failure
    /// - Needs 95% success rate to close
    /// - 2 minute reset timeout
    pub fn aggressive() -> Self {
        Self {
            failure_threshold: 1,
            success_threshold: 0.95,
            window_duration: Duration::from_secs(60),
            reset_timeout: Duration::from_secs(120),
            min_requests: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = CircuitBreakerConfig::default();
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.success_threshold, 0.5);
        assert_eq!(config.window_duration, Duration::from_secs(60));
        assert_eq!(config.reset_timeout, Duration::from_secs(30));
        assert_eq!(config.min_requests, 10);
    }

    #[test]
    fn test_config_builder() {
        let config = CircuitBreakerConfig::new()
            .with_failure_threshold(3)
            .with_success_threshold(0.8)
            .with_window_duration(Duration::from_secs(120))
            .with_reset_timeout(Duration::from_secs(60))
            .with_min_requests(5);

        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.success_threshold, 0.8);
        assert_eq!(config.window_duration, Duration::from_secs(120));
        assert_eq!(config.reset_timeout, Duration::from_secs(60));
        assert_eq!(config.min_requests, 5);
    }

    #[test]
    fn test_config_success_threshold_clamping() {
        let config = CircuitBreakerConfig::new().with_success_threshold(1.5);
        assert_eq!(config.success_threshold, 1.0);

        let config = CircuitBreakerConfig::new().with_success_threshold(-0.5);
        assert_eq!(config.success_threshold, 0.0);
    }

    #[test]
    fn test_config_clone() {
        let config1 = CircuitBreakerConfig::new().with_failure_threshold(7);
        let config2 = config1.clone();
        assert_eq!(config1.failure_threshold, config2.failure_threshold);
    }

    #[test]
    fn test_config_validate_default() {
        let config = CircuitBreakerConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_zero_failure_threshold() {
        let config = CircuitBreakerConfig::new().with_failure_threshold(0);
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error")
                .to_string()
                .contains("failure_threshold cannot be 0")
        );
    }

    #[test]
    fn test_config_validate_zero_min_requests() {
        let config = CircuitBreakerConfig::new().with_min_requests(0);
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error")
                .to_string()
                .contains("min_requests cannot be 0")
        );
    }

    #[test]
    fn test_config_validate_zero_reset_timeout() {
        let config = CircuitBreakerConfig::new().with_reset_timeout(Duration::ZERO);
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error")
                .to_string()
                .contains("reset_timeout cannot be zero")
        );
    }

    #[test]
    fn test_config_validate_zero_window_duration() {
        let config = CircuitBreakerConfig::new().with_window_duration(Duration::ZERO);
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error")
                .to_string()
                .contains("window_duration cannot be zero")
        );
    }

    #[test]
    fn test_config_validate_edge_values() {
        // Very small valid values
        let config = CircuitBreakerConfig::new()
            .with_failure_threshold(1)
            .with_min_requests(1)
            .with_reset_timeout(Duration::from_nanos(1))
            .with_window_duration(Duration::from_nanos(1));
        assert!(config.validate().is_ok());

        // Very large values
        let config = CircuitBreakerConfig::new()
            .with_failure_threshold(u32::MAX)
            .with_min_requests(u32::MAX)
            .with_reset_timeout(Duration::MAX)
            .with_window_duration(Duration::MAX);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_extreme_success_thresholds() {
        // Zero success threshold - always closes
        let config = CircuitBreakerConfig::new().with_success_threshold(0.0);
        assert_eq!(config.success_threshold, 0.0);
        assert!(config.validate().is_ok());

        // 100% success threshold - needs perfect success
        let config = CircuitBreakerConfig::new().with_success_threshold(1.0);
        assert_eq!(config.success_threshold, 1.0);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preset_high_availability() {
        let config = CircuitBreakerConfig::high_availability();
        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.success_threshold, 0.8);
        assert_eq!(config.reset_timeout, Duration::from_secs(60));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preset_fault_tolerant() {
        let config = CircuitBreakerConfig::fault_tolerant();
        assert_eq!(config.failure_threshold, 10);
        assert_eq!(config.success_threshold, 0.5);
        assert_eq!(config.reset_timeout, Duration::from_secs(15));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preset_aggressive() {
        let config = CircuitBreakerConfig::aggressive();
        assert_eq!(config.failure_threshold, 1);
        assert_eq!(config.success_threshold, 0.95);
        assert_eq!(config.reset_timeout, Duration::from_secs(120));
        assert!(config.validate().is_ok());
    }
}

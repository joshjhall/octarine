//! Configuration types for the runtime
//!
//! Provides configuration types and builders for runtime behavior. These are pure
//! data structures with no dependencies on observe or other internal modules.
//!
//! ## Usage Examples
//!
//! ### Basic Configuration
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::config::RuntimeConfig;
//!
//! let config = RuntimeConfig::default();
//! assert_eq!(config.max_queue_size, 10_000);
//! ```
//!
//! ### Builder Pattern
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::config::{RuntimeConfig, OverflowPolicy};
//!
//! let config = RuntimeConfig::new()
//!     .with_queue_size(5_000)
//!     .with_overflow_policy(OverflowPolicy::Block)
//!     .with_memory_limit(50)
//!     .with_rate_limit(500)
//!     .with_worker_count(8);
//!
//! assert_eq!(config.max_queue_size, 5_000);
//! assert_eq!(config.overflow_policy, OverflowPolicy::Block);
//! ```
//!
//! ## Design Notes
//!
//! This is a **primitive** module - it has NO dependencies on observe or other
//! internal modules.

use std::time::Duration;

use crate::primitives::{Problem, Result};

/// Configuration for the runtime with secure defaults
///
/// All defaults are chosen for security and stability:
/// - Bounded queues prevent memory exhaustion (CWE-400)
/// - Rate limiting prevents DoS attacks (CWE-307)
/// - Timeouts prevent resource starvation
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::config::RuntimeConfig;
///
/// let config = RuntimeConfig::new()
///     .with_queue_size(1_000)
///     .with_timeout(std::time::Duration::from_secs(60));
/// ```
#[derive(Debug, Clone)]
#[allow(dead_code)] // Reserved for future use
pub struct RuntimeConfig {
    /// Maximum number of items in a channel queue
    pub max_queue_size: usize,

    /// Policy for handling channel overflow
    pub overflow_policy: OverflowPolicy,

    /// Maximum memory usage in megabytes
    pub max_memory_mb: usize,

    /// Rate limit for events per second
    pub events_per_second: u32,

    /// Whether to enable metrics collection
    pub enable_metrics: bool,

    /// Whether to fallback to sync execution
    pub fallback_to_sync: bool,

    /// Default timeout for async operations
    pub default_timeout: Duration,

    /// Number of worker threads
    pub worker_count: usize,

    /// Enable circuit breaker
    pub circuit_breaker_enabled: bool,

    /// Default retry attempts
    pub retry_attempts: u32,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_queue_size: 10_000,
            overflow_policy: OverflowPolicy::DropOldest,
            max_memory_mb: 100,
            events_per_second: 1_000,
            enable_metrics: true,
            fallback_to_sync: true,
            default_timeout: Duration::from_secs(30),
            worker_count: 4,
            circuit_breaker_enabled: true,
            retry_attempts: 3,
        }
    }
}

#[allow(dead_code)] // Reserved for future use
impl RuntimeConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style method to set queue size
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::config::RuntimeConfig;
    ///
    /// let config = RuntimeConfig::new().with_queue_size(5_000);
    /// assert_eq!(config.max_queue_size, 5_000);
    /// ```
    pub fn with_queue_size(mut self, size: usize) -> Self {
        self.max_queue_size = size;
        self
    }

    /// Builder-style method to set overflow policy
    pub fn with_overflow_policy(mut self, policy: OverflowPolicy) -> Self {
        self.overflow_policy = policy;
        self
    }

    /// Builder-style method to set memory limit
    pub fn with_memory_limit(mut self, mb: usize) -> Self {
        self.max_memory_mb = mb;
        self
    }

    /// Builder-style method to set rate limit
    pub fn with_rate_limit(mut self, events_per_second: u32) -> Self {
        self.events_per_second = events_per_second;
        self
    }

    /// Builder-style method to set worker count
    pub fn with_worker_count(mut self, count: usize) -> Self {
        self.worker_count = count;
        self
    }

    /// Builder-style method to enable/disable circuit breaker
    pub fn with_circuit_breaker(mut self, enabled: bool) -> Self {
        self.circuit_breaker_enabled = enabled;
        self
    }

    /// Builder-style method to set default timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// Builder-style method to set retry attempts
    pub fn with_retry_attempts(mut self, attempts: u32) -> Self {
        self.retry_attempts = attempts;
        self
    }

    /// Builder-style method to enable/disable metrics
    pub fn with_metrics(mut self, enabled: bool) -> Self {
        self.enable_metrics = enabled;
        self
    }

    /// Builder-style method to enable/disable sync fallback
    pub fn with_sync_fallback(mut self, enabled: bool) -> Self {
        self.fallback_to_sync = enabled;
        self
    }

    /// Validate the configuration for correctness
    ///
    /// Checks for invalid or dangerous configuration values that could cause
    /// runtime failures, deadlocks, or undefined behavior.
    ///
    /// # Errors
    ///
    /// Returns `Problem::validation` if:
    /// - `max_queue_size` is 0 (would cause deadlock)
    /// - `events_per_second` is 0 (division by zero risk)
    /// - `worker_count` is 0 (no workers to process)
    /// - `default_timeout` is zero (instant timeout)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::runtime::config::RuntimeConfig;
    ///
    /// // Valid config
    /// let config = RuntimeConfig::new();
    /// assert!(config.validate().is_ok());
    ///
    /// // Invalid config - zero queue size
    /// let invalid = RuntimeConfig::new().with_queue_size(0);
    /// assert!(invalid.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<()> {
        if self.max_queue_size == 0 {
            return Err(Problem::Validation(
                "max_queue_size cannot be 0 - would cause deadlock".into(),
            ));
        }

        if self.events_per_second == 0 {
            return Err(Problem::Validation(
                "events_per_second cannot be 0 - would cause division by zero".into(),
            ));
        }

        if self.worker_count == 0 {
            return Err(Problem::Validation(
                "worker_count cannot be 0 - no workers to process tasks".into(),
            ));
        }

        if self.default_timeout == Duration::ZERO {
            return Err(Problem::Validation(
                "default_timeout cannot be zero - would cause instant timeout".into(),
            ));
        }

        Ok(())
    }

    /// Create a high-performance configuration
    ///
    /// Optimized for throughput with larger queues and more workers.
    /// Good for high-load scenarios where some data loss is acceptable.
    pub fn high_performance() -> Self {
        Self {
            max_queue_size: 100_000,
            overflow_policy: OverflowPolicy::DropOldest,
            max_memory_mb: 500,
            events_per_second: 10_000,
            enable_metrics: true,
            fallback_to_sync: false,
            default_timeout: Duration::from_secs(60),
            worker_count: 16,
            circuit_breaker_enabled: true,
            retry_attempts: 5,
        }
    }

    /// Create a low-latency configuration
    ///
    /// Optimized for fast responses with smaller queues and aggressive timeouts.
    /// Good for user-facing services where response time is critical.
    pub fn low_latency() -> Self {
        Self {
            max_queue_size: 1_000,
            overflow_policy: OverflowPolicy::Reject,
            max_memory_mb: 50,
            events_per_second: 5_000,
            enable_metrics: true,
            fallback_to_sync: true,
            default_timeout: Duration::from_secs(5),
            worker_count: 8,
            circuit_breaker_enabled: true,
            retry_attempts: 2,
        }
    }

    /// Create a resource-constrained configuration
    ///
    /// Minimal resource usage for embedded or memory-limited environments.
    /// Good for edge devices or sidecar containers.
    pub fn minimal() -> Self {
        Self {
            max_queue_size: 100,
            overflow_policy: OverflowPolicy::DropNewest,
            max_memory_mb: 10,
            events_per_second: 100,
            enable_metrics: false,
            fallback_to_sync: true,
            default_timeout: Duration::from_secs(10),
            worker_count: 1,
            circuit_breaker_enabled: false,
            retry_attempts: 1,
        }
    }
}

/// Overflow policy for channels
///
/// Determines what happens when a channel reaches its capacity limit.
///
/// # Security Considerations
///
/// - `DropOldest`/`DropNewest` prevent memory exhaustion but lose data
/// - `Block` prevents data loss but can cause deadlocks
/// - `Reject` is safest for critical data that must not be lost
#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum OverflowPolicy {
    /// Drop the oldest item in the queue
    DropOldest,
    /// Drop the newest item being sent
    DropNewest,
    /// Block until space is available
    Block,
    /// Immediately reject with an error
    Reject,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = RuntimeConfig::default();
        assert_eq!(config.max_queue_size, 10_000);
        assert_eq!(config.max_memory_mb, 100);
        assert_eq!(config.events_per_second, 1_000);
        assert!(config.enable_metrics);
        assert!(config.fallback_to_sync);
    }

    #[test]
    fn test_config_builder() {
        let config = RuntimeConfig::new()
            .with_queue_size(5_000)
            .with_overflow_policy(OverflowPolicy::Block)
            .with_memory_limit(50)
            .with_rate_limit(500);

        assert_eq!(config.max_queue_size, 5_000);
        assert_eq!(config.overflow_policy, OverflowPolicy::Block);
        assert_eq!(config.max_memory_mb, 50);
        assert_eq!(config.events_per_second, 500);
    }

    #[test]
    fn test_overflow_policy_equality() {
        assert_eq!(OverflowPolicy::DropOldest, OverflowPolicy::DropOldest);
        assert_ne!(OverflowPolicy::DropOldest, OverflowPolicy::Block);
    }

    #[test]
    fn test_config_clone() {
        let config1 = RuntimeConfig::new().with_queue_size(1_000);
        let config2 = config1.clone();
        assert_eq!(config1.max_queue_size, config2.max_queue_size);
    }

    #[test]
    fn test_all_builder_methods() {
        let config = RuntimeConfig::new()
            .with_queue_size(1_000)
            .with_overflow_policy(OverflowPolicy::Reject)
            .with_memory_limit(200)
            .with_rate_limit(2_000)
            .with_worker_count(8)
            .with_circuit_breaker(false)
            .with_timeout(Duration::from_secs(60))
            .with_retry_attempts(5)
            .with_metrics(false)
            .with_sync_fallback(false);

        assert_eq!(config.max_queue_size, 1_000);
        assert_eq!(config.overflow_policy, OverflowPolicy::Reject);
        assert_eq!(config.max_memory_mb, 200);
        assert_eq!(config.events_per_second, 2_000);
        assert_eq!(config.worker_count, 8);
        assert!(!config.circuit_breaker_enabled);
        assert_eq!(config.default_timeout, Duration::from_secs(60));
        assert_eq!(config.retry_attempts, 5);
        assert!(!config.enable_metrics);
        assert!(!config.fallback_to_sync);
    }

    #[test]
    fn test_validate_default_config() {
        let config = RuntimeConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_zero_queue_size() {
        let config = RuntimeConfig::new().with_queue_size(0);
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error")
                .to_string()
                .contains("max_queue_size cannot be 0")
        );
    }

    #[test]
    fn test_validate_zero_events_per_second() {
        let config = RuntimeConfig::new().with_rate_limit(0);
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error")
                .to_string()
                .contains("events_per_second cannot be 0")
        );
    }

    #[test]
    fn test_validate_zero_worker_count() {
        let config = RuntimeConfig::new().with_worker_count(0);
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error")
                .to_string()
                .contains("worker_count cannot be 0")
        );
    }

    #[test]
    fn test_validate_zero_timeout() {
        let config = RuntimeConfig::new().with_timeout(Duration::ZERO);
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected validation error")
                .to_string()
                .contains("default_timeout cannot be zero")
        );
    }

    #[test]
    fn test_validate_edge_values() {
        // Very small valid values
        let config = RuntimeConfig::new()
            .with_queue_size(1)
            .with_rate_limit(1)
            .with_worker_count(1)
            .with_timeout(Duration::from_nanos(1));
        assert!(config.validate().is_ok());

        // Very large values
        let config = RuntimeConfig::new()
            .with_queue_size(usize::MAX)
            .with_rate_limit(u32::MAX)
            .with_worker_count(usize::MAX)
            .with_timeout(Duration::MAX);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preset_high_performance() {
        let config = RuntimeConfig::high_performance();
        assert_eq!(config.max_queue_size, 100_000);
        assert_eq!(config.worker_count, 16);
        assert!(!config.fallback_to_sync);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preset_low_latency() {
        let config = RuntimeConfig::low_latency();
        assert_eq!(config.max_queue_size, 1_000);
        assert_eq!(config.default_timeout, Duration::from_secs(5));
        assert_eq!(config.overflow_policy, OverflowPolicy::Reject);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_preset_minimal() {
        let config = RuntimeConfig::minimal();
        assert_eq!(config.max_queue_size, 100);
        assert_eq!(config.worker_count, 1);
        assert!(!config.enable_metrics);
        assert!(config.validate().is_ok());
    }
}

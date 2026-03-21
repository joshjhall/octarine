//! Rate Limiting with Observability
//!
//! Keyed rate limiting with automatic logging, metrics, and audit trails.
//! Wraps the primitives layer with observe instrumentation.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │ Public API (this module)                                    │
//! │ - Full observability (events, metrics, logging)             │
//! │ - Audit trails for rate limit decisions                     │
//! │ - Named limiters for identification                         │
//! └─────────────────────────────────────────────────────────────┘
//!          ↓ wraps
//! ┌─────────────────────────────────────────────────────────────┐
//! │ Primitives (primitives/runtime/rate_limiter)                │
//! │ - Pure GCRA implementation via governor                     │
//! │ - No logging or side effects                                │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust
//! use octarine::runtime::rate_limiter::{RateLimiter, Decision};
//!
//! // Create a named rate limiter (name used in logs/metrics)
//! let limiter = RateLimiter::<String>::per_second("api_requests", 100).unwrap();
//!
//! // Check if request should be allowed
//! match limiter.check(&"user-123".to_string()) {
//!     Decision::Allow => {
//!         // Process request
//!     }
//!     Decision::Deny { retry_after } => {
//!         // Return 429 with Retry-After header
//!     }
//! }
//! ```
//!
//! # Observability
//!
//! The rate limiter automatically:
//! - Logs denied requests at WARN level
//! - Emits metrics for allowed/denied counts
//! - Provides audit trail for compliance

use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use once_cell::sync::Lazy;

use crate::observe;
use crate::observe::metrics::{self, MetricName};
use crate::primitives::runtime::rate_limiter as prim;

// Pre-validated metric names for rate limiter operations
// These are compile-time constants with known-valid names
static METRIC_ALLOWED: Lazy<MetricName> =
    Lazy::new(|| MetricName::from_static_str("rate_limiter.allowed"));
static METRIC_DENIED: Lazy<MetricName> =
    Lazy::new(|| MetricName::from_static_str("rate_limiter.denied"));

// Re-export types from primitives
pub use prim::{Decision, Quota, RateLimitError, RateLimiterStats};

/// A keyed rate limiter with observability
///
/// Wraps the primitives rate limiter with logging, metrics, and audit trails.
///
/// # Type Parameters
///
/// * `K` - The key type for rate limiting (e.g., IP address, user ID, API key)
///
/// # Example
///
/// ```rust
/// use octarine::runtime::rate_limiter::{RateLimiter, Decision};
///
/// // Create a rate limiter with a descriptive name
/// let limiter = RateLimiter::<String>::per_second("login_attempts", 5).unwrap();
///
/// // The name appears in all logs and metrics
/// match limiter.check(&"user@example.com".to_string()) {
///     Decision::Allow => println!("Login attempt allowed"),
///     Decision::Deny { retry_after } => {
///         println!("Too many attempts, retry after {:?}", retry_after);
///     }
/// }
/// ```
pub struct RateLimiter<K>
where
    K: Clone + Hash + Eq + Send + Sync + 'static,
{
    inner: prim::RateLimiter<K>,
    name: Arc<str>,
}

impl<K> RateLimiter<K>
where
    K: Clone + Hash + Eq + Send + Sync + std::fmt::Debug + 'static,
{
    /// Create a rate limiter with the given quota
    ///
    /// # Arguments
    ///
    /// * `name` - A descriptive name for this limiter (used in logs/metrics)
    /// * `quota` - The rate limit quota from `governor::Quota`
    pub fn new(name: impl Into<String>, quota: Quota) -> Self {
        let name: Arc<str> = name.into().into();
        observe::debug(
            "rate_limiter.created",
            format!("Rate limiter '{}' created", name),
        );
        Self {
            inner: prim::RateLimiter::new(quota),
            name,
        }
    }

    /// Create a rate limiter allowing N requests per second
    ///
    /// # Arguments
    ///
    /// * `name` - A descriptive name for this limiter
    /// * `requests` - Maximum requests per second (must be > 0)
    ///
    /// # Errors
    ///
    /// Returns `RateLimitError::InvalidQuota` if requests is 0.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::runtime::rate_limiter::RateLimiter;
    ///
    /// let limiter = RateLimiter::<String>::per_second("api", 100).unwrap();
    /// assert_eq!(limiter.name(), "api");
    /// ```
    pub fn per_second(name: impl Into<String>, requests: u32) -> Result<Self, RateLimitError> {
        let name: Arc<str> = name.into().into();
        let inner = prim::RateLimiter::per_second(requests)?;
        observe::info(
            "rate_limiter.created",
            format!(
                "Rate limiter '{}' created: {} requests/second",
                name, requests
            ),
        );
        Ok(Self { inner, name })
    }

    /// Create a rate limiter allowing N requests per minute
    ///
    /// # Arguments
    ///
    /// * `name` - A descriptive name for this limiter
    /// * `requests` - Maximum requests per minute (must be > 0)
    ///
    /// # Errors
    ///
    /// Returns `RateLimitError::InvalidQuota` if requests is 0.
    pub fn per_minute(name: impl Into<String>, requests: u32) -> Result<Self, RateLimitError> {
        let name: Arc<str> = name.into().into();
        let inner = prim::RateLimiter::per_minute(requests)?;
        observe::info(
            "rate_limiter.created",
            format!(
                "Rate limiter '{}' created: {} requests/minute",
                name, requests
            ),
        );
        Ok(Self { inner, name })
    }

    /// Create a rate limiter allowing N requests per hour
    ///
    /// # Arguments
    ///
    /// * `name` - A descriptive name for this limiter
    /// * `requests` - Maximum requests per hour (must be > 0)
    ///
    /// # Errors
    ///
    /// Returns `RateLimitError::InvalidQuota` if requests is 0.
    pub fn per_hour(name: impl Into<String>, requests: u32) -> Result<Self, RateLimitError> {
        let name: Arc<str> = name.into().into();
        let inner = prim::RateLimiter::per_hour(requests)?;
        observe::info(
            "rate_limiter.created",
            format!(
                "Rate limiter '{}' created: {} requests/hour",
                name, requests
            ),
        );
        Ok(Self { inner, name })
    }

    /// Create a rate limiter with a custom period
    ///
    /// # Arguments
    ///
    /// * `name` - A descriptive name for this limiter
    /// * `requests` - Maximum requests in the period (must be > 0)
    /// * `period` - The time period for the rate limit
    ///
    /// # Errors
    ///
    /// Returns `RateLimitError::InvalidQuota` if requests is 0 or period is invalid.
    pub fn with_period(
        name: impl Into<String>,
        requests: u32,
        period: Duration,
    ) -> Result<Self, RateLimitError> {
        let name: Arc<str> = name.into().into();
        let inner = prim::RateLimiter::with_period(requests, period)?;
        observe::info(
            "rate_limiter.created",
            format!(
                "Rate limiter '{}' created: {} requests per {:?}",
                name, requests, period
            ),
        );
        Ok(Self { inner, name })
    }

    /// Check if a request for the given key should be allowed
    ///
    /// This is a non-blocking check that returns immediately.
    /// Denied requests are logged at WARN level.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to check (e.g., user ID, IP address)
    ///
    /// # Returns
    ///
    /// * `Decision::Allow` if the request should be allowed
    /// * `Decision::Deny { retry_after }` if rate limited
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use octarine::runtime::rate_limiter::{RateLimiter, Decision};
    ///
    /// let limiter = RateLimiter::<String>::per_second("api", 2).unwrap();
    /// let key = "user-123".to_string();
    ///
    /// // First requests allowed (within burst)
    /// assert!(limiter.check(&key).is_allowed());
    /// assert!(limiter.check(&key).is_allowed());
    ///
    /// // Exceeds rate limit (timing-dependent in practice)
    /// let decision = limiter.check(&key);
    /// if decision.is_denied() {
    ///     assert!(decision.retry_after().is_some());
    /// }
    /// ```
    pub fn check(&self, key: &K) -> Decision {
        let decision = self.inner.check(key);

        match &decision {
            Decision::Allow => {
                metrics::increment(METRIC_ALLOWED.clone());
                observe::debug(
                    "rate_limiter.allowed",
                    format!(
                        "Rate limiter '{}': request allowed for {:?}",
                        self.name, key
                    ),
                );
            }
            Decision::Deny { retry_after } => {
                metrics::increment(METRIC_DENIED.clone());
                observe::warn(
                    "rate_limiter.denied",
                    format!(
                        "Rate limiter '{}': request denied for {:?}, retry after {:?}",
                        self.name, key, retry_after
                    ),
                );
            }
        }

        decision
    }

    /// Wait until a request for the given key is allowed
    ///
    /// This is an async method that will sleep until the rate limit allows
    /// the request to proceed.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to wait for
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::runtime::rate_limiter::RateLimiter;
    ///
    /// # tokio_test::block_on(async {
    /// let limiter = RateLimiter::<String>::per_second("api", 10).unwrap();
    /// let key = "user".to_string();
    ///
    /// // Wait until allowed (returns immediately if under limit)
    /// limiter.until_ready(&key).await;
    /// // Request is now guaranteed to be allowed
    /// # });
    /// ```
    pub async fn until_ready(&self, key: &K) {
        observe::debug(
            "rate_limiter.waiting",
            format!(
                "Rate limiter '{}': waiting for rate limit on {:?}",
                self.name, key
            ),
        );

        self.inner.until_ready(key).await;

        // Count as allowed since the request proceeded
        metrics::increment(METRIC_ALLOWED.clone());
        observe::debug(
            "rate_limiter.ready",
            format!(
                "Rate limiter '{}': rate limit cleared for {:?}",
                self.name, key
            ),
        );
    }

    /// Get current statistics
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::runtime::rate_limiter::RateLimiter;
    ///
    /// let limiter = RateLimiter::<String>::per_second("api", 1).unwrap();
    /// let key = "user".to_string();
    ///
    /// limiter.check(&key); // allowed
    /// limiter.check(&key); // denied
    ///
    /// let stats = limiter.stats();
    /// assert_eq!(stats.total_checks, 2);
    /// assert_eq!(stats.allowed, 1);
    /// assert_eq!(stats.denied, 1);
    /// assert!((stats.denial_rate() - 0.5).abs() < f64::EPSILON);
    /// ```
    pub fn stats(&self) -> RateLimiterStats {
        self.inner.stats()
    }

    /// Get the limiter name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        self.inner.reset_stats();
        observe::debug(
            "rate_limiter.stats_reset",
            format!("Rate limiter '{}': statistics reset", self.name),
        );
    }

    /// Log current statistics at INFO level
    pub fn log_stats(&self) {
        let stats = self.stats();
        observe::info(
            "rate_limiter.stats",
            format!(
                "Rate limiter '{}': {} total, {} allowed, {} denied ({:.1}% denial rate)",
                self.name,
                stats.total_checks,
                stats.allowed,
                stats.denied,
                stats.denial_rate() * 100.0
            ),
        );
    }
}

// RateLimiter is Clone because inner is Arc-based
impl<K> Clone for RateLimiter<K>
where
    K: Clone + Hash + Eq + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            name: Arc::clone(&self.name),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_rate_limiter_creation() {
        let limiter =
            RateLimiter::<String>::per_second("test", 100).expect("should create limiter");
        assert_eq!(limiter.name(), "test");
    }

    #[test]
    fn test_rate_limiter_check() {
        let limiter = RateLimiter::<String>::per_second("test", 5).expect("should create limiter");
        let key = "user-123".to_string();

        // Exhaust burst capacity. Under coverage instrumentation, the loop may run
        // slowly enough for tokens to refill, so we keep checking until denial.
        let mut denied = false;
        for _ in 0..20 {
            if limiter.check(&key).is_denied() {
                denied = true;
                break;
            }
        }
        assert!(denied, "should eventually be denied after exhausting burst");
    }

    #[test]
    fn test_rate_limiter_stats() {
        let limiter = RateLimiter::<String>::per_second("test", 5).expect("should create limiter");
        let key = "test".to_string();

        // Keep checking until we get at least one denial
        let mut got_denial = false;
        for _ in 0..20 {
            if limiter.check(&key).is_denied() {
                got_denial = true;
                break;
            }
        }
        assert!(got_denial, "should eventually get a denial");

        let stats = limiter.stats();
        assert!(stats.total_checks >= 2, "should have at least 2 checks");
        assert!(stats.allowed >= 1, "should have at least 1 allowed");
        assert!(stats.denied >= 1, "should have at least 1 denied");
    }

    #[test]
    fn test_rate_limiter_clone_shares_state() {
        let limiter = RateLimiter::<String>::per_second("test", 5).expect("should create limiter");
        let limiter2 = limiter.clone();
        let key = "test".to_string();

        // Exhaust capacity by alternating between clones until we get a denial.
        // This verifies they share state - if they didn't, we'd never get denied.
        let mut denied = false;
        for i in 0..20 {
            let l = if i % 2 == 0 { &limiter } else { &limiter2 };
            if l.check(&key).is_denied() {
                denied = true;
                break;
            }
        }
        assert!(denied, "clones should share state and eventually deny");

        // Stats should be shared between clones
        assert_eq!(limiter.stats().total_checks, limiter2.stats().total_checks);
    }

    #[tokio::test]
    async fn test_until_ready() {
        let limiter = RateLimiter::<String>::per_second("test", 10).expect("should create limiter");
        let key = "test".to_string();

        // Exhaust burst and verify we reach denial state.
        // Under coverage instrumentation, the loop may run slowly enough for tokens
        // to refill, so we keep checking until we see a denial.
        let mut denied = false;
        for _ in 0..20 {
            if limiter.check(&key).is_denied() {
                denied = true;
                break;
            }
        }
        assert!(denied, "should eventually be denied after exhausting burst");

        // until_ready should wait and succeed
        limiter.reset_stats();
        limiter.until_ready(&key).await;

        assert_eq!(limiter.stats().allowed, 1);
    }
}

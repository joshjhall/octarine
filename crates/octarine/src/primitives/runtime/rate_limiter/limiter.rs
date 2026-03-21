//! Rate limiter implementation
//!
//! Wraps the `governor` crate with a simplified API.

#![allow(dead_code)] // Layer 1 primitives - will be used by Layer 3

use std::hash::Hash;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter as GovernorLimiter};

use super::types::{Decision, RateLimitError, RateLimiterStats};

/// A keyed rate limiter
///
/// Uses the Generic Cell Rate Algorithm (GCRA) via the `governor` crate.
/// Thread-safe and suitable for concurrent access.
///
/// # Type Parameters
///
/// * `K` - The key type for rate limiting (e.g., IP address, user ID, API key)
///
/// # Public API
///
/// This is an internal primitive. For external usage with observability,
/// use [`crate::runtime::rate_limiter::RateLimiter`].
pub struct RateLimiter<K>
where
    K: Clone + Hash + Eq + Send + Sync + 'static,
{
    inner: Arc<GovernorLimiter<K, DashMapStateStore<K>, DefaultClock>>,
    stats: Arc<Stats>,
    quota: Quota,
}

/// Internal stats tracking
struct Stats {
    total_checks: AtomicU64,
    allowed: AtomicU64,
    denied: AtomicU64,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            total_checks: AtomicU64::new(0),
            allowed: AtomicU64::new(0),
            denied: AtomicU64::new(0),
        }
    }
}

impl<K> RateLimiter<K>
where
    K: Clone + Hash + Eq + Send + Sync + 'static,
{
    /// Create a rate limiter with the given quota
    ///
    /// # Arguments
    ///
    /// * `quota` - The rate limit quota from `governor::Quota`
    pub fn new(quota: Quota) -> Self {
        let inner = GovernorLimiter::keyed(quota);
        Self {
            inner: Arc::new(inner),
            stats: Arc::new(Stats::default()),
            quota,
        }
    }

    /// Create a rate limiter allowing N requests per second
    ///
    /// # Arguments
    ///
    /// * `requests` - Maximum requests per second (must be > 0)
    ///
    /// # Errors
    ///
    /// Returns `RateLimitError::InvalidQuota` if requests is 0.
    pub fn per_second(requests: u32) -> Result<Self, RateLimitError> {
        let n = NonZeroU32::new(requests).ok_or_else(|| {
            RateLimitError::invalid_quota("requests per second must be greater than 0")
        })?;
        Ok(Self::new(Quota::per_second(n)))
    }

    /// Create a rate limiter allowing N requests per minute
    ///
    /// # Arguments
    ///
    /// * `requests` - Maximum requests per minute (must be > 0)
    ///
    /// # Errors
    ///
    /// Returns `RateLimitError::InvalidQuota` if requests is 0.
    pub fn per_minute(requests: u32) -> Result<Self, RateLimitError> {
        let n = NonZeroU32::new(requests).ok_or_else(|| {
            RateLimitError::invalid_quota("requests per minute must be greater than 0")
        })?;
        Ok(Self::new(Quota::per_minute(n)))
    }

    /// Create a rate limiter allowing N requests per hour
    ///
    /// # Arguments
    ///
    /// * `requests` - Maximum requests per hour (must be > 0)
    ///
    /// # Errors
    ///
    /// Returns `RateLimitError::InvalidQuota` if requests is 0.
    pub fn per_hour(requests: u32) -> Result<Self, RateLimitError> {
        let n = NonZeroU32::new(requests).ok_or_else(|| {
            RateLimitError::invalid_quota("requests per hour must be greater than 0")
        })?;
        // Governor doesn't have per_hour, so we calculate the replenishment period
        // For N requests per hour, each request replenishes every (3600/N) seconds
        // Safety: requests is validated > 0 above via NonZeroU32
        let seconds_per_request = 3600_u64
            .checked_div(u64::from(requests))
            .ok_or_else(|| RateLimitError::invalid_quota("overflow calculating per-hour quota"))?;
        let quota = Quota::with_period(Duration::from_secs(seconds_per_request))
            .ok_or_else(|| RateLimitError::invalid_quota("invalid quota period"))?
            .allow_burst(n);
        Ok(Self::new(quota))
    }

    /// Create a rate limiter with a custom period
    ///
    /// # Arguments
    ///
    /// * `requests` - Maximum requests in the period (must be > 0)
    /// * `period` - The time period for the rate limit
    ///
    /// # Errors
    ///
    /// Returns `RateLimitError::InvalidQuota` if requests is 0 or period is invalid.
    pub fn with_period(requests: u32, period: Duration) -> Result<Self, RateLimitError> {
        let n = NonZeroU32::new(requests)
            .ok_or_else(|| RateLimitError::invalid_quota("requests must be greater than 0"))?;

        if period.is_zero() {
            return Err(RateLimitError::invalid_quota(
                "period must be greater than 0",
            ));
        }

        // Calculate the replenishment period (time between allowed requests)
        // Safety: requests is validated > 0 above via NonZeroU32
        let replenish_period = period.checked_div(requests).ok_or_else(|| {
            RateLimitError::invalid_quota("overflow calculating replenishment period")
        })?;

        let quota = Quota::with_period(replenish_period)
            .ok_or_else(|| RateLimitError::invalid_quota("invalid quota period"))?
            .allow_burst(n);

        Ok(Self::new(quota))
    }

    /// Check if a request for the given key should be allowed
    ///
    /// This is a non-blocking check that returns immediately.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to check (e.g., user ID, IP address)
    ///
    /// # Returns
    ///
    /// * `Decision::Allow` if the request should be allowed
    /// * `Decision::Deny { retry_after }` if rate limited
    pub fn check(&self, key: &K) -> Decision {
        self.stats.total_checks.fetch_add(1, Ordering::Relaxed);

        match self.inner.check_key(key) {
            Ok(()) => {
                self.stats.allowed.fetch_add(1, Ordering::Relaxed);
                Decision::Allow
            }
            Err(not_until) => {
                self.stats.denied.fetch_add(1, Ordering::Relaxed);
                let retry_after = not_until.wait_time_from(DefaultClock::default().now());
                Decision::Deny { retry_after }
            }
        }
    }

    /// Wait until a request for the given key is allowed
    ///
    /// This is an async method that will sleep until the rate limit allows
    /// the request to proceed.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to wait for
    pub async fn until_ready(&self, key: &K) {
        self.stats.total_checks.fetch_add(1, Ordering::Relaxed);

        // Use check_key in a loop with sleep to avoid blocking
        loop {
            match self.inner.check_key(key) {
                Ok(()) => {
                    self.stats.allowed.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(not_until) => {
                    let wait_time = not_until.wait_time_from(DefaultClock::default().now());
                    tokio::time::sleep(wait_time).await;
                }
            }
        }
    }

    /// Get current statistics
    pub fn stats(&self) -> RateLimiterStats {
        RateLimiterStats {
            total_checks: self.stats.total_checks.load(Ordering::Relaxed),
            allowed: self.stats.allowed.load(Ordering::Relaxed),
            denied: self.stats.denied.load(Ordering::Relaxed),
        }
    }

    /// Get the quota configuration
    pub fn quota(&self) -> &Quota {
        &self.quota
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        self.stats.total_checks.store(0, Ordering::Relaxed);
        self.stats.allowed.store(0, Ordering::Relaxed);
        self.stats.denied.store(0, Ordering::Relaxed);
    }
}

// RateLimiter is Clone because inner is Arc
impl<K> Clone for RateLimiter<K>
where
    K: Clone + Hash + Eq + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            stats: Arc::clone(&self.stats),
            quota: self.quota,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_per_second_creation() {
        let limiter = RateLimiter::<String>::per_second(100).expect("should create limiter");
        assert!(limiter.check(&"test".to_string()).is_allowed());
    }

    #[test]
    fn test_per_second_zero_fails() {
        let result = RateLimiter::<String>::per_second(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_per_minute_creation() {
        let limiter = RateLimiter::<String>::per_minute(60).expect("should create limiter");
        assert!(limiter.check(&"test".to_string()).is_allowed());
    }

    #[test]
    fn test_with_period_creation() {
        let limiter = RateLimiter::<String>::with_period(10, Duration::from_secs(1))
            .expect("should create limiter");
        assert!(limiter.check(&"test".to_string()).is_allowed());
    }

    #[test]
    fn test_with_period_zero_requests_fails() {
        let result = RateLimiter::<String>::with_period(0, Duration::from_secs(1));
        assert!(result.is_err());
    }

    #[test]
    fn test_with_period_zero_duration_fails() {
        let result = RateLimiter::<String>::with_period(10, Duration::ZERO);
        assert!(result.is_err());
    }

    #[test]
    fn test_rate_limiting_works() {
        // Allow only 2 requests per second
        let limiter = RateLimiter::<String>::per_second(2).expect("should create limiter");
        let key = "user-123".to_string();

        // First two requests should be allowed (burst)
        assert!(limiter.check(&key).is_allowed());
        assert!(limiter.check(&key).is_allowed());

        // Third request should be denied
        let decision = limiter.check(&key);
        assert!(decision.is_denied());
        assert!(decision.retry_after().is_some());
    }

    #[test]
    fn test_different_keys_independent() {
        let limiter = RateLimiter::<String>::per_second(1).expect("should create limiter");

        // Each key has its own bucket
        assert!(limiter.check(&"user-1".to_string()).is_allowed());
        assert!(limiter.check(&"user-2".to_string()).is_allowed());
        assert!(limiter.check(&"user-3".to_string()).is_allowed());

        // But same key is rate limited
        assert!(limiter.check(&"user-1".to_string()).is_denied());
    }

    #[test]
    fn test_stats_tracking() {
        let limiter = RateLimiter::<String>::per_second(1).expect("should create limiter");
        let key = "test".to_string();

        limiter.check(&key); // allowed
        limiter.check(&key); // denied

        let stats = limiter.stats();
        assert_eq!(stats.total_checks, 2);
        assert_eq!(stats.allowed, 1);
        assert_eq!(stats.denied, 1);
    }

    #[test]
    fn test_stats_reset() {
        let limiter = RateLimiter::<String>::per_second(1).expect("should create limiter");

        limiter.check(&"test".to_string());
        limiter.reset_stats();

        let stats = limiter.stats();
        assert_eq!(stats.total_checks, 0);
    }

    #[test]
    fn test_clone_shares_state() {
        let limiter = RateLimiter::<String>::per_second(1).expect("should create limiter");
        let limiter2 = limiter.clone();
        let key = "test".to_string();

        // Use first limiter
        assert!(limiter.check(&key).is_allowed());

        // Second limiter should see rate limit (same underlying state)
        assert!(limiter2.check(&key).is_denied());

        // Stats should be shared too
        assert_eq!(limiter.stats().total_checks, 2);
        assert_eq!(limiter2.stats().total_checks, 2);
    }

    #[tokio::test]
    async fn test_until_ready() {
        let limiter = RateLimiter::<String>::per_second(10).expect("should create limiter");
        let key = "test".to_string();

        // Exhaust the burst
        for _ in 0..10 {
            limiter.check(&key);
        }

        // Next check should be denied
        assert!(limiter.check(&key).is_denied());

        // Reset stats for clean measurement
        limiter.reset_stats();

        // until_ready should wait and then succeed
        let start = std::time::Instant::now();
        limiter.until_ready(&key).await;
        let elapsed = start.elapsed();

        // Should have waited some time (at least a few ms)
        assert!(elapsed.as_millis() > 0);

        // And request should be counted as allowed
        let stats = limiter.stats();
        assert_eq!(stats.allowed, 1);
    }
}

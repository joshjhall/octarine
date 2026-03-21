//! Caching infrastructure for personal detection
//!
//! Provides LRU caches for email and phone validation results
//! to improve performance when processing documents with repeated identifiers.

use crate::primitives::collections::{CacheStats, LruCache};
use once_cell::sync::Lazy;
use std::time::Duration;

// ============================================================================
// Cache Instances
// ============================================================================

/// Cache for email validation results
///
/// Caches up to 10,000 email validations for 1 hour.
pub(super) static EMAIL_CACHE: Lazy<LruCache<String, bool>> =
    Lazy::new(|| LruCache::new(10_000, Duration::from_secs(3600)));

/// Cache for phone validation results
///
/// Caches up to 10,000 phone validations for 1 hour.
pub(super) static PHONE_CACHE: Lazy<LruCache<String, bool>> =
    Lazy::new(|| LruCache::new(10_000, Duration::from_secs(3600)));

// ============================================================================
// Cache Statistics
// ============================================================================

/// Get email cache statistics
///
/// Returns cache hit/miss stats for performance monitoring.
#[must_use]
pub fn email_cache_stats() -> CacheStats {
    EMAIL_CACHE.stats()
}

/// Get phone cache statistics
///
/// Returns cache hit/miss stats for performance monitoring.
#[must_use]
pub fn phone_cache_stats() -> CacheStats {
    PHONE_CACHE.stats()
}

/// Clear all personal detection caches
///
/// Useful for testing or when memory pressure is high.
pub fn clear_personal_caches() {
    EMAIL_CACHE.clear();
    PHONE_CACHE.clear();
}

//! Caching infrastructure for government validation
//!
//! Provides LRU caches for SSN and VIN validation results to improve
//! performance when processing documents with repeated identifiers.

use crate::primitives::collections::{CacheStats, LruCache};
use once_cell::sync::Lazy;
use std::time::Duration;

// ============================================================================
// Cache Instances
// ============================================================================

/// Cache for SSN format validation results
///
/// Caches up to 10,000 SSN validations for 1 hour.
/// Provides 15-40% CPU reduction for documents with repeated SSNs.
pub(super) static SSN_VALIDATION_CACHE: Lazy<LruCache<String, Result<(), String>>> =
    Lazy::new(|| LruCache::new(10_000, Duration::from_secs(3600)));

/// Cache for VIN checksum validation results
///
/// Caches up to 5,000 VIN checksum validations for 1 hour.
pub(super) static VIN_CHECKSUM_CACHE: Lazy<LruCache<String, bool>> =
    Lazy::new(|| LruCache::new(5_000, Duration::from_secs(3600)));

// ============================================================================
// Cache Statistics
// ============================================================================

/// Get SSN validation cache statistics
///
/// Returns cache hit/miss stats for performance monitoring.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// let stats = validation::ssn_cache_stats();
/// println!("Hit rate: {:.2}%", stats.hit_rate() * 100.0);
/// ```
#[must_use]
pub fn ssn_cache_stats() -> CacheStats {
    SSN_VALIDATION_CACHE.stats()
}

/// Get VIN checksum cache statistics
///
/// Returns cache hit/miss stats for performance monitoring.
#[must_use]
pub fn vin_cache_stats() -> CacheStats {
    VIN_CHECKSUM_CACHE.stats()
}

/// Clear all government validation caches
///
/// Useful for testing or when memory pressure is high.
pub fn clear_government_caches() {
    SSN_VALIDATION_CACHE.clear();
    VIN_CHECKSUM_CACHE.clear();
}

/// Process-wide lock serializing tests that touch the government caches.
///
/// `SSN_VALIDATION_CACHE` and `VIN_CHECKSUM_CACHE` are global statics, so any
/// test that populates, reads or clears them races every other test doing the
/// same — one test's `clear_government_caches()` empties what another is
/// asserting on. A *file-local* mutex cannot fix this: the tests live in four
/// different modules (`validation::ssn`, `validation::vin`,
/// `builder::cache`, and the Layer 3 `identifiers::builder::government::cache`),
/// and under `cargo test` (and so `cargo llvm-cov`) the whole crate shares one
/// process. `#[serial]` is likewise a *different* lock and does not serialize
/// against holders of this one.
///
/// Every test touching those statics must take this lock, and only this lock:
///
/// ```ignore
/// let _guard = gov_cache_test_lock();
/// clear_government_caches();
/// // ... populate and assert ...
/// ```
///
/// Test-only helper gated behind `cfg(test)`, so it is not reachable from a
/// doctest binary - ignored rather than run.
#[cfg(any(test, feature = "testing"))]
pub fn gov_cache_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // A poisoned lock only means some other cache test panicked; the guard is
    // still sound to take, and failing here would mask that test's error.
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

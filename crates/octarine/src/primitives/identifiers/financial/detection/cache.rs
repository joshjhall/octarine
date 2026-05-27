//! Caching infrastructure for financial detection
//!
//! Provides LRU caches for Luhn and ABA checksum validation results
//! to improve performance when processing documents with repeated identifiers.

use crate::primitives::collections::{CacheStats, LruCache};
use once_cell::sync::Lazy;
use std::time::Duration;

// ============================================================================
// Cache Instances
// ============================================================================

/// Cache for Luhn checksum validation results
///
/// Caches up to 10,000 card number validations for 1 hour.
/// Provides 15-40% CPU reduction for documents with repeated card numbers.
pub(super) static LUHN_CACHE: Lazy<LruCache<String, bool>> =
    Lazy::new(|| LruCache::new(10_000, Duration::from_secs(3600)));

/// Cache for ABA routing number checksum results
///
/// Caches up to 5,000 routing number validations for 1 hour.
pub(super) static ABA_CACHE: Lazy<LruCache<String, bool>> =
    Lazy::new(|| LruCache::new(5_000, Duration::from_secs(3600)));

/// Cache for Bitcoin address checksum validation results
///
/// Caches up to 10,000 BTC address validations (Base58Check + Bech32/Bech32m) for 1 hour.
pub(super) static BTC_CHECKSUM_CACHE: Lazy<LruCache<String, bool>> =
    Lazy::new(|| LruCache::new(10_000, Duration::from_secs(3600)));

/// Cache for Ethereum EIP-55 mixed-case checksum results
///
/// Caches up to 5,000 ETH address validations for 1 hour. Smaller than the
/// BTC cache because keccak-256 is cheap enough that re-validation is not
/// usually a hot path; the cache exists primarily for callers that re-scan
/// the same document repeatedly.
pub(super) static ETH_EIP55_CACHE: Lazy<LruCache<String, bool>> =
    Lazy::new(|| LruCache::new(5_000, Duration::from_secs(3600)));

// ============================================================================
// Cache Statistics
// ============================================================================

/// Get Luhn cache statistics
///
/// Returns cache hit/miss stats for performance monitoring.
#[must_use]
pub fn luhn_cache_stats() -> CacheStats {
    LUHN_CACHE.stats()
}

/// Get ABA cache statistics
///
/// Returns cache hit/miss stats for performance monitoring.
#[must_use]
pub fn aba_cache_stats() -> CacheStats {
    ABA_CACHE.stats()
}

/// Get Bitcoin checksum cache statistics
#[must_use]
pub fn btc_checksum_cache_stats() -> CacheStats {
    BTC_CHECKSUM_CACHE.stats()
}

/// Get Ethereum EIP-55 cache statistics
#[must_use]
pub fn eth_eip55_cache_stats() -> CacheStats {
    ETH_EIP55_CACHE.stats()
}

/// Clear all financial detection caches
///
/// Useful for testing or when memory pressure is high.
pub fn clear_financial_caches() {
    LUHN_CACHE.clear();
    ABA_CACHE.clear();
    BTC_CHECKSUM_CACHE.clear();
    ETH_EIP55_CACHE.clear();
}

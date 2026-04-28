//! LRU cache for PII scan results
//!
//! Provides caching of scan results to avoid redundant regex operations.

use super::super::config::PiiScannerConfig;
use super::super::types::PiiType;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

/// Maximum cache size for scan results
pub(super) const CACHE_MAX_SIZE: usize = 1000;

/// Maximum text length to cache (longer texts are scanned but not cached)
pub(super) const CACHE_MAX_TEXT_LENGTH: usize = 1024;

/// Scanner statistics for health monitoring
pub(super) struct ScannerStats {
    /// Total scans performed
    pub(super) total_scans: AtomicU64,
    /// Cache hits
    pub(super) cache_hits: AtomicU64,
    /// Cache misses
    pub(super) cache_misses: AtomicU64,
    /// Total PII found
    pub(super) total_pii_found: AtomicU64,
    /// Total scan time in microseconds
    pub(super) total_scan_time_us: AtomicU64,
}

impl ScannerStats {
    pub(super) const fn new() -> Self {
        Self {
            total_scans: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            total_pii_found: AtomicU64::new(0),
            total_scan_time_us: AtomicU64::new(0),
        }
    }
}

/// Global scanner statistics
pub(super) static SCANNER_STATS: ScannerStats = ScannerStats::new();

/// Reset all scanner statistics to zero.
///
/// Test-only helper used by serial tests in `health.rs` that need to
/// drive the scanner into specific states by populating the atomic
/// counters directly.
#[cfg(test)]
pub(super) fn reset_stats() {
    SCANNER_STATS
        .total_scans
        .store(0, std::sync::atomic::Ordering::Relaxed);
    SCANNER_STATS
        .cache_hits
        .store(0, std::sync::atomic::Ordering::Relaxed);
    SCANNER_STATS
        .cache_misses
        .store(0, std::sync::atomic::Ordering::Relaxed);
    SCANNER_STATS
        .total_pii_found
        .store(0, std::sync::atomic::Ordering::Relaxed);
    SCANNER_STATS
        .total_scan_time_us
        .store(0, std::sync::atomic::Ordering::Relaxed);
}

/// LRU cache entry for scan results
struct CacheEntry {
    pii_types: Vec<PiiType>,
    last_access: Instant,
}

/// Simple LRU cache for scan results
pub(super) struct ScanCache {
    entries: HashMap<u64, CacheEntry>,
    max_size: usize,
}

impl ScanCache {
    fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_size),
            max_size,
        }
    }

    /// Get cached result if available
    pub(super) fn get(&mut self, hash: u64) -> Option<Vec<PiiType>> {
        if let Some(entry) = self.entries.get_mut(&hash) {
            entry.last_access = Instant::now();
            Some(entry.pii_types.clone())
        } else {
            None
        }
    }

    /// Insert result into cache, evicting oldest if necessary
    pub(super) fn insert(&mut self, hash: u64, pii_types: Vec<PiiType>) {
        // Evict oldest entry if at capacity
        if self.entries.len() >= self.max_size
            && let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.last_access)
                .map(|(k, _)| *k)
        {
            self.entries.remove(&oldest_key);
        }

        self.entries.insert(
            hash,
            CacheEntry {
                pii_types,
                last_access: Instant::now(),
            },
        );
    }

    /// Get the number of entries in the cache
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Clear all entries from the cache
    pub(super) fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Global scan cache
pub(super) static SCAN_CACHE: Lazy<Mutex<ScanCache>> =
    Lazy::new(|| Mutex::new(ScanCache::new(CACHE_MAX_SIZE)));

/// Simple hash function for cache keys
pub(super) fn hash_text(text: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

/// Hash function that includes config for cache keys
pub(super) fn hash_text_with_config(text: &str, config: &PiiScannerConfig) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    // Include config flags in hash
    config.scan_personal.hash(&mut hasher);
    config.scan_financial.hash(&mut hasher);
    config.scan_government.hash(&mut hasher);
    config.scan_medical.hash(&mut hasher);
    config.scan_biometric.hash(&mut hasher);
    config.scan_location.hash(&mut hasher);
    config.scan_organizational.hash(&mut hasher);
    config.scan_network.hash(&mut hasher);
    config.scan_tokens.hash(&mut hasher);
    hasher.finish()
}

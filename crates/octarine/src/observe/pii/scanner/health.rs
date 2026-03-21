//! Scanner health monitoring API
//!
//! Provides statistics and health checks for the PII scanner.

use super::cache::{SCAN_CACHE, SCANNER_STATS};
use std::sync::atomic::Ordering;

/// PII scanner statistics for monitoring
#[derive(Debug, Clone)]
pub struct PiiStatistics {
    /// Total number of scans performed
    pub total_scans: u64,
    /// Number of cache hits
    pub cache_hits: u64,
    /// Number of cache misses
    pub cache_misses: u64,
    /// Total PII instances found
    pub total_pii_found: u64,
    /// Total scan time in microseconds
    pub total_scan_time_us: u64,
    /// Cache hit rate (0.0 to 1.0)
    pub cache_hit_rate: f64,
    /// Average scan time in microseconds
    pub avg_scan_time_us: f64,
}

/// Get PII scanner statistics
///
/// Returns statistics about scanner performance including cache hits,
/// scan counts, and timing information.
pub fn scanner_stats() -> PiiStatistics {
    let total_scans = SCANNER_STATS.total_scans.load(Ordering::Relaxed);
    let cache_hits = SCANNER_STATS.cache_hits.load(Ordering::Relaxed);
    let cache_misses = SCANNER_STATS.cache_misses.load(Ordering::Relaxed);
    let total_pii_found = SCANNER_STATS.total_pii_found.load(Ordering::Relaxed);
    let total_scan_time_us = SCANNER_STATS.total_scan_time_us.load(Ordering::Relaxed);

    #[allow(clippy::arithmetic_side_effects)] // Safe: bounded u64 values
    let cache_hit_rate = if cache_hits + cache_misses > 0 {
        cache_hits as f64 / (cache_hits + cache_misses) as f64
    } else {
        0.0
    };

    let avg_scan_time_us = if total_scans > 0 {
        total_scan_time_us as f64 / total_scans as f64
    } else {
        0.0
    };

    PiiStatistics {
        total_scans,
        cache_hits,
        cache_misses,
        total_pii_found,
        total_scan_time_us,
        cache_hit_rate,
        avg_scan_time_us,
    }
}

/// Get scanner health score (0.0 to 1.0)
///
/// Combines cache performance and scan timing into a single health metric.
/// - 1.0 = excellent (high cache hit rate, low scan times)
/// - 0.5 = acceptable
/// - 0.0 = poor performance
pub fn scanner_health_score() -> f64 {
    let stats = scanner_stats();

    if stats.total_scans == 0 {
        return 1.0; // No data yet
    }

    // Cache hit rate contributes 60% of score
    let cache_score = stats.cache_hit_rate * 0.6;

    // Scan time contributes 40% of score
    // Target: <100μs avg scan time = 100% of time score
    // >1000μs = 0% of time score
    let time_score = if stats.avg_scan_time_us < 100.0 {
        0.4
    } else if stats.avg_scan_time_us > 1000.0 {
        0.0
    } else {
        // Linear interpolation
        0.4 * (1.0 - (stats.avg_scan_time_us - 100.0) / 900.0)
    };

    cache_score + time_score
}

/// Check if scanner is healthy
///
/// Returns true if cache hit rate > 20% and avg scan time < 500μs
pub fn scanner_is_healthy() -> bool {
    let stats = scanner_stats();

    if stats.total_scans < 10 {
        return true; // Not enough data
    }

    stats.cache_hit_rate > 0.2 && stats.avg_scan_time_us < 500.0
}

/// Check if scanner is degraded
///
/// Returns true if cache hit rate < 10% or avg scan time > 200μs
pub fn scanner_is_degraded() -> bool {
    let stats = scanner_stats();

    if stats.total_scans < 10 {
        return false; // Not enough data
    }

    stats.cache_hit_rate < 0.1 || stats.avg_scan_time_us > 200.0
}

/// Get current cache size
pub fn scanner_cache_size() -> usize {
    SCAN_CACHE.lock().len()
}

/// Clear the scanner cache
///
/// Useful for testing or when memory pressure is high.
pub fn clear_scanner_cache() {
    SCAN_CACHE.lock().clear();
}

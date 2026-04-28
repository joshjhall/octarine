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

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::super::cache::{SCANNER_STATS, reset_stats};
    use super::*;
    use serial_test::serial;
    use std::sync::atomic::Ordering;

    /// Populate `SCANNER_STATS` to a specific shape so the health
    /// thresholds can be exercised deterministically without running
    /// real scans (which would have variable timing).
    fn populate_stats(total_scans: u64, cache_hits: u64, cache_misses: u64, total_us: u64) {
        SCANNER_STATS
            .total_scans
            .store(total_scans, Ordering::Relaxed);
        SCANNER_STATS
            .cache_hits
            .store(cache_hits, Ordering::Relaxed);
        SCANNER_STATS
            .cache_misses
            .store(cache_misses, Ordering::Relaxed);
        SCANNER_STATS
            .total_scan_time_us
            .store(total_us, Ordering::Relaxed);
    }

    #[test]
    #[serial]
    fn test_scanner_stats_reflects_populated_counters() {
        reset_stats();
        populate_stats(100, 80, 20, 5_000);

        let stats = scanner_stats();
        assert_eq!(stats.total_scans, 100);
        assert_eq!(stats.cache_hits, 80);
        assert_eq!(stats.cache_misses, 20);
        assert!(
            (stats.cache_hit_rate - 0.8).abs() < f64::EPSILON,
            "cache_hit_rate = hits / (hits+misses) = 80/100 = 0.8, got {}",
            stats.cache_hit_rate,
        );
        assert!(
            (stats.avg_scan_time_us - 50.0).abs() < f64::EPSILON,
            "avg_scan_time_us = total_us / total_scans = 5000/100 = 50.0, got {}",
            stats.avg_scan_time_us,
        );

        reset_stats();
    }

    #[test]
    #[serial]
    fn test_scanner_stats_handles_zero_scans() {
        reset_stats();

        let stats = scanner_stats();
        assert_eq!(stats.total_scans, 0);
        // Division-by-zero guards must keep the derived metrics at 0.0.
        assert_eq!(stats.cache_hit_rate, 0.0);
        assert_eq!(stats.avg_scan_time_us, 0.0);
    }

    #[test]
    #[serial]
    fn test_scanner_is_healthy_with_no_data_returns_true() {
        reset_stats();
        // Below the 10-scan minimum, `scanner_is_healthy` returns true
        // because there isn't enough data to make a judgement.
        assert!(scanner_is_healthy());
        // ... and `scanner_is_degraded` returns false for the same reason.
        assert!(!scanner_is_degraded());
    }

    #[test]
    #[serial]
    fn test_scanner_is_healthy_with_high_cache_hit_rate() {
        reset_stats();
        // 90% hit rate, 50μs avg — clearly inside the healthy band
        // (cache_hit_rate > 20% AND avg_scan_time < 500μs).
        populate_stats(20, 18, 2, 1_000);

        assert!(scanner_is_healthy(), "should be healthy at 90% hits, 50μs");
        assert!(
            !scanner_is_degraded(),
            "must not be degraded at 90% hits, 50μs",
        );

        reset_stats();
    }

    #[test]
    #[serial]
    fn test_scanner_is_degraded_with_low_cache_hit_rate() {
        reset_stats();
        // 5% hit rate (< 10% degraded threshold), 100μs avg.
        populate_stats(20, 1, 19, 2_000);

        assert!(
            scanner_is_degraded(),
            "should be degraded at 5% hit rate (< 10% threshold)",
        );
        assert!(
            !scanner_is_healthy(),
            "must not be healthy at 5% hit rate (< 20% threshold)",
        );

        reset_stats();
    }

    #[test]
    #[serial]
    fn test_scanner_is_degraded_with_slow_scans() {
        reset_stats();
        // 90% hit rate (above healthy floor) but 750μs avg scan time —
        // crosses the > 200μs degraded threshold.
        populate_stats(20, 18, 2, 15_000);

        assert!(
            scanner_is_degraded(),
            "should be degraded at 750μs avg scan time (> 200μs threshold)",
        );
        // Slow scans also disqualify "healthy" (avg must be < 500μs).
        assert!(
            !scanner_is_healthy(),
            "must not be healthy at 750μs avg scan time (>= 500μs)",
        );

        reset_stats();
    }

    #[test]
    #[serial]
    fn test_scanner_health_score_returns_one_with_no_data() {
        reset_stats();
        // No scans yet — score is 1.0 by definition (no data to penalize).
        assert!(
            (scanner_health_score() - 1.0).abs() < f64::EPSILON,
            "health score must be 1.0 with no data, got {}",
            scanner_health_score(),
        );
    }

    #[test]
    #[serial]
    fn test_scanner_health_score_higher_for_healthy_than_degraded() {
        // Healthy snapshot: 90% hits, 50μs avg.
        reset_stats();
        populate_stats(20, 18, 2, 1_000);
        let healthy_score = scanner_health_score();

        // Degraded snapshot: 5% hits, 750μs avg.
        reset_stats();
        populate_stats(20, 1, 19, 15_000);
        let degraded_score = scanner_health_score();

        assert!(
            healthy_score > degraded_score,
            "healthy score ({healthy_score}) must exceed degraded score ({degraded_score})",
        );
        // Bounds check: scores live in [0.0, 1.0].
        assert!((0.0..=1.0).contains(&healthy_score));
        assert!((0.0..=1.0).contains(&degraded_score));

        reset_stats();
    }
}

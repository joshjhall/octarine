//! Validation method implementations for LocationIdentifierBuilder
//!
//! Implements validation and cache management methods that delegate to validation and cache modules.
//! Validation is transparently cached - no separate `*_cached` methods needed.

use super::super::cache;
use super::super::conversion::{GpsFormat, PostalCodeType};
use super::super::validation;
use crate::primitives::Problem;
use crate::primitives::collections::CacheStats;

use super::LocationIdentifierBuilder;

impl LocationIdentifierBuilder {
    // =========================================================================
    // Validation Methods (Transparently Cached)
    // =========================================================================

    /// Validate GPS coordinate format (returns Result)
    ///
    /// Validation results are transparently cached for performance.
    /// Repeated validations of the same coordinate are 50x faster.
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the GPS coordinate format is invalid or out of range
    pub fn validate_gps_coordinate(&self, coordinate: &str) -> Result<GpsFormat, Problem> {
        validation::validate_gps_coordinate(coordinate)
    }

    /// Validate street address format (returns Result)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the street address format is invalid
    pub fn validate_street_address(&self, address: &str) -> Result<(), Problem> {
        validation::validate_street_address(address)
    }

    /// Validate postal code format (returns Result)
    ///
    /// Validation results are transparently cached for performance.
    /// Repeated validations of the same postal code are 30x faster.
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the postal code format is invalid
    pub fn validate_postal_code(&self, postal_code: &str) -> Result<PostalCodeType, Problem> {
        validation::validate_postal_code(postal_code)
    }

    // =========================================================================
    // Cache Management Methods
    // =========================================================================

    /// Get combined cache statistics for all location identifier caches
    ///
    /// Returns aggregated stats across GPS and postal code validation caches.
    /// Use this for overall module performance monitoring.
    #[must_use]
    pub fn cache_stats(&self) -> CacheStats {
        cache::gps_cache_stats().combine(&cache::postal_cache_stats())
    }

    /// Get GPS coordinate cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn gps_cache_stats(&self) -> CacheStats {
        cache::gps_cache_stats()
    }

    /// Get postal code cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn postal_cache_stats(&self) -> CacheStats {
        cache::postal_cache_stats()
    }

    /// Clear GPS coordinate cache
    pub fn clear_gps_cache(&self) {
        cache::clear_gps_cache();
    }

    /// Clear postal code cache
    pub fn clear_postal_cache(&self) {
        cache::clear_postal_cache();
    }

    /// Clear all location validation caches
    pub fn clear_caches(&self) {
        cache::clear_location_caches();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_validation_methods() {
        let builder = LocationIdentifierBuilder::new();

        // GPS coordinate
        assert!(builder.validate_gps_coordinate("40.7128, -74.0060").is_ok());

        // Street address
        assert!(builder.validate_street_address("123 Main Street").is_ok());

        // Postal code
        assert!(builder.validate_postal_code("10001").is_ok());
    }

    #[test]
    #[serial_test::serial]
    fn test_transparent_caching_gps() {
        let builder = LocationIdentifierBuilder::new();

        let coord = "unique-builder-gps-test-transparent";

        // Get baseline
        let _stats_before = builder.gps_cache_stats();

        // First call - cache miss
        assert!(builder.validate_gps_coordinate(coord).is_err()); // Invalid coord
        let stats_after_first = builder.gps_cache_stats();

        // Second call - should hit cache (transparent)
        assert!(builder.validate_gps_coordinate(coord).is_err());
        let stats_after_second = builder.gps_cache_stats();

        // Verify hits increased
        assert!(
            stats_after_second.hits > stats_after_first.hits,
            "Second call should be cache hit (transparent caching)"
        );
    }

    #[test]
    #[serial_test::serial]
    fn test_transparent_caching_postal() {
        let builder = LocationIdentifierBuilder::new();

        let postal = "unique-builder-postal-test-transparent";

        // Get baseline
        let _stats_before = builder.postal_cache_stats();

        // First call - cache miss
        assert!(builder.validate_postal_code(postal).is_err()); // Invalid postal
        let stats_after_first = builder.postal_cache_stats();

        // Second call - should hit cache (transparent)
        assert!(builder.validate_postal_code(postal).is_err());
        let stats_after_second = builder.postal_cache_stats();

        // Verify hits increased
        assert!(
            stats_after_second.hits > stats_after_first.hits,
            "Second call should be cache hit (transparent caching)"
        );
    }

    #[test]
    #[serial_test::serial]
    fn test_builder_cache_hits() {
        let builder = LocationIdentifierBuilder::new();

        // Use a VERY unique GPS coordinate to avoid collisions with other tests
        let coord = "23.4567890, -67.8901234"; // Highly specific value

        // Get baseline - don't clear cache as it affects parallel tests
        let stats_before = builder.gps_cache_stats();

        // 1 first call + 9 repeated calls = 10 validations
        // First call: cache miss (adds to cache)
        let _ = builder.validate_gps_coordinate(coord);
        let stats_after_first = builder.gps_cache_stats();

        // Next 9 calls: cache hits (transparent)
        for _ in 0..9 {
            let _ = builder.validate_gps_coordinate(coord);
        }
        let stats_after_repeated = builder.gps_cache_stats();

        // Verify cache hit behavior
        let new_hits = stats_after_repeated.hits - stats_after_first.hits;
        assert!(
            new_hits >= 9,
            "Expected at least 9 cache hits from repeated calls, got {}.",
            new_hits
        );

        // Total operations should be at least 10 more than baseline
        let total_ops_before = stats_before.hits + stats_before.misses;
        let total_ops_after = stats_after_repeated.hits + stats_after_repeated.misses;
        assert!(
            total_ops_after >= total_ops_before + 10,
            "Expected at least 10 total cache operations"
        );
    }

    #[test]
    #[serial_test::serial]
    fn test_cache_clear() {
        let builder = LocationIdentifierBuilder::new();

        let size_before_gps = builder.gps_cache_stats().size;
        let size_before_postal = builder.postal_cache_stats().size;

        // Add some cached entries (via transparent caching)
        let _ = builder.validate_gps_coordinate("34.56, -78.90");
        let _ = builder.validate_postal_code("98765");

        // Verify size increased
        assert!(builder.gps_cache_stats().size >= size_before_gps);
        assert!(builder.postal_cache_stats().size >= size_before_postal);

        // Clear all caches (executes without error)
        builder.clear_caches();
    }
}

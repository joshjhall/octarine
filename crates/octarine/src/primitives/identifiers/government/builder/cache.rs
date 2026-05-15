//! Validation cache operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Get combined cache statistics for all government identifier caches
    ///
    /// Returns aggregated stats across SSN and VIN validation caches.
    /// Use this for overall module performance monitoring.
    #[must_use]
    pub fn cache_stats(&self) -> CacheStats {
        validation::ssn_cache_stats().combine(&validation::vin_cache_stats())
    }

    /// Get SSN validation cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn ssn_cache_stats(&self) -> CacheStats {
        validation::ssn_cache_stats()
    }

    /// Get VIN checksum cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn vin_cache_stats(&self) -> CacheStats {
        validation::vin_cache_stats()
    }

    /// Clear all validation caches
    ///
    /// Use this when memory pressure is high or to reset cache state.
    pub fn clear_caches(&self) {
        validation::clear_government_caches();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use serial_test::serial;

    fn builder() -> GovernmentIdentifierBuilder {
        GovernmentIdentifierBuilder::new()
    }

    #[test]
    #[serial]
    fn test_cache_stats() {
        let gov = builder();

        // Perform some validations to populate cache
        gov.validate_ssn("567-89-0123").ok();
        let _ = gov.validate_vin_with_checksum("55555555555555555");

        // Check stats are accessible - just verify they return without panic
        let _ssn_stats = gov.ssn_cache_stats();
        let _vin_stats = gov.vin_cache_stats();
    }

    #[test]
    #[serial]
    fn test_clear_caches() {
        let gov = builder();

        // Populate cache
        gov.validate_ssn("678-90-1234").ok();

        // Clear should not panic
        gov.clear_caches();

        // After clear, next validation should miss
        let stats_before = gov.ssn_cache_stats();
        gov.validate_ssn("678-90-1234").ok();
        let stats_after = gov.ssn_cache_stats();

        assert!(stats_after.misses > stats_before.misses);
    }
}

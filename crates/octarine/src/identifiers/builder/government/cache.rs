//! Cache management methods.

use super::*;

impl GovernmentBuilder {
    /// Get combined cache statistics for all government identifier caches
    ///
    /// Returns aggregated stats across SSN and VIN validation caches.
    /// Use this for overall module performance monitoring.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::identifiers::GovernmentBuilder;
    ///
    /// let builder = GovernmentBuilder::new();
    /// let stats = builder.cache_stats();
    ///
    /// println!("Cache size: {}/{}", stats.size, stats.capacity);
    /// println!("Hit rate: {:.1}%", stats.hit_rate());
    /// ```
    #[must_use]
    pub fn cache_stats(&self) -> crate::identifiers::types::CacheStats {
        self.inner.cache_stats()
    }

    /// Get SSN validation cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn ssn_cache_stats(&self) -> crate::identifiers::types::CacheStats {
        self.inner.ssn_cache_stats()
    }

    /// Get VIN validation cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn vin_cache_stats(&self) -> crate::identifiers::types::CacheStats {
        self.inner.vin_cache_stats()
    }

    /// Clear all government identifier caches
    ///
    /// Use this to reset cache state, typically for testing or memory management.
    pub fn clear_caches(&self) {
        self.inner.clear_caches();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_cache_stats_and_subcaches() {
        let b = GovernmentBuilder::silent();
        // Caches populate lazily on validation with checksum work.
        b.clear_caches();
        let _ = b.validate_ssn("234-56-7890");
        let _ = b.validate_vin_with_checksum("1HGBH41JXMN109186");

        let combined = b.cache_stats();
        let ssn = b.ssn_cache_stats();
        let vin = b.vin_cache_stats();

        // Combined capacity is the sum of the sub-cache capacities.
        assert_eq!(combined.capacity, ssn.capacity.saturating_add(vin.capacity));
        // Combined size equals the sum of the sub-cache sizes.
        assert_eq!(combined.size, ssn.size.saturating_add(vin.size));
        // Hit rate is a valid ratio.
        assert!((0.0..=100.0).contains(&combined.hit_rate()));
    }

    #[test]
    fn test_clear_caches_resets_size() {
        let b = GovernmentBuilder::silent();
        let _ = b.validate_vin_with_checksum("1HGBH41JXMN109186");
        b.clear_caches();
        assert_eq!(b.cache_stats().size, 0);
    }
}

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

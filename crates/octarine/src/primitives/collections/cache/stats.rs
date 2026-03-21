//! Cache statistics
//!
//! Shared statistics types for all cache implementations.

/// Statistics for a cache
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Used by higher layers
pub struct CacheStats {
    /// Current number of items in the cache
    pub size: usize,

    /// Maximum capacity of the cache
    pub capacity: usize,

    /// Total cache hits
    pub hits: usize,

    /// Total cache misses
    pub misses: usize,

    /// Total evictions due to capacity
    pub evictions: usize,
}

#[allow(dead_code)] // Used by higher layers
impl CacheStats {
    /// Calculate the hit rate as a percentage
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits.saturating_add(self.misses);
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }

    /// Calculate the current utilization as a percentage
    pub fn utilization(&self) -> f64 {
        if self.capacity == 0 {
            0.0
        } else {
            (self.size as f64 / self.capacity as f64) * 100.0
        }
    }

    /// Combine two cache stats into one (aggregate)
    ///
    /// Useful for reporting combined stats across multiple caches in a module.
    #[must_use]
    pub fn combine(&self, other: &CacheStats) -> CacheStats {
        CacheStats {
            size: self.size.saturating_add(other.size),
            capacity: self.capacity.saturating_add(other.capacity),
            hits: self.hits.saturating_add(other.hits),
            misses: self.misses.saturating_add(other.misses),
            evictions: self.evictions.saturating_add(other.evictions),
        }
    }
}

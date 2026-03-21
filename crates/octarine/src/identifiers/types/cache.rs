//! Cache statistics types
//!
//! Types for monitoring cache performance in identifier validation.

/// Statistics for identifier validation caches
///
/// Provides visibility into cache performance for production monitoring.
/// Each identifier module maintains caches for expensive validation operations.
///
/// # Example
///
/// ```rust
/// use octarine::identifiers::PersonalBuilder;
///
/// let builder = PersonalBuilder::new();
/// let stats = builder.cache_stats();
///
/// println!("Cache hit rate: {:.1}%", stats.hit_rate());
/// println!("Cache utilization: {:.1}%", stats.utilization());
/// ```
#[derive(Debug, Clone, Copy, Default)]
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

impl CacheStats {
    /// Calculate the hit rate as a percentage (0-100)
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits.saturating_add(self.misses);
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }

    /// Calculate the current utilization as a percentage (0-100)
    #[must_use]
    pub fn utilization(&self) -> f64 {
        if self.capacity == 0 {
            0.0
        } else {
            (self.size as f64 / self.capacity as f64) * 100.0
        }
    }

    /// Check if the cache is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl From<crate::primitives::collections::CacheStats> for CacheStats {
    fn from(s: crate::primitives::collections::CacheStats) -> Self {
        Self {
            size: s.size,
            capacity: s.capacity,
            hits: s.hits,
            misses: s.misses,
            evictions: s.evictions,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_cache_stats_hit_rate() {
        let stats = CacheStats {
            size: 50,
            capacity: 100,
            hits: 80,
            misses: 20,
            evictions: 5,
        };
        assert!((stats.hit_rate() - 80.0).abs() < 0.001);
    }

    #[test]
    fn test_cache_stats_utilization() {
        let stats = CacheStats {
            size: 50,
            capacity: 100,
            hits: 0,
            misses: 0,
            evictions: 0,
        };
        assert!((stats.utilization() - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_cache_stats_empty() {
        let stats = CacheStats::default();
        assert!(stats.is_empty());
        assert!((stats.hit_rate() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_cache_stats_zero_capacity() {
        let stats = CacheStats {
            size: 0,
            capacity: 0,
            hits: 0,
            misses: 0,
            evictions: 0,
        };
        assert!((stats.utilization() - 0.0).abs() < 0.001);
    }
}

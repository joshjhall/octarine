//! Cache entry type
//!
//! Shared entry type for all cache implementations.

use std::time::Instant;

/// A cache entry with expiration
#[derive(Debug, Clone)]
#[allow(dead_code)] // Used by higher layers
pub struct CacheEntry<V: Clone> {
    /// The cached value
    pub value: V,

    /// When this entry expires
    pub expires_at: Instant,

    /// When this entry was last accessed
    pub last_accessed: Instant,
}

#[allow(dead_code)] // Used by higher layers
impl<V: Clone> CacheEntry<V> {
    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    /// Update the last accessed time
    pub fn touch(&mut self) {
        self.last_accessed = Instant::now();
    }
}

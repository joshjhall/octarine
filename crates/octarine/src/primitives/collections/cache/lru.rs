//! LRU cache implementation
//!
//! A thread-safe least-recently-used cache with time-based expiration.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use super::entry::CacheEntry;
use super::stats::CacheStats;

/// A thread-safe LRU cache with TTL
///
/// Combines least-recently-used eviction with time-based expiration for optimal
/// cache management. Perfect for caching expensive computations, API responses,
/// or any data that becomes stale over time.
///
/// # Thread Safety
///
/// Uses `Arc<RwLock<>>` internally, allowing cheap cloning and safe concurrent access.
/// Multiple threads can read and write simultaneously.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::collections::cache::LruCache;
/// use std::time::Duration;
///
/// // Create cache with 1000 entry capacity, 5 minute TTL
/// let cache = LruCache::new(1000, Duration::from_secs(300));
///
/// // Thread-safe: can clone and share
/// let cache_clone = cache.clone();
///
/// cache.insert("key1", "value1");
/// cache_clone.insert("key2", "value2");
///
/// assert_eq!(cache.len(), 2);
/// ```
#[allow(dead_code)] // Used by higher layers
pub struct LruCache<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    inner: Arc<RwLock<LruCacheInner<K, V>>>,
    capacity: usize,
    ttl: Duration,
}

#[allow(dead_code)] // Used by higher layers
struct LruCacheInner<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    map: HashMap<K, CacheEntry<V>>,
    hits: usize,
    misses: usize,
    evictions: usize,
}

#[allow(dead_code)] // Used by higher layers
impl<K, V> LruCache<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    /// Create a new LRU cache with specified capacity and TTL
    ///
    /// # Panics
    ///
    /// Panics if capacity is 0.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::collections::cache::LruCache;
    /// use std::time::Duration;
    ///
    /// // 100 entries, 5 minute TTL
    /// let cache: LruCache<String, String> = LruCache::new(100, Duration::from_secs(300));
    /// assert_eq!(cache.len(), 0);
    ///
    /// // Short TTL for temporary data
    /// let temp_cache: LruCache<i32, Vec<u8>> = LruCache::new(50, Duration::from_secs(30));
    /// ```
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        assert!(capacity > 0, "Cache capacity must be greater than 0");

        Self {
            inner: Arc::new(RwLock::new(LruCacheInner {
                map: HashMap::with_capacity(capacity),
                hits: 0,
                misses: 0,
                evictions: 0,
            })),
            capacity,
            ttl,
        }
    }

    /// Create a cache with default TTL of 5 minutes
    ///
    /// Convenience constructor for common use cases where 5 minutes is an
    /// appropriate TTL.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::collections::cache::LruCache;
    ///
    /// let cache: LruCache<String, i32> = LruCache::with_capacity(100);
    /// ```
    pub fn with_capacity(capacity: usize) -> Self {
        Self::new(capacity, Duration::from_secs(300))
    }

    /// Insert a value into the cache
    ///
    /// If the cache is at capacity, the least-recently-used entry is evicted.
    /// If the key already exists, the old value is returned and the entry's
    /// expiration time is reset.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::collections::cache::LruCache;
    /// use std::time::Duration;
    ///
    /// let cache = LruCache::new(2, Duration::from_secs(300));
    ///
    /// // Insert new values
    /// assert_eq!(cache.insert("a", 1), None);
    /// assert_eq!(cache.insert("b", 2), None);
    ///
    /// // Update existing value (returns old value)
    /// assert_eq!(cache.insert("a", 10), Some(1));
    ///
    /// // Capacity reached - evicts LRU entry
    /// cache.insert("c", 3);  // Evicts "b"
    /// assert_eq!(cache.get(&"b"), None);
    /// ```
    pub fn insert(&self, key: K, value: V) -> Option<V> {
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Check if we need to evict
        if inner.map.len() >= self.capacity && !inner.map.contains_key(&key) {
            // Find and remove the oldest entry
            if let Some(oldest_key) = self.find_oldest(&inner) {
                inner.map.remove(&oldest_key);
                inner.evictions = inner.evictions.saturating_add(1);
            }
        }

        let now = Instant::now();
        let entry = CacheEntry {
            value: value.clone(),
            expires_at: now.checked_add(self.ttl).unwrap_or(now),
            last_accessed: now,
        };

        inner.map.insert(key, entry).map(|e| e.value)
    }

    /// Get a value from the cache
    ///
    /// Returns `None` if the key doesn't exist or if the entry has expired.
    /// On a hit, updates the entry's last-accessed time (for LRU tracking).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::collections::cache::LruCache;
    /// use std::time::Duration;
    ///
    /// let cache = LruCache::new(100, Duration::from_secs(300));
    ///
    /// cache.insert("key", "value");
    /// assert_eq!(cache.get(&"key"), Some("value"));
    /// assert_eq!(cache.get(&"missing"), None);
    /// ```
    pub fn get(&self, key: &K) -> Option<V> {
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Check if entry exists and is not expired
        let exists_and_valid = inner.map.get(key).map(|e| !e.is_expired()).unwrap_or(false);

        if exists_and_valid {
            // Entry exists and is valid - extract value first
            let value = inner.map.get(key).map(|e| e.value.clone());

            // Then update stats and touch
            if let Some(entry) = inner.map.get_mut(key) {
                entry.touch();
            }
            inner.hits = inner.hits.saturating_add(1);
            value
        } else if inner.map.contains_key(key) {
            // Entry exists but is expired
            inner.map.remove(key);
            inner.misses = inner.misses.saturating_add(1);
            None
        } else {
            // Entry doesn't exist
            inner.misses = inner.misses.saturating_add(1);
            None
        }
    }

    /// Remove a value from the cache
    pub fn remove(&self, key: &K) -> Option<V> {
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.map.remove(key).map(|e| e.value)
    }

    /// Clear the entire cache
    pub fn clear(&self) {
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.map.clear();
    }

    /// Get the current size of the cache
    pub fn len(&self) -> usize {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.map.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.map.is_empty()
    }

    /// Clean up expired entries
    ///
    /// Removes all entries that have exceeded their TTL. Returns the number
    /// of entries removed. Call this periodically to reclaim memory from
    /// expired entries.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use octarine::primitives::collections::cache::LruCache;
    /// use std::time::Duration;
    /// use std::thread;
    ///
    /// let cache = LruCache::new(100, Duration::from_millis(50));
    ///
    /// cache.insert("key1", 1);
    /// cache.insert("key2", 2);
    ///
    /// // Wait for expiration
    /// thread::sleep(Duration::from_millis(60));
    ///
    /// let removed = cache.cleanup_expired();
    /// assert_eq!(removed, 2);
    /// assert_eq!(cache.len(), 0);
    /// ```
    pub fn cleanup_expired(&self) -> usize {
        let mut inner = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();

        let expired_keys: Vec<K> = inner
            .map
            .iter()
            .filter(|(_, entry)| now > entry.expires_at)
            .map(|(k, _)| k.clone())
            .collect();

        let count = expired_keys.len();
        for key in expired_keys {
            inner.map.remove(&key);
        }

        count
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let inner = self
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        CacheStats {
            size: inner.map.len(),
            capacity: self.capacity,
            hits: inner.hits,
            misses: inner.misses,
            evictions: inner.evictions,
        }
    }

    /// Find the oldest entry by last accessed time
    fn find_oldest(&self, inner: &LruCacheInner<K, V>) -> Option<K> {
        inner
            .map
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
            .map(|(k, _)| k.clone())
    }
}

impl<K, V> Clone for LruCache<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            capacity: self.capacity,
            ttl: self.ttl,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_cache_basic_operations() {
        let cache: LruCache<String, i32> = LruCache::with_capacity(3);

        cache.insert("one".to_string(), 1);
        cache.insert("two".to_string(), 2);
        cache.insert("three".to_string(), 3);

        assert_eq!(cache.get(&"one".to_string()), Some(1));
        assert_eq!(cache.get(&"two".to_string()), Some(2));
        assert_eq!(cache.get(&"three".to_string()), Some(3));
        assert_eq!(cache.get(&"four".to_string()), None);

        let stats = cache.stats();
        assert_eq!(stats.hits, 3);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_cache_eviction() {
        let cache: LruCache<i32, String> = LruCache::with_capacity(2);

        cache.insert(1, "one".to_string());
        cache.insert(2, "two".to_string());
        cache.insert(3, "three".to_string()); // Should evict least recently used

        assert_eq!(cache.len(), 2);

        let stats = cache.stats();
        assert_eq!(stats.evictions, 1);
    }

    #[test]
    fn test_cache_expiration() {
        let cache: LruCache<&str, &str> = LruCache::new(10, Duration::from_millis(50));

        cache.insert("key", "value");
        assert_eq!(cache.get(&"key"), Some("value"));

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(60));

        assert_eq!(cache.get(&"key"), None);
    }

    #[test]
    fn test_cache_cleanup() {
        let cache: LruCache<i32, i32> = LruCache::new(10, Duration::from_millis(50));

        for i in 0..5 {
            cache.insert(i, i * 10);
        }

        assert_eq!(cache.len(), 5);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(60));

        let expired = cache.cleanup_expired();
        assert_eq!(expired, 5);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_thread_safety() {
        use std::sync::Arc;
        use std::sync::Barrier;
        use std::thread;

        let cache: LruCache<i32, i32> = LruCache::with_capacity(100);

        // Pre-populate cache to ensure there's always data to read
        for i in 0..10 {
            cache.insert(i, i * 2);
        }

        let cache_clone = cache.clone();
        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = Arc::clone(&barrier);

        let writer = thread::spawn(move || {
            barrier_clone.wait(); // Synchronize start
            for i in 10..60 {
                cache_clone.insert(i, i * 2);
            }
        });

        let reader = thread::spawn(move || {
            barrier.wait(); // Synchronize start
            let mut found = 0;
            for i in 0..60 {
                if cache.get(&i).is_some() {
                    found += 1;
                }
            }
            found
        });

        writer
            .join()
            .expect("Writer thread should complete successfully");
        let found = reader
            .join()
            .expect("Reader thread should complete successfully");

        // Should always find at least the pre-populated values (0..10)
        assert!(
            found >= 10,
            "Expected at least 10 cache hits (pre-populated), got {}",
            found
        );
    }
}

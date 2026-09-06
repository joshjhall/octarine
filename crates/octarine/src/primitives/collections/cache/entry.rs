//! Cache entry type
//!
//! Shared entry type for all cache implementations.

use std::time::{Duration, Instant};

/// A cache entry with expiration
#[derive(Debug, Clone)]
#[allow(dead_code)] // Used by higher layers
pub struct CacheEntry<V: Clone> {
    /// The cached value
    pub value: V,

    /// When this entry expires, or `None` if it never expires.
    ///
    /// Fixed at construction from the creation instant plus the TTL, and
    /// never recomputed — this is an absolute TTL, so `touch()` does *not*
    /// extend an entry's lifetime.
    ///
    /// `None` is reached only when that addition overflows `Instant` (an
    /// absurdly long TTL). Saturating toward "never expires" is the only
    /// safe direction: the opposite fallback would yield an entry that is
    /// already expired at construction, so a caller asking for the longest
    /// possible lifetime would silently get a cache that stores nothing.
    /// Callers should therefore pass a TTL from a bounded, trusted source
    /// rather than relying on this saturation.
    pub expires_at: Option<Instant>,

    /// When this entry was last accessed
    pub last_accessed: Instant,
}

#[allow(dead_code)] // Used by higher layers
impl<V: Clone> CacheEntry<V> {
    /// Create an entry that expires `ttl` after now.
    ///
    /// A `ttl` that overflows `Instant` yields a non-expiring entry.
    pub fn new(value: V, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            value,
            expires_at: now.checked_add(ttl),
            last_accessed: now,
        }
    }

    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Instant::now())
    }

    /// Check if this entry has expired as of `now`.
    ///
    /// Taking the reference instant as a parameter lets a caller classify a
    /// whole batch of entries against one clock reading (see
    /// `LruCache::cleanup_expired`) instead of re-reading the clock per
    /// entry, so the batch cannot straddle an expiry boundary partway
    /// through.
    pub fn is_expired_at(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|expires_at| now > expires_at)
    }

    /// Update the last accessed time
    pub fn touch(&mut self) {
        self.last_accessed = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_not_expired_within_ttl() {
        let entry = CacheEntry::new("value", Duration::from_secs(60));
        assert!(entry.expires_at.is_some());
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_entry_expired_after_ttl() {
        let ttl = Duration::from_millis(50);
        let entry = CacheEntry::new("value", ttl);

        // `new` reads the clock once, so expiry is exactly ttl past
        // last_accessed. Deriving the reference instants from that field
        // avoids unwrapping the Option.
        let expires_at = entry.last_accessed + ttl;
        assert_eq!(entry.expires_at, Some(expires_at));

        // Classify against explicit instants rather than sleeping — no
        // wall-clock dependency, so the assertion cannot be perturbed by
        // scheduling (issue #724).
        assert!(entry.is_expired_at(expires_at + Duration::from_millis(1)));
        // And is NOT expired just before that instant.
        assert!(!entry.is_expired_at(expires_at - Duration::from_millis(1)));
        // Boundary: `is_expired_at` is a strict `>`, so the expiry instant
        // itself is still live.
        assert!(!entry.is_expired_at(expires_at));
    }

    #[test]
    fn test_overflowing_ttl_never_expires() {
        // A TTL that overflows Instant must saturate to "never expires",
        // NOT to "already expired" (issue #724, AC5).
        let entry = CacheEntry::new("value", Duration::MAX);
        assert_eq!(
            entry.expires_at, None,
            "overflowing TTL should yield a non-expiring entry"
        );
        assert!(!entry.is_expired());
        // Still alive arbitrarily far in the future.
        assert!(!entry.is_expired_at(entry.last_accessed + Duration::from_secs(86_400)));
    }

    #[test]
    fn test_new_entry_carries_a_fresh_deadline() {
        // `LruCache::insert` promises that re-inserting a key resets its
        // expiry, and it delivers that purely by building a new entry via
        // `CacheEntry::new`. Pin the property here rather than in lru.rs:
        // a cache-level test would have to race a real TTL against the
        // wall clock, which is the very defect #724 is about. Comparing two
        // successive entries' deadlines is exact and stall-proof.
        let ttl = Duration::from_secs(60);
        let first = CacheEntry::new("first", ttl);

        std::thread::sleep(Duration::from_millis(1));

        let second = CacheEntry::new("second", ttl);

        assert!(
            second.expires_at > first.expires_at,
            "a newly built entry must carry a later deadline than its predecessor"
        );
        assert_eq!(second.expires_at, Some(second.last_accessed + ttl));
    }

    #[test]
    fn test_touch_updates_last_accessed() {
        let mut entry = CacheEntry::new("value", Duration::from_secs(60));
        let before = entry.last_accessed;

        // Force a measurable gap so the assertion below can distinguish
        // "touch() refreshed the timestamp" from "touch() did nothing".
        // A `>=` assertion here would be vacuous: Instant is monotonic, so
        // a no-op touch() leaves last_accessed == before, which still
        // satisfies `>=`. 1ms is well under the Rule 4 sleep threshold and
        // is not a timing assertion — a slow runner only widens the gap.
        std::thread::sleep(Duration::from_millis(1));

        entry.touch();

        assert!(
            entry.last_accessed > before,
            "touch() must refresh last_accessed, not leave it at its construction value"
        );
        // touch() must not disturb expiry — this cache uses absolute
        // (creation-time) TTL, not a sliding window.
        assert_eq!(entry.expires_at, Some(before + Duration::from_secs(60)));
    }
}

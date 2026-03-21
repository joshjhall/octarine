//! Cache primitives for key-value storage with eviction
//!
//! Thread-safe cache implementations with automatic eviction policies.
//!
//! ## Available Caches
//!
//! - `LruCache` - Least-recently-used cache with TTL expiration
//!
//! ## Shared Types
//!
//! - `CacheEntry` - Entry type with expiration metadata
//! - `CacheStats` - Statistics for monitoring cache usage
//!
//! ## Usage Examples
//!
//! ### Basic LRU Cache
//!
//! ```rust,ignore
//! use crate::primitives::collections::LruCache;
//! use std::time::Duration;
//!
//! let cache = LruCache::new(100, Duration::from_secs(300));
//!
//! cache.insert("user:123", "Alice");
//! cache.insert("user:456", "Bob");
//!
//! assert_eq!(cache.get(&"user:123"), Some("Alice"));
//! assert_eq!(cache.get(&"user:789"), None);  // Miss
//!
//! let stats = cache.stats();
//! assert_eq!(stats.hits, 1);
//! assert_eq!(stats.misses, 1);
//! ```
//!
//! ### LRU Eviction
//!
//! ```rust,ignore
//! use crate::primitives::collections::LruCache;
//! use std::time::Duration;
//!
//! let cache = LruCache::new(2, Duration::from_secs(300));
//!
//! cache.insert("a", 1);
//! cache.insert("b", 2);
//! cache.get(&"a");  // Access "a" to make it recently used
//! cache.insert("c", 3);  // Evicts "b" (least recently used)
//!
//! assert_eq!(cache.get(&"a"), Some(1));  // Still present
//! assert_eq!(cache.get(&"b"), None);     // Evicted
//! assert_eq!(cache.get(&"c"), Some(3));  // Present
//! ```

mod entry;
mod lru;
mod stats;

pub use entry::CacheEntry;
pub use lru::LruCache;
pub use stats::CacheStats;

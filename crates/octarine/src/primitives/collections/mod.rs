//! Collection primitives for rust-core
//!
//! Thread-safe data structures for bounded storage and caching.
//!
//! ## Module Contents
//!
//! - `buffer` - Thread-safe buffer implementations (RingBuffer)
//! - `cache` - Cache implementations with eviction policies (LruCache)
//!
//! ## Architecture Note
//!
//! This is a **Layer 1 primitive** module - shared foundational collections.
//! It has NO dependencies on observe or other internal modules.
//!
//! ## Naming Convention
//!
//! These types do NOT use the `Primitive*` prefix because:
//! - They are internal utilities used directly by higher layers
//! - `observe/metrics` uses `RingBuffer` directly (no wrapping needed)
//! - `primitives/data/identifiers` uses `LruCache` directly for caching
//! - Built-in `*Stats` types provide observability without wrapping
//!
//! This follows the same pattern as `Secret<T>`, `SecretString` in crypto/secrets.
//!
//! ## Features
//!
//! - **Fixed capacity**: Prevents unbounded memory growth
//! - **Thread-safe**: Uses `Arc<RwLock<>>` for safe concurrent access
//! - **Statistics tracking**: Monitors usage patterns
//! - **Clone-friendly**: Shared ownership via `Arc`
//!
//! ## Usage Examples
//!
//! ### Ring Buffer
//!
//! ```rust,ignore
//! use crate::primitives::collections::RingBuffer;
//!
//! let buffer = RingBuffer::new(100);
//! buffer.push("event").unwrap();
//! let item = buffer.pop().unwrap();
//! ```
//!
//! ### LRU Cache
//!
//! ```rust,ignore
//! use crate::primitives::collections::LruCache;
//! use std::time::Duration;
//!
//! let cache = LruCache::new(1000, Duration::from_secs(300));
//! cache.insert("key", "value");
//! let value = cache.get(&"key");
//! ```

// Allow dead_code: Layer 1 primitives used by Layer 2/3
#![allow(dead_code)]

mod buffer;
mod cache;

// Re-export commonly used types at the collections level
#[allow(unused_imports)]
pub use buffer::{BufferError, BufferStats, RingBuffer};
#[allow(unused_imports)]
pub use cache::{CacheEntry, CacheStats, LruCache};

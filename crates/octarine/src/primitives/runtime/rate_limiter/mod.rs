//! Rate Limiting Primitives
//!
//! Pure rate limiting utilities with NO observe dependencies.
//! Wraps the `governor` crate with a simplified, ergonomic API.
//!
//! ## Architecture Layer
//!
//! This is **Layer 1 (primitives)** - pure utilities with no observe dependencies.
//!
//! - **Layer 1 (primitives)**: Pure algorithms, no internal dependencies ← YOU ARE HERE
//! - **Layer 2 (observe)**: Can use these primitives for log throttling
//! - **Layer 3 (runtime)**: Wraps with observe instrumentation
//!
//! ## Public API
//!
//! **For external usage, use [`crate::runtime::rate_limiter`] which provides
//! the same functionality with observability (logging, metrics, audit trails).**
//!
//! ## Features
//!
//! - **GCRA Algorithm**: Generic Cell Rate Algorithm (functionally equivalent to token bucket)
//! - **Keyed Rate Limiting**: Rate limit by any hashable key (IP, user ID, API key, etc.)
//! - **Thread-Safe**: Safe for concurrent access from multiple threads
//! - **Async Support**: `until_ready()` for async waiting

mod limiter;
mod types;

// Re-exports for Layer 2 (observe) and Layer 3 (runtime)
#[allow(unused_imports)]
pub use limiter::RateLimiter;
#[allow(unused_imports)]
pub use types::{Decision, RateLimitError, RateLimiterStats};

// Re-export governor's Quota for advanced usage
#[allow(unused_imports)]
pub use governor::Quota;

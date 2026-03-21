//! HTTP client primitives
//!
//! Pure HTTP client wrapper with retry, rate limiting, and circuit breaker support.
//! NO observe dependencies - these are the building blocks for Layer 3 (runtime/http).
//!
//! ## Features
//!
//! - **Retry**: Configurable retry with HTTP-specific classification
//! - **Circuit Breaker**: Integration with existing circuit breaker primitives
//! - **Rate Limiting**: Integration with existing rate limiter primitives
//! - **Response Metadata**: Track attempts, latency, and retry status
//!
//! ## Design Notes
//!
//! This is a **primitive** module - it has NO dependencies on observe or other
//! internal modules. The actual HTTP client with observability is in `runtime::http`.

// Public API primitives - not all items used internally yet
#![allow(dead_code)]

pub mod client;
mod config;
mod response;
mod retry;

pub use client::{HttpClient, HttpClientError, HttpRequestBuilder};
pub use config::{HttpClientConfig, HttpClientConfigBuilder};
pub use response::HttpResponse;

// Re-export retry classification for custom retry logic
// These are part of the public API for users who need custom retry decisions
#[allow(unused_imports)]
pub use retry::{
    RetryDecision, classify_error, classify_status, is_retryable_error, is_retryable_status,
};

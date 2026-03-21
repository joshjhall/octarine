//! HTTP client with built-in observability
//!
//! Provides an HTTP client that wraps the primitives with comprehensive logging,
//! metrics, and error context. Use this for making HTTP requests from application code.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │ runtime::http (this module)                             │
//! │ - Full observability (events, metrics, logging)         │
//! │ - Rich error context with Problem type                  │
//! │ - Audit trails and compliance tags                      │
//! └─────────────────────────────────────────────────────────┘
//!          ↓ wraps
//! ┌─────────────────────────────────────────────────────────┐
//! │ primitives/runtime/http                                 │
//! │ - Pure implementations, no dependencies                 │
//! │ - Core retry, circuit breaker, rate limiting            │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ## Basic Usage
//!
//! ```rust,ignore
//! use octarine::runtime::http::HttpClient;
//!
//! // Create client with preset
//! let client = HttpClient::for_external_api()?;
//!
//! // Make requests
//! let response = client.get("https://api.example.com/users/123")
//!     .bearer_auth("token")
//!     .send()
//!     .await?;
//!
//! println!("Status: {}", response.status());
//! println!("Attempts: {}", response.attempts());
//! ```
//!
//! ## With Custom Configuration
//!
//! ```rust,ignore
//! use octarine::runtime::http::{HttpClient, HttpClientConfig};
//! use std::time::Duration;
//!
//! let config = HttpClientConfig::builder()
//!     .base_url("https://api.example.com")
//!     .timeout(Duration::from_secs(30))
//!     .rate_limit(100, Duration::from_secs(60))
//!     .build();
//!
//! let client = HttpClient::new(config)?;
//! ```
//!
//! ## Presets
//!
//! | Preset | Retry | Circuit Breaker | Rate Limit | Use Case |
//! |--------|-------|-----------------|------------|----------|
//! | `for_external_api()` | 5 attempts, exp backoff | 3 failures trip | None | Third-party APIs |
//! | `for_internal_service()` | 3 attempts, 50ms backoff | 10 failures trip | None | Microservices |
//! | `for_webhook()` | 3 attempts, 1s backoff | 5 failures trip | 10/sec | Outgoing webhooks |
//! | `for_cli()` | 2 attempts, 100ms backoff | None | None | CLI tools |

mod client;

pub use client::HttpClient;

// Re-export config types from primitives
pub use crate::primitives::runtime::http::{
    HttpClientConfig, HttpClientConfigBuilder, HttpResponse,
};

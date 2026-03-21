//! HTTP middleware preset configurations
//!
//! This module provides opinionated, security-focused configurations for common
//! HTTP middleware. Instead of configuring tower-http and tower-governor directly,
//! use these presets to ensure consistent security defaults across services.
//!
//! # Available Presets
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`cors`] | CORS configurations (development, production, read-only) |
//! | [`rate_limit`] | Rate limiting (API, auth, search, upload, webhook) |
//! | [`limits`] | Request body size limits |
//! | [`timeout`] | Request timeout configurations |
//! | [`compression`] | Response compression |
//!
//! # Recommended Middleware Stack
//!
//! Apply middleware in this order (outermost first):
//!
//! ```rust,ignore
//! use axum::Router;
//! use octarine::http::{RequestIdLayer, ContextLayer};
//! use octarine::http::presets::{cors, compression, limits, timeout};
//!
//! let app = Router::new()
//!     .route("/api/data", axum::routing::get(handler))
//!     // Layer order: bottom layers run first on request, last on response
//!     .layer(compression::default_compression())  // Compress responses
//!     .layer(cors::production(&["https://app.example.com"]))
//!     .layer(ContextLayer::new())                 // Extract tenant/user
//!     .layer(limits::default_body())              // Limit request size
//!     .layer(timeout::default_timeout())          // Timeout slow requests
//!     .layer(RequestIdLayer::new());              // Add correlation ID
//!
//! async fn handler() -> &'static str { "ok" }
//! ```
//!
//! # Per-Route Rate Limiting
//!
//! Apply rate limiting to specific routes:
//!
//! ```rust,ignore
//! use axum::{Router, routing::{get, post}};
//! use octarine::http::presets::rate_limit;
//!
//! let app = Router::new()
//!     .route("/login", post(login).layer(rate_limit::auth()))
//!     .route("/search", get(search).layer(rate_limit::search()))
//!     .route("/api/data", get(data).layer(rate_limit::api()));
//! ```
//!
//! # Custom Configurations
//!
//! When presets don't match your needs, use the builders or raw tower-http APIs:
//!
//! ```rust,ignore
//! use octarine::http::presets::rate_limit::RateLimitBuilder;
//! use octarine::http::presets::limits;
//!
//! // Custom rate limit
//! let custom_limit = RateLimitBuilder::new()
//!     .requests_per_minute(200)
//!     .burst_size(300)
//!     .build();
//!
//! // Custom body limit
//! let custom_body = limits::custom_body(25 * 1024 * 1024); // 25 MB
//! ```

pub mod compression;
pub mod cors;
pub mod limits;
pub mod rate_limit;
pub mod timeout;

// Re-export key types for convenience (directly from tower-http/tower_governor)
pub use tower_governor::GovernorLayer;
pub use tower_http::compression::CompressionLayer;
pub use tower_http::cors::CorsLayer;
pub use tower_http::limit::RequestBodyLimitLayer;
pub use tower_http::timeout::TimeoutLayer;

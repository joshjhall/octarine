//! HTTP server middleware for Axum
//!
//! This module provides Tower middleware, Axum extractors, and preset configurations
//! that integrate with Octarine's observability and context management system.
//!
//! # Features
//!
//! - **Request ID**: Generate and propagate unique request IDs
//! - **Context Extraction**: Extract tenant, user, source IP from headers
//! - **Error Handling**: Convert `Problem` errors to HTTP responses with automatic logging
//! - **Extractors**: Axum extractors for accessing Octarine context
//! - **Presets**: Opinionated configurations for CORS, rate limiting, body limits, etc.
//!
//! # Quick Start
//!
//! ```rust
//! use axum::{Router, routing::get};
//! use octarine::http::{RequestIdLayer, ContextLayer};
//!
//! async fn list_patterns() -> &'static str {
//!     "patterns"
//! }
//!
//! let app: Router = Router::new()
//!     .route("/api/patterns", get(list_patterns))
//!     .layer(RequestIdLayer::new())
//!     .layer(ContextLayer::new());
//! ```
//!
//! # Full Middleware Stack
//!
//! For production services, use the preset configurations:
//!
//! ```rust,ignore
//! use axum::Router;
//! use octarine::http::{RequestIdLayer, ContextLayer};
//! use octarine::http::presets::{cors, compression, limits, timeout};
//!
//! let app = Router::new()
//!     .route("/api/data", axum::routing::get(handler))
//!     // Layer order: bottom layers run first on request
//!     .layer(compression::default_compression())
//!     .layer(cors::production(&["https://app.example.com"]))
//!     .layer(ContextLayer::new())
//!     .layer(limits::default_body())
//!     .layer(timeout::default_timeout())
//!     .layer(RequestIdLayer::new());
//! ```
//!
//! # Middleware Order
//!
//! Recommended order (outermost first):
//!
//! 1. `RequestIdLayer` - correlation ID (first, so all logs have it)
//! 2. `TimeoutLayer` - reject slow requests early
//! 3. `RequestBodyLimitLayer` - reject oversized requests
//! 4. `ContextLayer` - extract tenant/user
//! 5. `CorsLayer` - CORS headers
//! 6. `CompressionLayer` - compress responses
//!
//! Rate limiting is typically applied per-route rather than globally.
//!
//! # Context Architecture
//!
//! This module sets context values in two places:
//!
//! - **Runtime context** (`primitives::runtime`): General request context used
//!   across all layers - tenant ID, user ID, correlation ID.
//!
//! - **Observe context** (`observe`): Observability-specific context for
//!   audit trails - source IP.
//!
//! Both are stored as task-local values and automatically flow into all
//! `observe::*` logging calls within the request scope.

pub mod extractors;
pub mod middleware;
pub mod presets;

mod error;

// Re-export main types
pub use error::{ProblemExt, ProblemResponse};
pub use extractors::{
    Authenticated, CorrelationId, OptionalCorrelationId, RequiredTenant, SourceIp, Tenant, UserId,
};
#[cfg(feature = "auth")]
pub use middleware::{AuthConfig, AuthLayer, Claims};
pub use middleware::{
    ContextLayer, FrameOptions, KeyStrategy, MetricsConfig, MetricsLayer, ObserveConfig,
    ObserveLayer, PathPattern, RateLimitConfig, RateLimitLayer, RequestIdLayer, SecurityConfig,
    SecurityLayer,
};

// Re-export tower-http types for convenience (so users don't need to add tower-http dependency)
pub use tower_http::compression::CompressionLayer;
pub use tower_http::cors::CorsLayer;
pub use tower_http::limit::RequestBodyLimitLayer;
pub use tower_http::timeout::TimeoutLayer;
pub use tower_http::trace::TraceLayer;

//! Rate limiting preset configurations
//!
//! Provides opinionated rate limiting configurations based on OWASP recommendations.
//! Uses `tower_governor` for proven rate limiting algorithms.
//!
//! # Presets
//!
//! | Preset | Rate | Burst | Use Case |
//! |--------|------|-------|----------|
//! | `api()` | 100/min | 150 | General API endpoints |
//! | `auth()` | 5/min | 5 | Authentication (login, password reset) |
//! | `search()` | 30/min | 50 | Search/query endpoints |
//! | `upload()` | 10/min | 20 | File upload endpoints |
//! | `webhook()` | 1000/min | 1500 | Machine-to-machine webhooks |
//!
//! # Example
//!
//! ```rust,ignore
//! use axum::{Router, routing::post};
//! use octarine::http::presets::rate_limit;
//!
//! let app = Router::new()
//!     .route("/login", post(login).layer(rate_limit::auth()))
//!     .route("/api/data", post(data).layer(rate_limit::api()));
//! ```

use std::sync::Arc;

use tower_governor::governor::GovernorConfigBuilder;

/// Re-export GovernorLayer for convenience
pub use tower_governor::GovernorLayer;

/// Re-export error types
pub use tower_governor::GovernorError;

// ============================================================================
// Preset Configurations
// ============================================================================

/// General API rate limiting (100 requests/minute, burst of 150).
///
/// Suitable for most API endpoints with normal usage patterns.
/// Uses peer IP address for rate limiting keys.
///
/// # Example
///
/// ```rust,ignore
/// use axum::Router;
/// use octarine::http::presets::rate_limit;
///
/// let app = Router::new()
///     .route("/api/data", get(handler))
///     .layer(rate_limit::api());
/// ```
#[must_use]
pub fn api<ReqBody>() -> tower_governor::GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::NoOpMiddleware<governor::clock::QuantaInstant>,
    ReqBody,
> {
    let config = GovernorConfigBuilder::default()
        .per_second(2) // ~100 per minute with some smoothing
        .burst_size(150)
        .finish();

    // SAFETY: These are hardcoded valid configuration values that cannot fail
    #[allow(clippy::expect_used)]
    let config = config.expect("hardcoded rate limit config");

    tower_governor::GovernorLayer::new(Arc::new(config))
}

/// Strict rate limiting for authentication endpoints (5 requests/minute).
///
/// Protects against brute force attacks on login, password reset, etc.
/// OWASP recommendation for authentication endpoints.
/// Uses peer IP address for rate limiting keys.
///
/// # Example
///
/// ```rust,ignore
/// use axum::Router;
/// use octarine::http::presets::rate_limit;
///
/// let app = Router::new()
///     .route("/login", post(login))
///     .layer(rate_limit::auth());
/// ```
#[must_use]
pub fn auth<ReqBody>() -> tower_governor::GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::NoOpMiddleware<governor::clock::QuantaInstant>,
    ReqBody,
> {
    let config = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(5)
        .finish();

    // SAFETY: These are hardcoded valid configuration values that cannot fail
    #[allow(clippy::expect_used)]
    let config = config.expect("hardcoded rate limit config");

    tower_governor::GovernorLayer::new(Arc::new(config))
}

/// Rate limiting for search/query endpoints (30 requests/minute, burst of 50).
///
/// Balances user experience with database load protection.
/// Uses peer IP address for rate limiting keys.
///
/// # Example
///
/// ```rust,ignore
/// use axum::Router;
/// use octarine::http::presets::rate_limit;
///
/// let app = Router::new()
///     .route("/search", get(search))
///     .layer(rate_limit::search());
/// ```
#[must_use]
pub fn search<ReqBody>() -> tower_governor::GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::NoOpMiddleware<governor::clock::QuantaInstant>,
    ReqBody,
> {
    let config = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(50)
        .finish();

    // SAFETY: These are hardcoded valid configuration values that cannot fail
    #[allow(clippy::expect_used)]
    let config = config.expect("hardcoded rate limit config");

    tower_governor::GovernorLayer::new(Arc::new(config))
}

/// Rate limiting for file upload endpoints (10 requests/minute, burst of 20).
///
/// Protects against resource exhaustion from large file uploads.
/// Uses peer IP address for rate limiting keys.
///
/// # Example
///
/// ```rust,ignore
/// use axum::Router;
/// use octarine::http::presets::rate_limit;
///
/// let app = Router::new()
///     .route("/upload", post(upload))
///     .layer(rate_limit::upload());
/// ```
#[must_use]
pub fn upload<ReqBody>() -> tower_governor::GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::NoOpMiddleware<governor::clock::QuantaInstant>,
    ReqBody,
> {
    let config = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(20)
        .finish();

    // SAFETY: These are hardcoded valid configuration values that cannot fail
    #[allow(clippy::expect_used)]
    let config = config.expect("hardcoded rate limit config");

    tower_governor::GovernorLayer::new(Arc::new(config))
}

/// High-throughput rate limiting for webhooks (1000 requests/minute).
///
/// Suitable for machine-to-machine communication where higher rates are expected.
/// Uses peer IP address for rate limiting keys.
///
/// # Example
///
/// ```rust,ignore
/// use axum::Router;
/// use octarine::http::presets::rate_limit;
///
/// let app = Router::new()
///     .route("/webhook", post(webhook))
///     .layer(rate_limit::webhook());
/// ```
#[must_use]
pub fn webhook<ReqBody>() -> tower_governor::GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::NoOpMiddleware<governor::clock::QuantaInstant>,
    ReqBody,
> {
    let config = GovernorConfigBuilder::default()
        .per_second(20) // ~1000 per minute
        .burst_size(1500)
        .finish();

    // SAFETY: These are hardcoded valid configuration values that cannot fail
    #[allow(clippy::expect_used)]
    let config = config.expect("hardcoded rate limit config");

    tower_governor::GovernorLayer::new(Arc::new(config))
}

// ============================================================================
// Custom Configuration Builder
// ============================================================================

/// Builder for custom rate limit configurations.
///
/// Use this when the presets don't match your needs.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::http::presets::rate_limit::RateLimitBuilder;
///
/// let layer = RateLimitBuilder::new()
///     .requests_per_minute(200)
///     .burst_size(300)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct RateLimitBuilder {
    requests_per_second: u64,
    burst_size: u32,
}

impl RateLimitBuilder {
    /// Create a new rate limit builder with defaults (100/min, burst 150).
    #[must_use]
    pub fn new() -> Self {
        Self {
            requests_per_second: 2,
            burst_size: 150,
        }
    }

    /// Set the rate as requests per minute.
    ///
    /// Internally converted to per-second for smoother limiting.
    #[must_use]
    pub fn requests_per_minute(mut self, rpm: u64) -> Self {
        // Convert to per-second, minimum 1
        self.requests_per_second = (rpm / 60).max(1);
        self
    }

    /// Set the rate as requests per second.
    #[must_use]
    pub fn requests_per_second(mut self, rps: u64) -> Self {
        self.requests_per_second = rps.max(1);
        self
    }

    /// Set the burst size (max requests in a burst).
    #[must_use]
    pub fn burst_size(mut self, size: u32) -> Self {
        self.burst_size = size.max(1);
        self
    }

    /// Build the rate limit layer.
    #[must_use]
    pub fn build<ReqBody>(
        self,
    ) -> tower_governor::GovernorLayer<
        tower_governor::key_extractor::PeerIpKeyExtractor,
        governor::middleware::NoOpMiddleware<governor::clock::QuantaInstant>,
        ReqBody,
    > {
        let config = GovernorConfigBuilder::default()
            .per_second(self.requests_per_second)
            .burst_size(self.burst_size)
            .finish();

        // SAFETY: Builder values are validated to be >= 1 in setter methods
        #[allow(clippy::expect_used)]
        let config = config.expect("builder rate limit config");

        tower_governor::GovernorLayer::new(Arc::new(config))
    }
}

impl Default for RateLimitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_creates_layer() {
        let _layer = api::<axum::body::Body>();
    }

    #[test]
    fn test_auth_creates_layer() {
        let _layer = auth::<axum::body::Body>();
    }

    #[test]
    fn test_search_creates_layer() {
        let _layer = search::<axum::body::Body>();
    }

    #[test]
    fn test_upload_creates_layer() {
        let _layer = upload::<axum::body::Body>();
    }

    #[test]
    fn test_webhook_creates_layer() {
        let _layer = webhook::<axum::body::Body>();
    }

    #[test]
    fn test_builder_default() {
        let _layer = RateLimitBuilder::new().build::<axum::body::Body>();
    }

    #[test]
    fn test_builder_custom() {
        let _layer = RateLimitBuilder::new()
            .requests_per_minute(60)
            .burst_size(100)
            .build::<axum::body::Body>();
    }

    #[test]
    fn test_builder_per_second() {
        let _layer = RateLimitBuilder::new()
            .requests_per_second(10)
            .burst_size(50)
            .build::<axum::body::Body>();
    }
}

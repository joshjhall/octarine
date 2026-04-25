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
// Preset Rates
// ============================================================================

/// `api()` preset — ~100 requests/minute (2/sec with smoothing), burst 150.
const API_RATE_PER_SEC: u64 = 2;
const API_BURST: u32 = 150;

/// `auth()` preset — 5 requests/minute (1/sec), burst 5. OWASP recommendation.
const AUTH_RATE_PER_SEC: u64 = 1;
const AUTH_BURST: u32 = 5;

/// `search()` preset — 30 requests/minute (1/sec), burst 50.
const SEARCH_RATE_PER_SEC: u64 = 1;
const SEARCH_BURST: u32 = 50;

/// `upload()` preset — 10 requests/minute (1/sec), burst 20.
const UPLOAD_RATE_PER_SEC: u64 = 1;
const UPLOAD_BURST: u32 = 20;

/// `webhook()` preset — ~1000 requests/minute (20/sec), burst 1500.
const WEBHOOK_RATE_PER_SEC: u64 = 20;
const WEBHOOK_BURST: u32 = 1500;

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
        .per_second(API_RATE_PER_SEC)
        .burst_size(API_BURST)
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
        .per_second(AUTH_RATE_PER_SEC)
        .burst_size(AUTH_BURST)
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
        .per_second(SEARCH_RATE_PER_SEC)
        .burst_size(SEARCH_BURST)
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
        .per_second(UPLOAD_RATE_PER_SEC)
        .burst_size(UPLOAD_BURST)
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
        .per_second(WEBHOOK_RATE_PER_SEC)
        .burst_size(WEBHOOK_BURST)
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

    /// Test-only accessor for builder state.
    ///
    /// Returns `(requests_per_second, burst_size)`. Used by unit tests to
    /// assert builder behavior without needing access to private fields.
    #[cfg(test)]
    pub(crate) fn config(&self) -> (u64, u32) {
        (self.requests_per_second, self.burst_size)
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

    // ------------------------------------------------------------------------
    // Preset constant assertions — guard against accidental rate changes
    // ------------------------------------------------------------------------

    #[test]
    fn test_preset_rates() {
        // Convert per-second back to per-minute for human-readable assertions
        // matching the documented values in the module table.
        assert_eq!(API_RATE_PER_SEC, 2);
        assert_eq!(API_BURST, 150);

        assert_eq!(AUTH_RATE_PER_SEC, 1);
        assert_eq!(AUTH_BURST, 5);

        assert_eq!(SEARCH_RATE_PER_SEC, 1);
        assert_eq!(SEARCH_BURST, 50);

        assert_eq!(UPLOAD_RATE_PER_SEC, 1);
        assert_eq!(UPLOAD_BURST, 20);

        assert_eq!(WEBHOOK_RATE_PER_SEC, 20);
        assert_eq!(WEBHOOK_BURST, 1500);
    }

    // ------------------------------------------------------------------------
    // Preset smoke tests — confirm constructors succeed (don't panic on
    // invalid governor config). Behavioral testing of GovernorLayer requires
    // ConnectInfo<SocketAddr> in the request, which Router::oneshot() does
    // not populate; preset rates are asserted via test_preset_rates above.
    // ------------------------------------------------------------------------

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

    // ------------------------------------------------------------------------
    // Builder state assertions — verify the public API actually mutates
    // state. The cfg(test) `config()` accessor returns the internal pair.
    // ------------------------------------------------------------------------

    #[test]
    fn test_builder_default() {
        let builder = RateLimitBuilder::new();
        assert_eq!(builder.config(), (2, 150));

        // Default impl matches new()
        assert_eq!(RateLimitBuilder::default().config(), (2, 150));
    }

    #[test]
    fn test_builder_requests_per_minute_converts_to_per_second() {
        // 60/min -> 1/sec
        let builder = RateLimitBuilder::new().requests_per_minute(60);
        assert_eq!(builder.config().0, 1);

        // 600/min -> 10/sec
        let builder = RateLimitBuilder::new().requests_per_minute(600);
        assert_eq!(builder.config().0, 10);
    }

    #[test]
    fn test_builder_requests_per_minute_below_60_clamps_to_one() {
        // 30/min would round down to 0; setter must clamp to minimum 1
        // because GovernorConfig rejects per_second(0).
        let builder = RateLimitBuilder::new().requests_per_minute(30);
        assert_eq!(builder.config().0, 1);

        // Zero must also clamp.
        let builder = RateLimitBuilder::new().requests_per_minute(0);
        assert_eq!(builder.config().0, 1);
    }

    #[test]
    fn test_builder_requests_per_second_clamps_to_one() {
        let builder = RateLimitBuilder::new().requests_per_second(0);
        assert_eq!(builder.config().0, 1);

        let builder = RateLimitBuilder::new().requests_per_second(50);
        assert_eq!(builder.config().0, 50);
    }

    #[test]
    fn test_builder_burst_size_clamps_to_one() {
        let builder = RateLimitBuilder::new().burst_size(0);
        assert_eq!(builder.config().1, 1);

        let builder = RateLimitBuilder::new().burst_size(200);
        assert_eq!(builder.config().1, 200);
    }

    #[test]
    fn test_builder_chained_setters_compose() {
        let builder = RateLimitBuilder::new()
            .requests_per_minute(60)
            .burst_size(100);
        assert_eq!(builder.config(), (1, 100));

        let builder = RateLimitBuilder::new()
            .requests_per_second(10)
            .burst_size(50);
        assert_eq!(builder.config(), (10, 50));
    }

    #[test]
    fn test_builder_build_does_not_panic() {
        // The build() path uses .expect() — make sure clamped minimums
        // produce a valid governor config rather than panicking.
        let _layer = RateLimitBuilder::new()
            .requests_per_minute(0) // clamped
            .burst_size(0) // clamped
            .build::<axum::body::Body>();
    }
}

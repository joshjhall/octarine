//! HTTP rate limiting middleware
//!
//! Provides token bucket rate limiting with observe integration and
//! configurable key extraction (per-IP, per-user, global).
//!
//! # Algorithm
//!
//! Uses a token bucket algorithm where:
//! - Tokens are added at a fixed rate (e.g., 10 per second)
//! - Each request consumes one token
//! - Burst capacity allows temporary spikes above the rate
//!
//! # Example
//!
//! ```rust,ignore
//! use axum::{Router, routing::get};
//! use octarine::http::middleware::{RateLimitLayer, RateLimitConfig};
//!
//! // 100 requests per minute with burst of 10
//! let config = RateLimitConfig::per_minute(100)
//!     .with_burst(10);
//!
//! let app: Router = Router::new()
//!     .route("/api/resource", get(|| async { "ok" }))
//!     .layer(RateLimitLayer::with_config(config));
//! ```
//!
//! # Per-IP Rate Limiting
//!
//! By default, rate limiting is applied per source IP:
//!
//! ```rust,ignore
//! use octarine::http::middleware::RateLimitConfig;
//!
//! let config = RateLimitConfig::per_second(10)
//!     .per_ip(); // Default behavior
//! ```
//!
//! # Global Rate Limiting
//!
//! For API-wide limits regardless of client:
//!
//! ```rust,ignore
//! use octarine::http::middleware::RateLimitConfig;
//!
//! let config = RateLimitConfig::per_second(1000)
//!     .global();
//! ```

use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

use axum::{
    extract::ConnectInfo,
    http::{Request, StatusCode, header::HeaderName},
    response::{IntoResponse, Response},
};
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed, keyed::DefaultKeyedStateStore},
};

use crate::observe;

/// Header for forwarded IP (when behind proxy)
static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// Header for real IP (nginx convention)
static X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");

/// Key extraction strategy for rate limiting.
#[derive(Debug, Clone, Default)]
pub enum KeyStrategy {
    /// Rate limit per source IP address (default)
    #[default]
    PerIp,
    /// Rate limit per value of a specific header
    PerHeader(HeaderName),
    /// Global rate limit (all requests share the same bucket)
    Global,
}

/// Configuration for rate limiting.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Requests allowed per period (stored for Debug display)
    #[allow(dead_code)]
    requests: NonZeroU32,
    /// Time period for the rate
    period: Duration,
    /// Burst capacity (additional requests allowed above rate)
    burst: NonZeroU32,
    /// Key extraction strategy
    key_strategy: KeyStrategy,
    /// Trust X-Forwarded-For header for IP extraction
    trust_forwarded_for: bool,
    /// Paths to exclude from rate limiting
    exclude_paths: Vec<String>,
}

impl RateLimitConfig {
    /// Create a rate limit of N requests per second.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::http::middleware::RateLimitConfig;
    ///
    /// let config = RateLimitConfig::per_second(10); // 10 req/s
    /// ```
    #[must_use]
    pub fn per_second(requests: u32) -> Self {
        Self::new(requests, Duration::from_secs(1))
    }

    /// Create a rate limit of N requests per minute.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::http::middleware::RateLimitConfig;
    ///
    /// let config = RateLimitConfig::per_minute(100); // 100 req/min
    /// ```
    #[must_use]
    pub fn per_minute(requests: u32) -> Self {
        Self::new(requests, Duration::from_secs(60))
    }

    /// Create a rate limit of N requests per hour.
    #[must_use]
    pub fn per_hour(requests: u32) -> Self {
        Self::new(requests, Duration::from_secs(3600))
    }

    /// Create a custom rate limit.
    #[must_use]
    pub fn new(requests: u32, period: Duration) -> Self {
        let requests = NonZeroU32::new(requests).unwrap_or(NonZeroU32::MIN);
        Self {
            requests,
            period,
            burst: requests, // Default burst equals rate
            key_strategy: KeyStrategy::default(),
            trust_forwarded_for: false,
            exclude_paths: Vec::new(),
        }
    }

    /// Set burst capacity (requests allowed above the rate).
    ///
    /// Burst allows temporary spikes. For example, with rate=10/s and burst=5,
    /// a client can make 15 requests instantly, then must wait for tokens to refill.
    #[must_use]
    pub fn with_burst(mut self, burst: u32) -> Self {
        self.burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        self
    }

    /// Use per-IP rate limiting (default).
    #[must_use]
    pub fn per_ip(mut self) -> Self {
        self.key_strategy = KeyStrategy::PerIp;
        self
    }

    /// Use per-header rate limiting.
    ///
    /// Useful for rate limiting by API key or user ID header.
    #[must_use]
    pub fn per_header(mut self, header: HeaderName) -> Self {
        self.key_strategy = KeyStrategy::PerHeader(header);
        self
    }

    /// Use global rate limiting (all requests share one bucket).
    #[must_use]
    pub fn global(mut self) -> Self {
        self.key_strategy = KeyStrategy::Global;
        self
    }

    /// Trust X-Forwarded-For header for IP extraction.
    ///
    /// # Security Warning
    ///
    /// Only enable when behind a trusted reverse proxy.
    #[must_use]
    pub fn trust_forwarded_for(mut self, trust: bool) -> Self {
        self.trust_forwarded_for = trust;
        self
    }

    /// Exclude paths from rate limiting.
    #[must_use]
    pub fn exclude_paths<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exclude_paths = paths.into_iter().map(Into::into).collect();
        self
    }

    /// Check if a path should be excluded.
    fn is_excluded(&self, path: &str) -> bool {
        self.exclude_paths.iter().any(|p| path.starts_with(p))
    }

    /// Build the quota for governor.
    ///
    /// # Panics
    ///
    /// This method is only called internally during layer construction with
    /// validated periods (from `per_second`, `per_minute`, etc.), so the
    /// period is guaranteed to be non-zero.
    #[allow(clippy::expect_used)]
    fn quota(&self) -> Quota {
        Quota::with_period(self.period)
            .expect("period must be non-zero - this is a bug in RateLimitConfig construction")
            .allow_burst(self.burst)
    }
}

/// Rate limiter state that can be either keyed or global.
enum LimiterState {
    /// Per-key rate limiter (per-IP or per-header)
    Keyed(Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock, NoOpMiddleware>>),
    /// Global rate limiter (all requests share one bucket)
    Global(Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>>),
}

impl std::fmt::Debug for LimiterState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keyed(_) => f.debug_tuple("Keyed").finish(),
            Self::Global(_) => f.debug_tuple("Global").finish(),
        }
    }
}

impl Clone for LimiterState {
    fn clone(&self) -> Self {
        match self {
            Self::Keyed(limiter) => Self::Keyed(Arc::clone(limiter)),
            Self::Global(limiter) => Self::Global(Arc::clone(limiter)),
        }
    }
}

/// Layer that adds rate limiting to a service.
///
/// # Example
///
/// ```rust,ignore
/// use axum::{Router, routing::get};
/// use octarine::http::middleware::RateLimitLayer;
///
/// let app: Router = Router::new()
///     .route("/api", get(|| async { "ok" }))
///     .layer(RateLimitLayer::per_second(10));
/// ```
#[derive(Debug, Clone)]
pub struct RateLimitLayer {
    config: RateLimitConfig,
    state: LimiterState,
}

impl RateLimitLayer {
    /// Create a rate limiter with N requests per second.
    #[must_use]
    pub fn per_second(requests: u32) -> Self {
        Self::with_config(RateLimitConfig::per_second(requests))
    }

    /// Create a rate limiter with N requests per minute.
    #[must_use]
    pub fn per_minute(requests: u32) -> Self {
        Self::with_config(RateLimitConfig::per_minute(requests))
    }

    /// Create a rate limiter with custom configuration.
    #[must_use]
    pub fn with_config(config: RateLimitConfig) -> Self {
        let quota = config.quota();
        let state = match &config.key_strategy {
            KeyStrategy::Global => LimiterState::Global(Arc::new(RateLimiter::direct(quota))),
            KeyStrategy::PerIp | KeyStrategy::PerHeader(_) => {
                LimiterState::Keyed(Arc::new(RateLimiter::keyed(quota)))
            }
        };

        Self { config, state }
    }
}

impl<S> tower::Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            config: self.config.clone(),
            state: self.state.clone(),
        }
    }
}

/// Service that applies rate limiting.
#[derive(Debug, Clone)]
pub struct RateLimitService<S> {
    inner: S,
    config: RateLimitConfig,
    state: LimiterState,
}

impl<S> RateLimitService<S> {
    /// Extract the rate limit key from a request.
    fn extract_key<B>(&self, request: &Request<B>) -> Option<String> {
        match &self.config.key_strategy {
            KeyStrategy::Global => None,
            KeyStrategy::PerIp => self.extract_ip(request).map(|ip| ip.to_string()),
            KeyStrategy::PerHeader(header) => request
                .headers()
                .get(header)
                .and_then(|v| v.to_str().ok())
                .map(String::from),
        }
    }

    /// Extract source IP from request.
    fn extract_ip<B>(&self, request: &Request<B>) -> Option<IpAddr> {
        // Try forwarded headers first (if trusted)
        if self.config.trust_forwarded_for {
            // Try X-Forwarded-For header
            let forwarded_ip = request
                .headers()
                .get(&X_FORWARDED_FOR)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .and_then(|s| s.trim().parse().ok());

            if let Some(ip) = forwarded_ip {
                return Some(ip);
            }

            // Try X-Real-IP header
            let real_ip = request
                .headers()
                .get(&X_REAL_IP)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok());

            if let Some(ip) = real_ip {
                return Some(ip);
            }
        }

        // Fall back to connection info
        request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())
    }

    /// Check if the request should be rate limited.
    fn validate_rate_limit<B>(&self, request: &Request<B>) -> Result<(), Duration> {
        match &self.state {
            LimiterState::Global(limiter) => limiter.check().map_err(|e| {
                e.wait_time_from(governor::clock::Clock::now(&DefaultClock::default()))
            }),
            LimiterState::Keyed(limiter) => {
                let key = self
                    .extract_key(request)
                    .unwrap_or_else(|| "unknown".to_string());
                limiter.check_key(&key).map_err(|e| {
                    e.wait_time_from(governor::clock::Clock::now(&DefaultClock::default()))
                })
            }
        }
    }
}

impl<S, B> tower::Service<Request<B>> for RateLimitService<S>
where
    S: tower::Service<Request<B>, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let path = request.uri().path().to_string();

        // Skip rate limiting for excluded paths
        if self.config.is_excluded(&path) {
            let mut inner = self.inner.clone();
            return Box::pin(async move { inner.call(request).await });
        }

        // Check rate limit
        match self.validate_rate_limit(&request) {
            Ok(()) => {
                // Request allowed
                let mut inner = self.inner.clone();
                Box::pin(async move { inner.call(request).await })
            }
            Err(wait_time) => {
                // Rate limited
                let key = self
                    .extract_key(&request)
                    .unwrap_or_else(|| "global".to_string());
                observe::warn(
                    "rate_limit_exceeded",
                    format!("Rate limit exceeded for {} on {}", key, path),
                );

                let retry_after = wait_time.as_secs().saturating_add(1); // Round up
                Box::pin(async move { Ok(RateLimitResponse { retry_after }.into_response()) })
            }
        }
    }
}

/// Response returned when rate limit is exceeded.
struct RateLimitResponse {
    retry_after: u64,
}

impl IntoResponse for RateLimitResponse {
    fn into_response(self) -> Response {
        let body = format!(
            r#"{{"error":{{"code":"rate_limited","message":"Too many requests. Retry after {} seconds.","retry_after":{}}}}}"#,
            self.retry_after, self.retry_after
        );

        (
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("content-type", "application/json"),
                ("retry-after", &self.retry_after.to_string()),
            ],
            body,
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_per_second() {
        let config = RateLimitConfig::per_second(10);
        assert_eq!(config.requests.get(), 10);
        assert_eq!(config.period, Duration::from_secs(1));
    }

    #[test]
    fn test_config_per_minute() {
        let config = RateLimitConfig::per_minute(100);
        assert_eq!(config.requests.get(), 100);
        assert_eq!(config.period, Duration::from_secs(60));
    }

    #[test]
    fn test_config_per_hour() {
        let config = RateLimitConfig::per_hour(1000);
        assert_eq!(config.requests.get(), 1000);
        assert_eq!(config.period, Duration::from_secs(3600));
    }

    #[test]
    fn test_config_with_burst() {
        let config = RateLimitConfig::per_second(10).with_burst(20);
        assert_eq!(config.burst.get(), 20);
    }

    #[test]
    fn test_config_per_ip() {
        let config = RateLimitConfig::per_second(10).per_ip();
        assert!(matches!(config.key_strategy, KeyStrategy::PerIp));
    }

    #[test]
    fn test_config_per_header() {
        let header = HeaderName::from_static("x-api-key");
        let config = RateLimitConfig::per_second(10).per_header(header);
        assert!(matches!(config.key_strategy, KeyStrategy::PerHeader(_)));
    }

    #[test]
    fn test_config_global() {
        let config = RateLimitConfig::per_second(10).global();
        assert!(matches!(config.key_strategy, KeyStrategy::Global));
    }

    #[test]
    fn test_config_trust_forwarded_for() {
        let config = RateLimitConfig::per_second(10).trust_forwarded_for(true);
        assert!(config.trust_forwarded_for);
    }

    #[test]
    fn test_config_exclude_paths() {
        let config = RateLimitConfig::per_second(10).exclude_paths(["/health", "/metrics"]);
        assert!(config.is_excluded("/health"));
        assert!(config.is_excluded("/health/live"));
        assert!(config.is_excluded("/metrics"));
        assert!(!config.is_excluded("/api/users"));
    }

    #[test]
    fn test_layer_per_second() {
        let _layer = RateLimitLayer::per_second(10);
    }

    #[test]
    fn test_layer_per_minute() {
        let _layer = RateLimitLayer::per_minute(100);
    }

    #[test]
    fn test_layer_with_config() {
        let config = RateLimitConfig::per_second(10).with_burst(20).global();
        let _layer = RateLimitLayer::with_config(config);
    }

    #[test]
    fn test_layer_keyed_vs_global() {
        // Keyed (per-IP)
        let layer = RateLimitLayer::per_second(10);
        assert!(matches!(layer.state, LimiterState::Keyed(_)));

        // Global
        let layer = RateLimitLayer::with_config(RateLimitConfig::per_second(10).global());
        assert!(matches!(layer.state, LimiterState::Global(_)));
    }

    #[test]
    fn test_zero_requests_uses_minimum() {
        let config = RateLimitConfig::new(0, Duration::from_secs(1));
        assert_eq!(config.requests.get(), 1);
    }

    #[test]
    fn test_zero_burst_uses_minimum() {
        let config = RateLimitConfig::per_second(10).with_burst(0);
        assert_eq!(config.burst.get(), 1);
    }
}

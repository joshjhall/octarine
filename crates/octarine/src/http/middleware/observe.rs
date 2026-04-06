//! HTTP request/response observability middleware
//!
//! Automatically logs HTTP requests and responses through the observe module,
//! capturing method, path, status, latency, headers, and optional body content
//! with PII redaction.
//!
//! # Features
//!
//! - **Structured Events**: Emits structured events with metadata for compliance
//! - **Latency Metrics**: Records request latency as histogram metrics
//! - **PII Protection**: Optional body logging with automatic PII redaction
//! - **Compliance Tags**: SOC2 control tagging on all events
//! - **Path Normalization**: Replaces dynamic path segments for metrics aggregation
//! - **Context Integration**: Captures correlation ID and tenant from runtime context
//!
//! # Log Levels
//!
//! - **Debug**: Request start, body content (when enabled)
//! - **Info**: Response completion for 2xx/3xx status codes
//! - **Warn**: Response completion for 4xx/5xx status codes
//!
//! # Example
//!
//! ```rust
//! use axum::{Router, routing::get};
//! use octarine::http::middleware::ObserveLayer;
//!
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "ok" }))
//!     .layer(ObserveLayer::new());
//! ```
//!
//! With full configuration:
//!
//! ```rust
//! use octarine::http::middleware::{ObserveLayer, ObserveConfig};
//!
//! let config = ObserveConfig::new()
//!     .exclude_paths(["/health", "/ready", "/metrics"])
//!     .log_headers(true)
//!     .log_request_body(true)
//!     .normalize_paths(true)
//!     .with_compliance();
//!
//! let layer = ObserveLayer::with_config(config);
//! ```

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
};
use http_body_util::BodyExt;
use tower::{Layer, Service};

use crate::data::network::PathPattern;
use crate::observe::ObserveBuilder;
use crate::observe::compliance::Soc2Control;
use crate::observe::metrics::{self, MetricName};
use crate::observe::pii;
use crate::primitives::data::network::{
    PathPattern as PrimitivePathPattern, normalize_path_segments_with_patterns,
};
use crate::primitives::runtime::{
    correlation_id as get_correlation_id, tenant_id as get_tenant_id,
};

/// Default maximum body size to log (4KB)
const DEFAULT_MAX_BODY_LOG_SIZE: usize = 4096;

/// Configuration for the observe middleware.
#[derive(Debug, Clone)]
pub struct ObserveConfig {
    /// Paths to exclude from logging (e.g., health checks)
    exclude_paths: Vec<String>,
    /// Whether to log request/response headers at debug level
    log_headers: bool,
    /// Whether to log request body size
    log_request_size: bool,
    /// Whether to log response body size
    log_response_size: bool,
    /// Whether to log request body content (with PII redaction)
    log_request_body: bool,
    /// Whether to log response body content (with PII redaction)
    log_response_body: bool,
    /// Maximum body size to log in bytes (larger bodies are truncated)
    max_body_log_size: usize,
    /// Whether to apply SOC2 compliance tags to events
    compliance_enabled: bool,
    /// Whether to normalize paths (replace IDs/UUIDs with placeholders)
    normalize_paths: bool,
    /// Custom path patterns for normalization
    path_patterns: Vec<PrimitivePathPattern>,
}

impl Default for ObserveConfig {
    fn default() -> Self {
        Self {
            exclude_paths: Vec::new(),
            log_headers: false,
            log_request_size: false,
            log_response_size: false,
            log_request_body: false,
            log_response_body: false,
            max_body_log_size: DEFAULT_MAX_BODY_LOG_SIZE,
            compliance_enabled: false,
            normalize_paths: false,
            path_patterns: Vec::new(),
        }
    }
}

impl ObserveConfig {
    /// Create a new configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Exclude paths from logging.
    ///
    /// Useful for health check endpoints that would otherwise create noise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::http::middleware::ObserveConfig;
    ///
    /// let config = ObserveConfig::new()
    ///     .exclude_paths(["/health", "/ready"]);
    /// ```
    #[must_use]
    pub fn exclude_paths<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exclude_paths = paths.into_iter().map(Into::into).collect();
        self
    }

    /// Enable logging of request/response headers at debug level.
    ///
    /// Headers are automatically sanitized by the observe module to redact
    /// sensitive values like Authorization tokens and cookies.
    #[must_use]
    pub fn log_headers(mut self, enable: bool) -> Self {
        self.log_headers = enable;
        self
    }

    /// Enable logging of request body size (Content-Length header).
    #[must_use]
    pub fn log_request_size(mut self, enable: bool) -> Self {
        self.log_request_size = enable;
        self
    }

    /// Enable logging of response body size (Content-Length header).
    #[must_use]
    pub fn log_response_size(mut self, enable: bool) -> Self {
        self.log_response_size = enable;
        self
    }

    /// Enable logging of request body content with PII redaction.
    ///
    /// When enabled, request bodies are buffered (up to `max_body_log_size`)
    /// and logged with automatic PII detection and redaction.
    ///
    /// **Note**: This adds overhead due to body buffering. Use with caution
    /// in high-throughput scenarios.
    #[must_use]
    pub fn log_request_body(mut self, enable: bool) -> Self {
        self.log_request_body = enable;
        self
    }

    /// Enable logging of response body content with PII redaction.
    ///
    /// When enabled, response bodies are buffered (up to `max_body_log_size`)
    /// and logged with automatic PII detection and redaction.
    ///
    /// **Note**: This adds overhead due to body buffering. Use with caution
    /// in high-throughput scenarios.
    #[must_use]
    pub fn log_response_body(mut self, enable: bool) -> Self {
        self.log_response_body = enable;
        self
    }

    /// Set the maximum body size to log in bytes.
    ///
    /// Bodies larger than this will be truncated. Default is 4KB.
    #[must_use]
    pub fn max_body_log_size(mut self, size: usize) -> Self {
        self.max_body_log_size = size;
        self
    }

    /// Enable SOC2 compliance tagging on all events.
    ///
    /// When enabled, events are tagged with appropriate SOC2 controls:
    /// - CC7.2 (System Operations) for request logging
    /// - CC6.1 (Access Control) for rate limit events
    #[must_use]
    pub fn with_compliance(mut self) -> Self {
        self.compliance_enabled = true;
        self
    }

    /// Enable path normalization for metrics aggregation.
    ///
    /// When enabled, dynamic path segments (numeric IDs, UUIDs) are replaced
    /// with placeholders like `{id}` or `{uuid}` to reduce cardinality.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::http::middleware::ObserveConfig;
    ///
    /// let config = ObserveConfig::new()
    ///     .normalize_paths(true);
    /// // /users/123 becomes /users/{id}
    /// // /orders/550e8400-e29b-41d4-a716-446655440000 becomes /orders/{uuid}
    /// ```
    #[must_use]
    pub fn normalize_paths(mut self, enable: bool) -> Self {
        self.normalize_paths = enable;
        self
    }

    /// Add a custom path pattern for normalization.
    ///
    /// Use `{name}` placeholders for dynamic segments. These patterns are
    /// checked before auto-detection of numeric IDs and UUIDs.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::http::middleware::{ObserveConfig, PathPattern};
    ///
    /// let config = ObserveConfig::new()
    ///     .normalize_paths(true)
    ///     .add_path_pattern(PathPattern::new("/api/{version}/users/{id}"));
    /// ```
    #[must_use]
    pub fn add_path_pattern(mut self, pattern: PathPattern) -> Self {
        self.path_patterns.push(pattern.into());
        self
    }

    /// Check if a path should be excluded from logging.
    fn is_excluded(&self, path: &str) -> bool {
        self.exclude_paths.iter().any(|p| path.starts_with(p))
    }

    /// Normalize a path using configured patterns and auto-detection.
    fn normalize_path(&self, path: &str) -> String {
        if self.normalize_paths {
            normalize_path_segments_with_patterns(path, &self.path_patterns).into_owned()
        } else {
            path.to_string()
        }
    }
}

/// Layer that adds HTTP observability to a service.
///
/// # Example
///
/// ```rust
/// use axum::{Router, routing::get};
/// use octarine::http::middleware::ObserveLayer;
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(ObserveLayer::new());
/// ```
#[derive(Debug, Clone, Default)]
pub struct ObserveLayer {
    config: ObserveConfig,
}

impl ObserveLayer {
    /// Create a new `ObserveLayer` with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new `ObserveLayer` with custom configuration.
    #[must_use]
    pub fn with_config(config: ObserveConfig) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for ObserveLayer {
    type Service = ObserveService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ObserveService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Service that logs HTTP requests and responses.
#[derive(Debug, Clone)]
pub struct ObserveService<S> {
    inner: S,
    config: ObserveConfig,
}

/// Shared metadata for a single request lifecycle, passed to helper functions
/// to avoid repeating parameters.
struct RequestContext {
    method: String,
    path: String,
    correlation_id: String,
    tenant_id: Option<String>,
    request_size: Option<u64>,
    compliance_enabled: bool,
}

/// Buffer an HTTP body, optionally log it with PII redaction, and reconstruct it.
///
/// Used for both request and response body logging to deduplicate the
/// nearly-identical buffering logic.
async fn buffer_and_log_body(
    ctx: &RequestContext,
    body: Body,
    direction: &str,
    max_size: usize,
) -> Body {
    match body.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            let truncated = bytes.len() > max_size;
            let body_slice = bytes.get(..max_size).unwrap_or(&bytes);
            let body_str = String::from_utf8_lossy(body_slice);

            let (safe_body, was_redacted) = if pii::is_pii_present(&body_str) {
                (pii::redact_pii(&body_str), true)
            } else {
                (body_str.to_string(), false)
            };

            ObserveBuilder::new()
                .message(format!("HTTP {direction} body"))
                .with_metadata("method", ctx.method.as_str())
                .with_metadata("path", ctx.path.as_str())
                .with_metadata("correlation_id", ctx.correlation_id.as_str())
                .with_metadata("body", safe_body.as_str())
                .with_metadata("redacted", was_redacted)
                .with_metadata("truncated", truncated)
                .with_metadata("size", bytes.len())
                .debug();

            Body::from(bytes)
        }
        Err(e) => {
            ObserveBuilder::new()
                .message(format!("Failed to collect {direction} body"))
                .with_metadata("method", ctx.method.as_str())
                .with_metadata("path", ctx.path.as_str())
                .with_metadata("correlation_id", ctx.correlation_id.as_str())
                .with_metadata("error", e.to_string())
                .warn();

            Body::empty()
        }
    }
}

/// Emit the HTTP completion event and optional rate-limit security event.
fn emit_completion_event(
    ctx: &RequestContext,
    status: StatusCode,
    latency_ms: f64,
    response_size: Option<u64>,
    response_headers: Option<&str>,
) {
    let mut event = ObserveBuilder::new()
        .message("HTTP request completed")
        .with_metadata("method", ctx.method.as_str())
        .with_metadata("path", ctx.path.as_str())
        .with_metadata("status", status.as_u16())
        .with_metadata("latency_ms", latency_ms)
        .with_metadata("correlation_id", ctx.correlation_id.as_str());

    if let Some(ref tenant) = ctx.tenant_id {
        event = event.with_metadata("tenant_id", tenant.as_str());
    }

    if let Some(size) = ctx.request_size {
        event = event.with_metadata("request_size", size);
    }

    if let Some(size) = response_size {
        event = event.with_metadata("response_size", size);
    }

    if let Some(headers) = response_headers {
        event = event.with_metadata("headers", headers);
    }

    if ctx.compliance_enabled {
        event = event.soc2_control(Soc2Control::CC7_2);
    }

    emit_by_status(status, event);

    // Special handling for rate limit responses (security event)
    if status == StatusCode::TOO_MANY_REQUESTS {
        let mut rate_limit_event = ObserveBuilder::new()
            .message("Rate limit exceeded")
            .with_metadata("path", ctx.path.as_str())
            .with_metadata("correlation_id", ctx.correlation_id.as_str());

        if let Some(ref tenant) = ctx.tenant_id {
            rate_limit_event = rate_limit_event.with_metadata("tenant_id", tenant.as_str());
        }

        if ctx.compliance_enabled {
            rate_limit_event = rate_limit_event.soc2_control(Soc2Control::CC6_1);
        }

        rate_limit_event.warn();
    }
}

impl<S> Service<Request<Body>> for ObserveService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let path = request.uri().path().to_string();

        // Check if this path should be excluded
        if self.config.is_excluded(&path) {
            let mut inner = self.inner.clone();
            return Box::pin(async move { inner.call(request).await });
        }

        let config = self.config.clone();
        let start = Instant::now();

        let ctx = RequestContext {
            method: request.method().to_string(),
            path: config.normalize_path(&path),
            correlation_id: get_correlation_id().to_string(),
            tenant_id: get_tenant_id(),
            request_size: if config.log_request_size {
                request
                    .headers()
                    .get(axum::http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
            } else {
                None
            },
            compliance_enabled: config.compliance_enabled,
        };

        // Extract request headers for logging
        let request_headers = if config.log_headers {
            Some(format_headers(request.headers()))
        } else {
            None
        };

        // Emit structured request start event
        let mut event = ObserveBuilder::new()
            .message("HTTP request received")
            .with_metadata("method", ctx.method.as_str())
            .with_metadata("path", ctx.path.as_str())
            .with_metadata("correlation_id", ctx.correlation_id.as_str());

        if let Some(ref tenant) = ctx.tenant_id {
            event = event.with_metadata("tenant_id", tenant.as_str());
        }
        if let Some(ref headers) = request_headers {
            event = event.with_metadata("headers", headers.as_str());
        }
        if let Some(size) = ctx.request_size {
            event = event.with_metadata("request_size", size);
        }
        event.debug();

        let mut inner = self.inner.clone();
        let log_request_body = config.log_request_body;
        let log_response_body = config.log_response_body;
        let max_body_size = config.max_body_log_size;

        Box::pin(async move {
            // Optionally buffer and log request body
            let request = if log_request_body {
                let (parts, body) = request.into_parts();
                let new_body = buffer_and_log_body(&ctx, body, "request", max_body_size).await;
                Request::from_parts(parts, new_body)
            } else {
                request
            };

            let response = inner.call(request).await?;

            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            let status = response.status();

            // Record latency histogram
            if let Ok(metric_name) = MetricName::new("http.request.latency_ms") {
                metrics::record(metric_name, latency_ms);
            }

            // Extract response info
            let response_headers = if config.log_headers {
                Some(format_headers(response.headers()))
            } else {
                None
            };
            let response_size = if config.log_response_size {
                response
                    .headers()
                    .get(axum::http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
            } else {
                None
            };

            // Optionally buffer and log response body
            let response = if log_response_body {
                let (parts, body) = response.into_parts();
                let new_body = buffer_and_log_body(&ctx, body, "response", max_body_size).await;
                Response::from_parts(parts, new_body)
            } else {
                response
            };

            emit_completion_event(
                &ctx,
                status,
                latency_ms,
                response_size,
                response_headers.as_deref(),
            );

            Ok(response)
        })
    }
}

/// Emit an event at the appropriate level based on HTTP status code.
fn emit_by_status(status: StatusCode, event: ObserveBuilder) {
    if status.is_server_error() {
        // 5xx - Server errors, needs attention
        event.warn();
    } else if status.is_client_error() {
        // 4xx - Client errors, worth noting
        event.info();
    } else {
        // 2xx, 3xx - Success/redirect, debug level
        event.debug();
    }
}

/// Headers that should have their values redacted for security.
const REDACTED_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "proxy-authorization",
    "www-authenticate",
];

/// Format headers for logging with sensitive value redaction.
///
/// Sensitive headers (Authorization, Cookie, API keys, etc.) have their
/// values replaced with `[REDACTED]` to prevent credential leakage.
fn format_headers(headers: &axum::http::HeaderMap) -> String {
    let pairs: Vec<String> = headers
        .iter()
        .map(|(name, value)| {
            let name_lower = name.as_str().to_lowercase();
            let value_str = if REDACTED_HEADERS.contains(&name_lower.as_str()) {
                "[REDACTED]"
            } else {
                value.to_str().unwrap_or("<binary>")
            };
            format!("{}: {}", name.as_str(), value_str)
        })
        .collect();

    format!("{{{}}}", pairs.join(", "))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = ObserveConfig::new();
        assert!(config.exclude_paths.is_empty());
        assert!(!config.log_headers);
        assert!(!config.log_request_size);
        assert!(!config.log_response_size);
        assert!(!config.log_request_body);
        assert!(!config.log_response_body);
        assert_eq!(config.max_body_log_size, DEFAULT_MAX_BODY_LOG_SIZE);
        assert!(!config.compliance_enabled);
        assert!(!config.normalize_paths);
        assert!(config.path_patterns.is_empty());
    }

    #[test]
    fn test_config_exclude_paths() {
        let config = ObserveConfig::new().exclude_paths(["/health", "/ready"]);
        assert_eq!(config.exclude_paths.len(), 2);
        assert!(config.is_excluded("/health"));
        assert!(config.is_excluded("/health/live"));
        assert!(config.is_excluded("/ready"));
        assert!(!config.is_excluded("/api/users"));
    }

    #[test]
    fn test_config_log_headers() {
        let config = ObserveConfig::new().log_headers(true);
        assert!(config.log_headers);
    }

    #[test]
    fn test_config_log_sizes() {
        let config = ObserveConfig::new()
            .log_request_size(true)
            .log_response_size(true);
        assert!(config.log_request_size);
        assert!(config.log_response_size);
    }

    #[test]
    fn test_config_body_logging() {
        let config = ObserveConfig::new()
            .log_request_body(true)
            .log_response_body(true)
            .max_body_log_size(8192);
        assert!(config.log_request_body);
        assert!(config.log_response_body);
        assert_eq!(config.max_body_log_size, 8192);
    }

    #[test]
    fn test_config_compliance() {
        let config = ObserveConfig::new().with_compliance();
        assert!(config.compliance_enabled);
    }

    #[test]
    fn test_config_path_normalization() {
        let config = ObserveConfig::new()
            .normalize_paths(true)
            .add_path_pattern(PathPattern::new("/api/{version}/users/{id}"));
        assert!(config.normalize_paths);
        assert_eq!(config.path_patterns.len(), 1);
    }

    #[test]
    fn test_config_path_normalization_with_patterns() {
        let config = ObserveConfig::new()
            .normalize_paths(true)
            .add_path_pattern(PathPattern::new("/api/{version}/users/{id}"));

        // Pattern should match and normalize
        assert_eq!(
            config.normalize_path("/api/v1/users/123"),
            "/api/{version}/users/{id}"
        );
        assert_eq!(
            config.normalize_path("/api/v2/users/456"),
            "/api/{version}/users/{id}"
        );

        // Non-matching paths should still auto-normalize numeric IDs
        assert_eq!(config.normalize_path("/orders/789"), "/orders/{id}");

        // UUIDs should be normalized
        assert_eq!(
            config.normalize_path("/items/550e8400-e29b-41d4-a716-446655440000"),
            "/items/{uuid}"
        );
    }

    #[test]
    fn test_config_normalize_path() {
        let config = ObserveConfig::new().normalize_paths(true);

        // Numeric IDs normalized
        assert_eq!(config.normalize_path("/users/123"), "/users/{id}");

        // UUIDs normalized
        assert_eq!(
            config.normalize_path("/orders/550e8400-e29b-41d4-a716-446655440000"),
            "/orders/{uuid}"
        );

        // No normalization when disabled
        let config_disabled = ObserveConfig::new();
        assert_eq!(config_disabled.normalize_path("/users/123"), "/users/123");
    }

    #[test]
    fn test_layer_creation() {
        let layer = ObserveLayer::new();
        assert!(layer.config.exclude_paths.is_empty());
    }

    #[test]
    fn test_layer_with_config() {
        let config = ObserveConfig::new().exclude_paths(["/metrics"]);
        let layer = ObserveLayer::with_config(config);
        assert_eq!(layer.config.exclude_paths.len(), 1);
    }

    #[test]
    fn test_format_headers() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        headers.insert(axum::http::header::ACCEPT, "*/*".parse().unwrap());

        let formatted = format_headers(&headers);
        assert!(formatted.contains("content-type: application/json"));
        assert!(formatted.contains("accept: */*"));
        assert!(formatted.starts_with('{'));
        assert!(formatted.ends_with('}'));
    }

    #[test]
    fn test_format_headers_redacts_sensitive() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer secret-token-12345".parse().unwrap(),
        );
        headers.insert(
            axum::http::header::COOKIE,
            "session=abc123; auth=xyz789".parse().unwrap(),
        );
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        let formatted = format_headers(&headers);

        // Sensitive headers should be redacted
        assert!(formatted.contains("authorization: [REDACTED]"));
        assert!(formatted.contains("cookie: [REDACTED]"));
        assert!(!formatted.contains("secret-token"));
        assert!(!formatted.contains("abc123"));

        // Non-sensitive headers should be visible
        assert!(formatted.contains("content-type: application/json"));
    }

    #[test]
    fn test_emit_by_status_levels() {
        // This test verifies the function doesn't panic for various status codes
        // Actual event output is handled by observe module

        // 2xx - should use debug
        emit_by_status(StatusCode::OK, ObserveBuilder::new().message("test"));
        emit_by_status(StatusCode::CREATED, ObserveBuilder::new().message("test"));

        // 3xx - should use debug
        emit_by_status(
            StatusCode::MOVED_PERMANENTLY,
            ObserveBuilder::new().message("test"),
        );
        emit_by_status(StatusCode::FOUND, ObserveBuilder::new().message("test"));

        // 4xx - should use info
        emit_by_status(
            StatusCode::BAD_REQUEST,
            ObserveBuilder::new().message("test"),
        );
        emit_by_status(StatusCode::NOT_FOUND, ObserveBuilder::new().message("test"));
        emit_by_status(
            StatusCode::UNAUTHORIZED,
            ObserveBuilder::new().message("test"),
        );

        // 5xx - should use warn
        emit_by_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            ObserveBuilder::new().message("test"),
        );
        emit_by_status(
            StatusCode::BAD_GATEWAY,
            ObserveBuilder::new().message("test"),
        );
    }

    #[test]
    fn test_full_config() {
        // Test all config options together
        let config = ObserveConfig::new()
            .exclude_paths(["/health", "/ready", "/metrics"])
            .log_headers(true)
            .log_request_size(true)
            .log_response_size(true)
            .log_request_body(true)
            .log_response_body(true)
            .max_body_log_size(2048)
            .with_compliance()
            .normalize_paths(true)
            .add_path_pattern(PathPattern::new("/users/{id}"));

        assert_eq!(config.exclude_paths.len(), 3);
        assert!(config.log_headers);
        assert!(config.log_request_size);
        assert!(config.log_response_size);
        assert!(config.log_request_body);
        assert!(config.log_response_body);
        assert_eq!(config.max_body_log_size, 2048);
        assert!(config.compliance_enabled);
        assert!(config.normalize_paths);
        assert_eq!(config.path_patterns.len(), 1);
    }
}

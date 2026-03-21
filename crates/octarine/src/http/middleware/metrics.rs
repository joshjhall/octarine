//! HTTP metrics middleware
//!
//! Records HTTP request metrics through the observe module, enabling
//! Prometheus/OTLP export for monitoring and alerting.
//!
//! # Metrics Recorded
//!
//! | Metric | Type | Description |
//! |--------|------|-------------|
//! | `http.requests` | Counter | Total request count |
//! | `http.request.duration` | Histogram | Request latency in seconds |
//! | `http.requests.in_flight` | Gauge | Current active requests |
//!
//! # Example
//!
//! ```rust
//! use axum::{Router, routing::get};
//! use octarine::http::middleware::MetricsLayer;
//!
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "ok" }))
//!     .layer(MetricsLayer::new());
//! ```
//!
//! With path normalization:
//!
//! ```rust
//! use octarine::http::middleware::{MetricsLayer, MetricsConfig, PathPattern};
//!
//! let config = MetricsConfig::new()
//!     .add_pattern(PathPattern::new("/users/{id}"))
//!     .add_pattern(PathPattern::new("/orders/{id}/items/{item_id}"))
//!     .exclude_paths(["/health", "/metrics"]);
//!
//! let layer = MetricsLayer::with_config(config);
//! ```

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};

use axum::{
    body::Body,
    http::{Request, Response},
};
use tower::{Layer, Service};

use crate::data::network::PathPattern;
use crate::observe::metrics::{self, MetricName};
use crate::primitives::data::network::{
    PathPattern as PrimitivePathPattern, normalize_path_segments_with_patterns,
};

// ============================================================================
// Metrics Configuration
// ============================================================================

/// Configuration for HTTP metrics.
#[derive(Debug, Clone, Default)]
pub struct MetricsConfig {
    /// Paths to exclude from metrics (e.g., health checks)
    exclude_paths: Vec<String>,
    /// Path patterns for normalization (stored as primitives internally)
    path_patterns: Vec<PrimitivePathPattern>,
    /// Whether to track in-flight requests
    track_in_flight: bool,
    /// Whether to auto-normalize numeric/UUID segments
    auto_normalize: bool,
}

impl MetricsConfig {
    /// Create a new configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            exclude_paths: Vec::new(),
            path_patterns: Vec::new(),
            track_in_flight: true,
            auto_normalize: true,
        }
    }

    /// Exclude paths from metrics collection.
    ///
    /// Useful for health check endpoints that would create noise.
    #[must_use]
    pub fn exclude_paths<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exclude_paths = paths.into_iter().map(Into::into).collect();
        self
    }

    /// Add a path pattern for normalization.
    ///
    /// Use `{name}` placeholders for dynamic segments.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::http::middleware::{MetricsConfig, PathPattern};
    ///
    /// let config = MetricsConfig::new()
    ///     .add_pattern(PathPattern::new("/users/{id}"))
    ///     .add_pattern(PathPattern::new("/orders/{order_id}/items/{item_id}"));
    /// ```
    #[must_use]
    pub fn add_pattern(mut self, pattern: PathPattern) -> Self {
        self.path_patterns.push(pattern.into());
        self
    }

    /// Convenience method to add a path pattern from a string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::http::middleware::MetricsConfig;
    ///
    /// let config = MetricsConfig::new()
    ///     .normalize_path("/users/{id}")
    ///     .normalize_path("/orders/{order_id}/items/{item_id}");
    /// ```
    #[must_use]
    pub fn normalize_path(mut self, pattern: &str) -> Self {
        self.path_patterns.push(PrimitivePathPattern::new(pattern));
        self
    }

    /// Disable tracking of in-flight requests gauge.
    #[must_use]
    pub fn disable_in_flight_tracking(mut self) -> Self {
        self.track_in_flight = false;
        self
    }

    /// Disable auto-normalization of numeric/UUID segments.
    ///
    /// When disabled, only user-defined patterns are used.
    #[must_use]
    pub fn disable_auto_normalize(mut self) -> Self {
        self.auto_normalize = false;
        self
    }

    /// Check if a path should be excluded from metrics.
    fn is_excluded(&self, path: &str) -> bool {
        self.exclude_paths.iter().any(|p| path.starts_with(p))
    }

    /// Apply normalization to a path using configured patterns.
    fn apply_normalization(&self, path: &str) -> String {
        if self.auto_normalize || !self.path_patterns.is_empty() {
            // Use pattern matching and auto-detection (UUID, numeric IDs)
            normalize_path_segments_with_patterns(path, &self.path_patterns).into_owned()
        } else {
            // No normalization
            path.to_string()
        }
    }
}

// ============================================================================
// In-Flight Counter
// ============================================================================

/// Shared counter for tracking in-flight requests.
#[derive(Debug, Default)]
struct InFlightCounter {
    count: AtomicI64,
}

impl InFlightCounter {
    fn new() -> Self {
        Self {
            count: AtomicI64::new(0),
        }
    }

    fn increment(&self) -> i64 {
        let prev = self.count.fetch_add(1, Ordering::SeqCst);
        prev.saturating_add(1)
    }

    fn decrement(&self) -> i64 {
        let prev = self.count.fetch_sub(1, Ordering::SeqCst);
        prev.saturating_sub(1)
    }
}

// ============================================================================
// Metrics Layer
// ============================================================================

/// Layer that records HTTP metrics.
///
/// # Example
///
/// ```rust
/// use axum::{Router, routing::get};
/// use octarine::http::middleware::MetricsLayer;
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(MetricsLayer::new());
/// ```
#[derive(Debug, Clone)]
pub struct MetricsLayer {
    config: MetricsConfig,
    in_flight: Arc<InFlightCounter>,
}

impl MetricsLayer {
    /// Create a new metrics layer with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: MetricsConfig::new(),
            in_flight: Arc::new(InFlightCounter::new()),
        }
    }

    /// Create a metrics layer with custom configuration.
    #[must_use]
    pub fn with_config(config: MetricsConfig) -> Self {
        Self {
            config,
            in_flight: Arc::new(InFlightCounter::new()),
        }
    }
}

impl Default for MetricsLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for MetricsLayer {
    type Service = MetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricsService {
            inner,
            config: self.config.clone(),
            in_flight: Arc::clone(&self.in_flight),
        }
    }
}

// ============================================================================
// Metrics Service
// ============================================================================

/// Service that records HTTP metrics.
#[derive(Debug, Clone)]
pub struct MetricsService<S> {
    inner: S,
    config: MetricsConfig,
    in_flight: Arc<InFlightCounter>,
}

impl<S> Service<Request<Body>> for MetricsService<S>
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
        let method = request.method().clone();
        let path = request.uri().path().to_string();

        // Check if this path should be excluded
        if self.config.is_excluded(&path) {
            let mut inner = self.inner.clone();
            return Box::pin(async move { inner.call(request).await });
        }

        let config = self.config.clone();
        let in_flight = Arc::clone(&self.in_flight);
        let track_in_flight = config.track_in_flight;

        // Normalize path for metrics labels
        let normalized_path = config.apply_normalization(&path);
        let method_str = method.to_string();

        // Track in-flight requests
        if track_in_flight {
            let current = in_flight.increment();
            if let Ok(metric_name) = MetricName::new("http.requests.in_flight") {
                metrics::gauge(metric_name, current);
            }
        }

        let start = Instant::now();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let response = inner.call(request).await;

            // Record metrics after response
            let duration = start.elapsed();
            let status = response
                .as_ref()
                .map(|r| r.status().as_u16())
                .unwrap_or(500);

            // Decrement in-flight
            if track_in_flight {
                let current = in_flight.decrement();
                if let Ok(metric_name) = MetricName::new("http.requests.in_flight") {
                    metrics::gauge(metric_name, current);
                }
            }

            // Record request counter
            // Metric name includes method and normalized path for cardinality control
            let counter_name = format!("http.requests.{}.{}", method_str.to_lowercase(), status);
            if let Ok(metric_name) = MetricName::new(&counter_name) {
                metrics::increment(metric_name);
            }

            // Record duration histogram
            let duration_name = format!(
                "http.request.duration.{}.{}",
                method_str.to_lowercase(),
                normalized_path.replace('/', ".").trim_matches('.')
            );
            if let Ok(metric_name) = MetricName::new(&duration_name) {
                metrics::record(metric_name, duration.as_secs_f64());
            }

            response
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::network::{normalize_path_segments, normalize_path_segments_with_patterns};

    // Path normalization tests (using data layer)

    #[test]
    fn test_normalize_path_segments_auto() {
        // Numeric IDs
        assert_eq!(normalize_path_segments("/users/123"), "/users/{id}");
        assert_eq!(
            normalize_path_segments("/users/123/orders/456"),
            "/users/{id}/orders/{id}"
        );

        // UUIDs
        assert_eq!(
            normalize_path_segments("/users/550e8400-e29b-41d4-a716-446655440000"),
            "/users/{uuid}"
        );

        // Mixed
        assert_eq!(
            normalize_path_segments("/users/123/orders/550e8400-e29b-41d4-a716-446655440000"),
            "/users/{id}/orders/{uuid}"
        );

        // No normalization needed
        assert_eq!(normalize_path_segments("/api/users"), "/api/users");
    }

    #[test]
    fn test_normalize_path_with_patterns() {
        let patterns = vec![PathPattern::new("/api/{version}/users/{id}")];

        assert_eq!(
            normalize_path_segments_with_patterns("/api/v1/users/123", &patterns),
            "/api/{version}/users/{id}"
        );
        assert_eq!(
            normalize_path_segments_with_patterns("/api/v2/users/456", &patterns),
            "/api/{version}/users/{id}"
        );

        // Falls back to auto-detection for unmatched paths
        assert_eq!(
            normalize_path_segments_with_patterns("/other/123", &patterns),
            "/other/{id}"
        );
    }

    // Configuration tests

    #[test]
    fn test_config_defaults() {
        let config = MetricsConfig::new();
        assert!(config.exclude_paths.is_empty());
        assert!(config.path_patterns.is_empty());
        assert!(config.track_in_flight);
        assert!(config.auto_normalize);
    }

    #[test]
    fn test_config_exclude_paths() {
        let config = MetricsConfig::new().exclude_paths(["/health", "/metrics"]);
        assert!(config.is_excluded("/health"));
        assert!(config.is_excluded("/health/live"));
        assert!(config.is_excluded("/metrics"));
        assert!(!config.is_excluded("/api/users"));
    }

    #[test]
    fn test_config_normalize_path() {
        let config = MetricsConfig::new().normalize_path("/users/{id}");
        assert_eq!(config.path_patterns.len(), 1);
    }

    #[test]
    fn test_config_disable_features() {
        let config = MetricsConfig::new()
            .disable_in_flight_tracking()
            .disable_auto_normalize();
        assert!(!config.track_in_flight);
        assert!(!config.auto_normalize);
    }

    // Layer tests

    #[test]
    fn test_layer_creation() {
        let _layer = MetricsLayer::new();
        let _layer = MetricsLayer::with_config(MetricsConfig::new());
    }

    #[test]
    fn test_in_flight_counter() {
        let counter = InFlightCounter::new();
        assert_eq!(counter.increment(), 1);
        assert_eq!(counter.increment(), 2);
        assert_eq!(counter.decrement(), 1);
        assert_eq!(counter.decrement(), 0);
    }
}

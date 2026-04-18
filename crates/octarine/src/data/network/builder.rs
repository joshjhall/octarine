//! URL normalization builder with observability
//!
//! Wraps `primitives::data::network` with observe instrumentation.

// Allow dead_code: This is public API that will be used by consumers
#![allow(dead_code)]

use std::borrow::Cow;
use std::time::Instant;

use crate::observe::metrics::{MetricName, increment, record};
use crate::primitives::data::network::{
    NormalizeUrlPathOptions as PrimitiveOptions, PathPattern as PrimitivePathPattern,
    normalize_path_segments as prim_normalize_segments,
    normalize_path_segments_with_patterns as prim_normalize_segments_with_patterns,
    normalize_url_path_with_options as prim_normalize_opts,
};

use super::types::{NormalizeUrlPathOptions, PathPattern};

// Pre-validated metric names
#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn normalize_ms() -> MetricName {
        MetricName::new("data.network.normalize_ms").expect("valid metric name")
    }

    pub fn normalize_count() -> MetricName {
        MetricName::new("data.network.normalize_count").expect("valid metric name")
    }

    pub fn normalize_segments_ms() -> MetricName {
        MetricName::new("data.network.normalize_segments_ms").expect("valid metric name")
    }

    pub fn normalize_segments_count() -> MetricName {
        MetricName::new("data.network.normalize_segments_count").expect("valid metric name")
    }
}

/// URL normalization builder with observability
///
/// Provides URL path normalization with full audit trail via observe.
///
/// # Example
///
/// ```ignore
/// use octarine::data::network::UrlNormalizationBuilder;
///
/// let builder = UrlNormalizationBuilder::new();
///
/// // Normalize with default options
/// let path = builder.normalize("/api//users/");
/// assert_eq!(path, "/api/users");
///
/// // Normalize with custom options
/// let path = builder.normalize_for_metrics("/API/Users/");
/// assert_eq!(path, "/api/users");
/// ```
#[derive(Debug, Clone, Default)]
pub struct UrlNormalizationBuilder {
    options: NormalizeUrlPathOptions,
    emit_events: bool,
}

impl UrlNormalizationBuilder {
    /// Create a new builder with strict normalization options
    #[must_use]
    pub fn new() -> Self {
        Self {
            options: NormalizeUrlPathOptions::strict(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            options: NormalizeUrlPathOptions::strict(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    /// Use custom normalization options
    #[must_use]
    pub fn with_options(mut self, options: NormalizeUrlPathOptions) -> Self {
        self.options = options;
        self
    }

    /// Use options suitable for metrics collection (lowercase)
    #[must_use]
    pub fn for_metrics(mut self) -> Self {
        self.options = NormalizeUrlPathOptions::for_metrics();
        self
    }

    /// Use minimal normalization options
    #[must_use]
    pub fn minimal(mut self) -> Self {
        self.options = NormalizeUrlPathOptions::minimal();
        self
    }

    /// Normalize a URL path using the configured options
    #[must_use]
    pub fn normalize<'a>(&self, path: &'a str) -> Cow<'a, str> {
        let start = Instant::now();

        let prim_opts: PrimitiveOptions = self.options.clone().into();
        let result = prim_normalize_opts(path, &prim_opts);

        if self.emit_events {
            record(
                metric_names::normalize_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            increment(metric_names::normalize_count());
        }

        result
    }

    /// Normalize a URL path with strict options
    #[must_use]
    pub fn normalize_strict<'a>(&self, path: &'a str) -> Cow<'a, str> {
        let start = Instant::now();

        let result = prim_normalize_opts(path, &PrimitiveOptions::strict());

        if self.emit_events {
            record(
                metric_names::normalize_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            increment(metric_names::normalize_count());
        }

        result
    }

    /// Normalize a URL path for metrics collection (lowercase)
    #[must_use]
    pub fn normalize_for_metrics<'a>(&self, path: &'a str) -> Cow<'a, str> {
        let start = Instant::now();

        let result = prim_normalize_opts(path, &PrimitiveOptions::for_metrics());

        if self.emit_events {
            record(
                metric_names::normalize_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            increment(metric_names::normalize_count());
        }

        result
    }

    /// Normalize path segments by replacing dynamic values with placeholders
    #[must_use]
    pub fn normalize_path_segments<'a>(&self, path: &'a str) -> Cow<'a, str> {
        let start = Instant::now();

        let result = prim_normalize_segments(path);

        if self.emit_events {
            record(
                metric_names::normalize_segments_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            increment(metric_names::normalize_segments_count());
        }

        result
    }

    /// Normalize path segments using custom patterns with auto-detection fallback
    #[must_use]
    pub fn normalize_path_segments_with_patterns<'a>(
        &self,
        path: &'a str,
        patterns: &[PathPattern],
    ) -> Cow<'a, str> {
        let start = Instant::now();

        let prim_patterns: Vec<PrimitivePathPattern> =
            patterns.iter().map(|p| p.as_ref().clone()).collect();
        let result = prim_normalize_segments_with_patterns(path, &prim_patterns);

        if self.emit_events {
            record(
                metric_names::normalize_segments_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            increment(metric_names::normalize_segments_count());
        }

        result
    }

    /// Check if a path needs normalization
    #[must_use]
    pub fn needs_normalization(&self, path: &str) -> bool {
        let normalized = self.normalize(path);
        matches!(normalized, Cow::Owned(_))
    }

    /// Get the current options
    #[must_use]
    pub fn options(&self) -> &NormalizeUrlPathOptions {
        &self.options
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_new() {
        let builder = UrlNormalizationBuilder::new();
        assert!(builder.emit_events);
        assert!(builder.options.remove_trailing_slash);
        assert!(builder.options.collapse_slashes);
        assert!(!builder.options.lowercase);
        assert!(builder.options.remove_dot_segments);
    }

    #[test]
    fn test_builder_silent() {
        let builder = UrlNormalizationBuilder::silent();
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_builder_normalize() {
        let builder = UrlNormalizationBuilder::silent();
        assert_eq!(builder.normalize("/api/users/"), "/api/users");
        assert_eq!(builder.normalize("/api//users"), "/api/users");
        assert_eq!(builder.normalize("/api/./users"), "/api/users");
    }

    #[test]
    fn test_builder_for_metrics() {
        let builder = UrlNormalizationBuilder::silent().for_metrics();
        assert!(builder.options.lowercase);
        assert_eq!(builder.normalize("/API/Users/"), "/api/users");
    }

    #[test]
    fn test_builder_minimal() {
        let builder = UrlNormalizationBuilder::silent().minimal();
        assert!(!builder.options.remove_trailing_slash);
        assert_eq!(builder.normalize("/api/users/"), "/api/users/");
    }

    #[test]
    fn test_needs_normalization() {
        let builder = UrlNormalizationBuilder::silent();
        assert!(builder.needs_normalization("/api/users/"));
        assert!(!builder.needs_normalization("/api/users"));
    }

    #[test]
    fn test_normalize_strict() {
        let builder = UrlNormalizationBuilder::silent();
        assert_eq!(builder.normalize_strict("/api/users/"), "/api/users");
        assert_eq!(builder.normalize_strict("/api//users"), "/api/users");
    }

    #[test]
    fn test_normalize_for_metrics() {
        let builder = UrlNormalizationBuilder::silent();
        assert_eq!(builder.normalize_for_metrics("/API/Users/"), "/api/users");
    }

    #[test]
    fn test_normalize_path_segments() {
        let builder = UrlNormalizationBuilder::silent();
        assert_eq!(builder.normalize_path_segments("/users/123"), "/users/{id}");
        assert_eq!(
            builder.normalize_path_segments("/users/550e8400-e29b-41d4-a716-446655440000"),
            "/users/{uuid}"
        );
        assert_eq!(builder.normalize_path_segments("/api/users"), "/api/users");
    }

    #[test]
    fn test_normalize_path_segments_with_patterns() {
        use crate::data::network::types::PathPattern;

        let builder = UrlNormalizationBuilder::silent();
        let patterns = vec![PathPattern::new("/api/{version}/users/{id}")];

        assert_eq!(
            builder.normalize_path_segments_with_patterns("/api/v1/users/123", &patterns,),
            "/api/{version}/users/{id}"
        );
        // Falls back to auto-detection
        assert_eq!(
            builder.normalize_path_segments_with_patterns("/other/456", &patterns,),
            "/other/{id}"
        );
    }
}

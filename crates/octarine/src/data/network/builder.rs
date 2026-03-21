//! URL normalization builder with observability
//!
//! Wraps `primitives::data::network` with observe instrumentation.

// Allow dead_code: This is public API that will be used by consumers
#![allow(dead_code)]

use std::borrow::Cow;
use std::time::Instant;

use crate::observe::metrics::{MetricName, record};
use crate::primitives::data::network::{
    NormalizeUrlPathOptions as PrimitiveOptions, normalize_url_path as prim_normalize,
    normalize_url_path_with_options as prim_normalize_opts,
};

use super::types::NormalizeUrlPathOptions;

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

        let prim_opts = PrimitiveOptions {
            remove_trailing_slash: self.options.remove_trailing_slash,
            collapse_slashes: self.options.collapse_slashes,
            lowercase: self.options.lowercase,
            remove_dot_segments: self.options.remove_dot_segments,
        };
        let result = prim_normalize_opts(path, &prim_opts);

        if self.emit_events {
            record(
                metric_names::normalize_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }

        result
    }

    /// Normalize a URL path with strict options (default)
    #[must_use]
    pub fn normalize_strict<'a>(&self, path: &'a str) -> Cow<'a, str> {
        prim_normalize(path)
    }

    /// Normalize a URL path for metrics collection (lowercase)
    #[must_use]
    pub fn normalize_for_metrics<'a>(&self, path: &'a str) -> Cow<'a, str> {
        let prim_opts = PrimitiveOptions::for_metrics();
        prim_normalize_opts(path, &prim_opts)
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
}

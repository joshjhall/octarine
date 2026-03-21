//! Configuration for tracing integration

use crate::observe::Severity;

/// Configuration for the tracing integration
#[derive(Debug, Clone)]
pub struct TracingConfig {
    /// Minimum severity level to forward to observe
    pub min_level: Severity,

    /// Whether to capture span enter/exit events
    pub capture_spans: bool,

    /// Whether to propagate correlation IDs from spans
    pub propagate_correlation: bool,

    /// Maximum number of events to buffer before dropping
    pub buffer_size: usize,

    /// Whether to include tracing span attributes in metadata
    pub include_span_attributes: bool,

    /// Whether to capture the target (module path) from tracing events
    pub capture_target: bool,

    /// Operation name to use when not specified in the tracing event
    pub default_operation: String,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            min_level: Severity::Debug,
            capture_spans: true,
            propagate_correlation: true,
            buffer_size: 10_000,
            include_span_attributes: true,
            capture_target: true,
            default_operation: "tracing".to_string(),
        }
    }
}

impl TracingConfig {
    /// Create a new TracingConfig with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the minimum severity level
    pub fn min_level(mut self, level: Severity) -> Self {
        self.min_level = level;
        self
    }

    /// Enable or disable span capture
    pub fn capture_spans(mut self, capture: bool) -> Self {
        self.capture_spans = capture;
        self
    }

    /// Enable or disable correlation ID propagation
    pub fn propagate_correlation(mut self, propagate: bool) -> Self {
        self.propagate_correlation = propagate;
        self
    }

    /// Set the buffer size
    pub fn buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    /// Enable or disable span attribute inclusion
    pub fn include_span_attributes(mut self, include: bool) -> Self {
        self.include_span_attributes = include;
        self
    }

    /// Enable or disable target capture
    pub fn capture_target(mut self, capture: bool) -> Self {
        self.capture_target = capture;
        self
    }

    /// Set the default operation name
    pub fn default_operation(mut self, operation: impl Into<String>) -> Self {
        self.default_operation = operation.into();
        self
    }

    /// Create a configuration for production use
    ///
    /// - Info level minimum
    /// - Spans captured
    /// - Correlation propagation enabled
    pub fn production() -> Self {
        Self::default()
            .min_level(Severity::Info)
            .capture_spans(true)
            .propagate_correlation(true)
    }

    /// Create a configuration for development use
    ///
    /// - Debug level minimum
    /// - Full attribute capture
    pub fn development() -> Self {
        Self::default()
            .min_level(Severity::Debug)
            .include_span_attributes(true)
    }

    /// Create a minimal configuration
    ///
    /// - Warning level minimum
    /// - No span capture
    /// - Correlation propagation only
    pub fn minimal() -> Self {
        Self::default()
            .min_level(Severity::Warning)
            .capture_spans(false)
            .include_span_attributes(false)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = TracingConfig::default();
        assert_eq!(config.min_level, Severity::Debug);
        assert!(config.capture_spans);
        assert!(config.propagate_correlation);
        assert_eq!(config.buffer_size, 10_000);
    }

    #[test]
    fn test_config_builder() {
        let config = TracingConfig::new()
            .min_level(Severity::Info)
            .capture_spans(false)
            .buffer_size(5000)
            .default_operation("myapp");

        assert_eq!(config.min_level, Severity::Info);
        assert!(!config.capture_spans);
        assert_eq!(config.buffer_size, 5000);
        assert_eq!(config.default_operation, "myapp");
    }

    #[test]
    fn test_production_preset() {
        let config = TracingConfig::production();
        assert_eq!(config.min_level, Severity::Info);
        assert!(config.capture_spans);
    }

    #[test]
    fn test_development_preset() {
        let config = TracingConfig::development();
        assert_eq!(config.min_level, Severity::Debug);
        assert!(config.include_span_attributes);
    }

    #[test]
    fn test_minimal_preset() {
        let config = TracingConfig::minimal();
        assert_eq!(config.min_level, Severity::Warning);
        assert!(!config.capture_spans);
    }
}

//! Metrics identifier builder with observability
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.

use crate::observe::Problem;
use crate::primitives::identifiers::{MetricViolation, MetricsBuilder as PrimitiveMetricsBuilder};

/// Metrics identifier builder with observability
#[derive(Debug, Clone)]
pub struct MetricsBuilder {
    inner: PrimitiveMetricsBuilder,
    emit_events: bool,
}

impl Default for MetricsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsBuilder {
    /// Create a new MetricsBuilder with default configuration and observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PrimitiveMetricsBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: PrimitiveMetricsBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    /// Set custom maximum metric name length
    #[must_use]
    pub fn with_max_name_length(mut self, length: usize) -> Self {
        self.inner = self.inner.with_max_name_length(length);
        self
    }

    /// Set custom maximum label key length
    #[must_use]
    pub fn with_max_label_key_length(mut self, length: usize) -> Self {
        self.inner = self.inner.with_max_label_key_length(length);
        self
    }

    /// Set custom maximum label value length
    #[must_use]
    pub fn with_max_label_value_length(mut self, length: usize) -> Self {
        self.inner = self.inner.with_max_label_value_length(length);
        self
    }

    /// Set custom maximum labels per metric
    #[must_use]
    pub fn with_max_labels(mut self, max: usize) -> Self {
        self.inner = self.inner.with_max_labels(max);
        self
    }

    // ========================================================================
    // Detection Methods (bool)
    // ========================================================================

    /// Check if a metric name is valid (returns bool)
    #[must_use]
    pub fn is_name(&self, name: &str) -> bool {
        self.inner.is_name(name)
    }

    /// Check if a label key is valid (returns bool)
    #[must_use]
    pub fn is_label_key(&self, key: &str) -> bool {
        self.inner.is_label_key(key)
    }

    /// Check if a label value is valid (returns bool)
    #[must_use]
    pub fn is_label_value(&self, value: &str) -> bool {
        self.inner.is_label_value(value)
    }

    /// Check if label count is within limits (returns bool)
    #[must_use]
    pub fn is_label_count_ok(&self, count: usize) -> bool {
        self.inner.is_label_count_ok(count)
    }

    // ========================================================================
    // Detect Methods (structured violations)
    // ========================================================================

    /// Detect all violations in a metric name
    ///
    /// Returns a Vec of all violations found. Empty Vec means the name is valid.
    #[must_use]
    pub fn detect_name_violations(&self, name: &str) -> Vec<MetricViolation> {
        self.inner.detect_name_violations(name)
    }

    /// Detect all violations in a label key
    #[must_use]
    pub fn detect_label_key_violations(&self, key: &str) -> Vec<MetricViolation> {
        self.inner.detect_label_key_violations(key)
    }

    /// Detect all violations in a label value
    #[must_use]
    pub fn detect_label_value_violations(&self, value: &str) -> Vec<MetricViolation> {
        self.inner.detect_label_value_violations(value)
    }

    // ========================================================================
    // Validation Methods (Result)
    // ========================================================================

    /// Validate a metric name (returns Result)
    pub fn validate_name(&self, name: &str) -> Result<(), Problem> {
        self.inner.validate_name(name)
    }

    /// Validate a label key (returns Result)
    pub fn validate_label_key(&self, key: &str) -> Result<(), Problem> {
        self.inner.validate_label_key(key)
    }

    /// Validate a label value (returns Result)
    pub fn validate_label_value(&self, value: &str) -> Result<(), Problem> {
        self.inner.validate_label_value(value)
    }

    /// Validate label count (returns Result)
    pub fn validate_label_count(&self, count: usize) -> Result<(), Problem> {
        self.inner.validate_label_count(count)
    }

    // ========================================================================
    // Normalization Methods (String - always succeeds)
    // ========================================================================

    /// Normalize a metric name to valid format (always succeeds)
    #[must_use]
    pub fn normalize_name(&self, name: &str) -> String {
        self.inner.normalize_name(name)
    }

    /// Normalize a label key to valid format (always succeeds)
    #[must_use]
    pub fn normalize_label_key(&self, key: &str) -> String {
        self.inner.normalize_label_key(key)
    }

    /// Normalize a label value to valid format (always succeeds)
    #[must_use]
    pub fn normalize_label_value(&self, value: &str) -> String {
        self.inner.normalize_label_value(value)
    }

    // ========================================================================
    // Sanitization Methods (Result - can fail)
    // ========================================================================

    /// Sanitize a metric name, returning an error if invalid
    pub fn sanitize_name(&self, name: &str) -> Result<String, Problem> {
        self.inner.sanitize_name(name)
    }

    /// Sanitize a label key, returning an error if invalid
    pub fn sanitize_label_key(&self, key: &str) -> Result<String, Problem> {
        self.inner.sanitize_label_key(key)
    }

    /// Sanitize a label value, returning an error if invalid
    pub fn sanitize_label_value(&self, value: &str) -> Result<String, Problem> {
        self.inner.sanitize_label_value(value)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = MetricsBuilder::new();
        assert!(builder.emit_events);

        let silent = MetricsBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = MetricsBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_name_detection() {
        let builder = MetricsBuilder::silent();
        assert!(builder.is_name("api_requests"));
        assert!(!builder.is_name("123metric"));
    }

    #[test]
    fn test_validation() {
        let builder = MetricsBuilder::new();
        assert!(builder.validate_name("api_requests").is_ok());
        assert!(builder.validate_name("").is_err());
    }

    #[test]
    fn test_normalization() {
        let builder = MetricsBuilder::new();
        assert_eq!(builder.normalize_name("API-Requests"), "api_requests");
        assert_eq!(builder.normalize_name(""), "metric");
    }

    #[test]
    fn test_sanitization() {
        let builder = MetricsBuilder::new();
        assert!(builder.sanitize_name("api_requests").is_ok());
        // Sanitization rejects empty strings
        assert!(builder.sanitize_name("").is_err());
        // Sanitization rejects injection patterns
        assert!(builder.sanitize_name("$(whoami)").is_err());
    }

    #[test]
    fn test_labels() {
        let builder = MetricsBuilder::new();
        assert!(builder.is_label_key("method"));
        assert!(builder.is_label_value("GET"));
        assert!(builder.is_label_count_ok(10));
    }
}

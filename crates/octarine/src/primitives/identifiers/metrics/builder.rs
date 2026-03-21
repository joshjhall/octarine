//! Metrics builder for convenient access to all metrics functions
//!
//! The MetricsBuilder provides a unified interface for detection,
//! validation, and sanitization of metric names and labels.

use super::{
    MAX_LABEL_KEY_LENGTH, MAX_LABEL_VALUE_LENGTH, MAX_LABELS_PER_METRIC, MAX_METRIC_NAME_LENGTH,
};
use super::{detection, sanitization, validation};
use crate::primitives::types::Problem;

/// Builder for metrics validation, detection, and sanitization
///
/// Provides configurable access to all metrics functions with optional
/// custom limits.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::metrics::MetricsBuilder;
///
/// let mb = MetricsBuilder::new();
///
/// // Detection (bool)
/// if mb.is_name("api.requests") {
///     println!("Valid!");
/// }
///
/// // Validation (Result)
/// mb.validate_name("api.requests")?;
///
/// // Sanitization
/// let safe = mb.sanitize_name("API-Requests");
/// ```
#[derive(Debug, Clone)]
pub struct MetricsBuilder {
    max_name_length: usize,
    max_label_key_length: usize,
    max_label_value_length: usize,
    max_labels: usize,
}

impl Default for MetricsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsBuilder {
    /// Create a new MetricsBuilder with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_name_length: MAX_METRIC_NAME_LENGTH,
            max_label_key_length: MAX_LABEL_KEY_LENGTH,
            max_label_value_length: MAX_LABEL_VALUE_LENGTH,
            max_labels: MAX_LABELS_PER_METRIC,
        }
    }

    /// Set custom maximum metric name length
    #[must_use]
    pub fn with_max_name_length(mut self, length: usize) -> Self {
        self.max_name_length = length;
        self
    }

    /// Set custom maximum label key length
    #[must_use]
    pub fn with_max_label_key_length(mut self, length: usize) -> Self {
        self.max_label_key_length = length;
        self
    }

    /// Set custom maximum label value length
    #[must_use]
    pub fn with_max_label_value_length(mut self, length: usize) -> Self {
        self.max_label_value_length = length;
        self
    }

    /// Set custom maximum labels per metric
    #[must_use]
    pub fn with_max_labels(mut self, max: usize) -> Self {
        self.max_labels = max;
        self
    }

    // ========================================================================
    // Detection Methods (bool)
    // ========================================================================

    /// Check if a metric name is valid (returns bool)
    #[must_use]
    pub fn is_name(&self, name: &str) -> bool {
        detection::is_valid_name_with_config(name, self.max_name_length)
    }

    /// Check if a label key is valid (returns bool)
    #[must_use]
    pub fn is_label_key(&self, key: &str) -> bool {
        detection::is_valid_label_key_with_config(key, self.max_label_key_length)
    }

    /// Check if a label value is valid (returns bool)
    #[must_use]
    pub fn is_label_value(&self, value: &str) -> bool {
        detection::is_valid_label_value_with_config(value, self.max_label_value_length)
    }

    /// Check if label count is within limits (returns bool)
    #[must_use]
    pub fn is_label_count_ok(&self, count: usize) -> bool {
        detection::is_valid_label_count_with_config(count, self.max_labels)
    }

    // ========================================================================
    // Validation Methods (Result)
    // ========================================================================

    /// Validate a metric name (returns Result)
    pub fn validate_name(&self, name: &str) -> Result<(), Problem> {
        validation::validate_name_with_config(name, self.max_name_length)
    }

    /// Validate a label key (returns Result)
    pub fn validate_label_key(&self, key: &str) -> Result<(), Problem> {
        validation::validate_label_key_with_config(key, self.max_label_key_length)
    }

    /// Validate a label value (returns Result)
    pub fn validate_label_value(&self, value: &str) -> Result<(), Problem> {
        validation::validate_label_value_with_config(value, self.max_label_value_length)
    }

    /// Validate label count (returns Result)
    pub fn validate_label_count(&self, count: usize) -> Result<(), Problem> {
        validation::validate_label_count_with_config(count, self.max_labels)
    }

    // ========================================================================
    // Normalization Methods (String - always succeeds)
    // ========================================================================

    /// Normalize a metric name to valid format (always succeeds)
    #[must_use]
    pub fn normalize_name(&self, name: &str) -> String {
        sanitization::sanitize_name_with_config(name, self.max_name_length)
    }

    /// Normalize a label key to valid format (always succeeds)
    #[must_use]
    pub fn normalize_label_key(&self, key: &str) -> String {
        sanitization::sanitize_label_key(key)
    }

    /// Normalize a label value to valid format (always succeeds)
    #[must_use]
    pub fn normalize_label_value(&self, value: &str) -> String {
        sanitization::sanitize_label_value_with_config(value, self.max_label_value_length)
    }

    // ========================================================================
    // Sanitization Methods (Result - can fail)
    // ========================================================================

    /// Sanitize a metric name, returning an error if invalid
    pub fn sanitize_name(&self, name: &str) -> Result<String, Problem> {
        sanitization::sanitize_name_strict(name)
    }

    /// Sanitize a label key, returning an error if invalid
    pub fn sanitize_label_key(&self, key: &str) -> Result<String, Problem> {
        sanitization::sanitize_label_key_strict(key)
    }

    /// Sanitize a label value, returning an error if invalid
    pub fn sanitize_label_value(&self, value: &str) -> Result<String, Problem> {
        sanitization::sanitize_label_value_strict(value)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_default() {
        let mb = MetricsBuilder::new();
        assert!(mb.is_name("api_requests"));
        assert!(!mb.is_name(""));
    }

    #[test]
    fn test_builder_custom_name_length() {
        let mb = MetricsBuilder::new().with_max_name_length(10);

        assert!(mb.is_name("short"));
        assert!(!mb.is_name("this_is_too_long"));
    }

    #[test]
    fn test_builder_custom_labels() {
        let mb = MetricsBuilder::new().with_max_labels(5);

        assert!(mb.is_label_count_ok(5));
        assert!(!mb.is_label_count_ok(6));
    }

    #[test]
    fn test_builder_validation() {
        let mb = MetricsBuilder::new();

        assert!(mb.validate_name("api_requests").is_ok());
        assert!(mb.validate_name("").is_err());
    }

    #[test]
    fn test_builder_normalization() {
        let mb = MetricsBuilder::new();

        assert_eq!(mb.normalize_name("API-Requests"), "api_requests");
        assert_eq!(mb.normalize_name(""), "metric");
    }

    #[test]
    fn test_builder_sanitization() {
        let mb = MetricsBuilder::new();

        assert!(mb.sanitize_name("api_requests").is_ok());
        // Sanitization rejects empty strings
        assert!(mb.sanitize_name("").is_err());
        // Sanitization rejects injection patterns
        assert!(mb.sanitize_name("$(whoami)").is_err());
    }

    #[test]
    fn test_builder_chaining() {
        let mb = MetricsBuilder::new()
            .with_max_name_length(50)
            .with_max_label_key_length(30)
            .with_max_label_value_length(100)
            .with_max_labels(10);

        // Verify settings applied
        assert!(mb.is_name(&"a".repeat(50)));
        assert!(!mb.is_name(&"a".repeat(51)));
        assert!(mb.is_label_count_ok(10));
        assert!(!mb.is_label_count_ok(11));
    }
}

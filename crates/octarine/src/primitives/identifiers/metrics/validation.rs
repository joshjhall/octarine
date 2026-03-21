//! Metrics validation functions
//!
//! Result-returning validation functions for metric names and labels.
//! These are the "validate_*" functions that return Result<(), Problem>.

use super::detection;
use super::{
    MAX_LABEL_KEY_LENGTH, MAX_LABEL_VALUE_LENGTH, MAX_LABELS_PER_METRIC, MAX_METRIC_NAME_LENGTH,
};
use crate::primitives::types::Problem;

/// Result type for validation operations
pub type ValidationResult = Result<(), Problem>;

// ============================================================================
// Metric Name Validation
// ============================================================================

/// Validate a metric name
///
/// Returns `Ok(())` if valid, or `Err(Problem)` with details if invalid.
///
/// # Errors
///
/// Returns error if:
/// - Name is empty
/// - Name exceeds MAX_METRIC_NAME_LENGTH
/// - Name starts with invalid character
/// - Name contains invalid characters
/// - Name contains injection patterns
/// - Name has consecutive separators
/// - Name starts/ends with dot
pub fn validate_name(name: &str) -> ValidationResult {
    validate_name_with_config(name, MAX_METRIC_NAME_LENGTH)
}

/// Validate a metric name with custom max length
pub fn validate_name_with_config(name: &str, max_length: usize) -> ValidationResult {
    if name.is_empty() {
        return Err(Problem::validation("Metric name cannot be empty"));
    }

    if name.len() > max_length {
        return Err(Problem::validation(format!(
            "Metric name exceeds {} characters",
            max_length
        )));
    }

    if !detection::is_valid_name_with_config(name, max_length) {
        // Provide specific error messages
        if !super::super::common::is_valid_start_char(name) {
            return Err(Problem::validation(
                "Metric name must start with letter or underscore",
            ));
        }
        if !super::super::common::is_identifier_chars(name, &['.']) {
            return Err(Problem::validation(
                "Metric name contains invalid characters (use alphanumeric, underscore, or dot)",
            ));
        }
        if super::super::common::is_injection_pattern_present(name) {
            return Err(Problem::security(
                "Injection pattern detected in metric name",
            ));
        }
        if detection::is_consecutive_separators(name) {
            return Err(Problem::validation(
                "Metric name contains consecutive separators",
            ));
        }
        if detection::is_separator_at_boundary(name) {
            return Err(Problem::validation(
                "Metric name cannot start or end with a dot",
            ));
        }
        // Fallback
        return Err(Problem::validation("Invalid metric name"));
    }

    Ok(())
}

// ============================================================================
// Label Key Validation
// ============================================================================

/// Validate a label key
pub fn validate_label_key(key: &str) -> ValidationResult {
    validate_label_key_with_config(key, MAX_LABEL_KEY_LENGTH)
}

/// Validate a label key with custom max length
pub fn validate_label_key_with_config(key: &str, max_length: usize) -> ValidationResult {
    if key.is_empty() {
        return Err(Problem::validation("Label key cannot be empty"));
    }

    // Label keys follow metric name rules
    validate_name_with_config(key, max_length)
}

// ============================================================================
// Label Value Validation
// ============================================================================

/// Validate a label value
pub fn validate_label_value(value: &str) -> ValidationResult {
    validate_label_value_with_config(value, MAX_LABEL_VALUE_LENGTH)
}

/// Validate a label value with custom max length
pub fn validate_label_value_with_config(value: &str, max_length: usize) -> ValidationResult {
    if value.len() > max_length {
        return Err(Problem::validation(format!(
            "Label value exceeds {} characters",
            max_length
        )));
    }

    if !detection::is_valid_label_value_with_config(value, max_length) {
        if super::super::common::is_severe_injection_pattern_present(value) {
            return Err(Problem::security(
                "Injection pattern detected in label value",
            ));
        }
        if super::super::common::is_control_chars_present(value) {
            return Err(Problem::validation(
                "Label value contains control characters",
            ));
        }
        // Fallback
        return Err(Problem::validation("Invalid label value"));
    }

    Ok(())
}

// ============================================================================
// Label Count Validation
// ============================================================================

/// Validate label count
pub fn validate_label_count(count: usize) -> ValidationResult {
    validate_label_count_with_config(count, MAX_LABELS_PER_METRIC)
}

/// Validate label count with custom max
pub fn validate_label_count_with_config(count: usize, max_labels: usize) -> ValidationResult {
    if count > max_labels {
        return Err(Problem::security(format!(
            "Cardinality limit exceeded: {} labels (max: {})",
            count, max_labels
        )));
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ------------------------------------------------------------------------
    // Metric Name Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validate_valid_names() {
        assert!(validate_name("api_requests").is_ok());
        assert!(validate_name("http.requests.total").is_ok());
        assert!(validate_name("_internal_metric").is_ok());
    }

    #[test]
    fn test_validate_empty_name() {
        let result = validate_name("");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected error")
                .to_string()
                .contains("empty")
        );
    }

    #[test]
    fn test_validate_long_name() {
        let too_long = "a".repeat(MAX_METRIC_NAME_LENGTH + 1);
        let result = validate_name(&too_long);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected error")
                .to_string()
                .contains("exceeds")
        );
    }

    #[test]
    fn test_validate_invalid_start() {
        let result = validate_name("123metric");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected error")
                .to_string()
                .contains("start")
        );
    }

    #[test]
    fn test_validate_injection() {
        let result = validate_name("$(whoami)");
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------------
    // Label Key Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validate_label_keys() {
        assert!(validate_label_key("method").is_ok());
        assert!(validate_label_key("status_code").is_ok());
        assert!(validate_label_key("").is_err());
    }

    // ------------------------------------------------------------------------
    // Label Value Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validate_label_values() {
        assert!(validate_label_value("GET").is_ok());
        assert!(validate_label_value("value with spaces").is_ok());
        assert!(validate_label_value("/api/users").is_ok());
    }

    #[test]
    fn test_validate_label_value_injection() {
        assert!(validate_label_value("'; DROP TABLE").is_err());
        assert!(validate_label_value("<script>alert(1)</script>").is_err());
    }

    // ------------------------------------------------------------------------
    // Label Count Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_validate_label_count() {
        assert!(validate_label_count(0).is_ok());
        assert!(validate_label_count(MAX_LABELS_PER_METRIC).is_ok());
        assert!(validate_label_count(MAX_LABELS_PER_METRIC + 1).is_err());
    }
}

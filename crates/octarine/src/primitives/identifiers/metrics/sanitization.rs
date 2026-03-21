//! Metrics sanitization functions
//!
//! Functions to sanitize metric names and labels into valid formats.

use super::MAX_METRIC_NAME_LENGTH;
use super::detection::is_valid_metric_char;
use crate::primitives::types::Problem;

// ============================================================================
// Metric Name Sanitization
// ============================================================================

/// Sanitize a metric name to make it valid (lenient)
///
/// Transforms the input to conform to metric naming rules:
/// - Converts to lowercase
/// - Replaces invalid characters with underscores
/// - Ensures valid start character
/// - Truncates to max length
/// - Returns "metric" if result would be empty
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::metrics::sanitization;
///
/// assert_eq!(sanitization::sanitize_name("API-Requests"), "api_requests");
/// assert_eq!(sanitization::sanitize_name("123metric"), "_123metric");
/// assert_eq!(sanitization::sanitize_name(""), "metric");
/// ```
#[must_use]
pub fn sanitize_name(name: &str) -> String {
    sanitize_name_with_config(name, MAX_METRIC_NAME_LENGTH)
}

/// Sanitize a metric name with custom max length
#[must_use]
pub fn sanitize_name_with_config(name: &str, max_length: usize) -> String {
    let mut result = String::with_capacity(name.len().min(max_length));

    for (i, ch) in name.chars().enumerate() {
        if result.len() >= max_length {
            break;
        }

        if i == 0 {
            // First character must be letter or underscore
            if ch.is_ascii_alphabetic() {
                result.push(ch.to_ascii_lowercase());
            } else if ch == '_' {
                result.push('_');
            } else {
                result.push('_');
                if ch.is_ascii_alphanumeric() && result.len() < max_length {
                    result.push(ch.to_ascii_lowercase());
                }
            }
        } else {
            // Subsequent characters
            if is_valid_metric_char(ch) {
                result.push(ch.to_ascii_lowercase());
            } else if ch == '-' || ch == '/' || ch == ' ' {
                // Convert common separators to underscore
                result.push('_');
            }
            // Skip other invalid characters
        }
    }

    // Ensure not empty
    if result.is_empty() {
        result.push_str("metric");
    }

    result
}

/// Sanitize a metric name strictly
///
/// Normalizes the input and validates the result. Returns `Err` if the input
/// is empty, contains injection patterns, or cannot be sanitized to a valid name.
///
/// # Errors
///
/// Returns error if:
/// - Input is empty
/// - Input contains injection patterns
/// - Sanitized result would be invalid
pub fn sanitize_name_strict(name: &str) -> Result<String, Problem> {
    // Empty input cannot be sanitized
    if name.is_empty() {
        return Err(Problem::validation("Metric name cannot be empty"));
    }

    // Check for injection patterns that shouldn't be silently sanitized
    if super::super::common::is_injection_pattern_present(name) {
        return Err(Problem::security(
            "Metric name contains injection patterns - rejecting instead of sanitizing",
        ));
    }

    // Normalize and validate result
    let sanitized = sanitize_name(name);

    // Validate the sanitized result (it should be valid after sanitization,
    // but verify to ensure consistency)
    super::validation::validate_name(&sanitized)?;

    Ok(sanitized)
}

// ============================================================================
// Label Key Sanitization
// ============================================================================

/// Sanitize a label key (lenient)
#[must_use]
pub fn sanitize_label_key(key: &str) -> String {
    sanitize_name(key)
}

/// Sanitize a label key strictly
pub fn sanitize_label_key_strict(key: &str) -> Result<String, Problem> {
    sanitize_name_strict(key)
}

// ============================================================================
// Label Value Sanitization
// ============================================================================

/// Sanitize a label value (lenient)
///
/// Label values are more permissive, but we still:
/// - Remove control characters
/// - Truncate to max length
#[must_use]
pub fn sanitize_label_value(value: &str) -> String {
    sanitize_label_value_with_config(value, super::MAX_LABEL_VALUE_LENGTH)
}

/// Sanitize a label value with custom max length
#[must_use]
pub fn sanitize_label_value_with_config(value: &str, max_length: usize) -> String {
    let result: String = value
        .chars()
        .filter(|ch| !ch.is_control() || *ch == '\t')
        .take(max_length)
        .collect();

    result
}

/// Sanitize a label value strictly
pub fn sanitize_label_value_strict(value: &str) -> Result<String, Problem> {
    if super::super::common::is_severe_injection_pattern_present(value) {
        return Err(Problem::security(
            "Label value contains severe injection patterns",
        ));
    }

    Ok(sanitize_label_value(value))
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
    fn test_sanitize_basic() {
        assert_eq!(sanitize_name("api_requests"), "api_requests");
        assert_eq!(sanitize_name("http.requests.total"), "http.requests.total");
    }

    #[test]
    fn test_sanitize_case() {
        assert_eq!(sanitize_name("API_REQUESTS"), "api_requests");
        assert_eq!(sanitize_name("HttpRequests"), "httprequests");
    }

    #[test]
    fn test_sanitize_separators() {
        assert_eq!(sanitize_name("api-requests"), "api_requests");
        assert_eq!(sanitize_name("api/requests/total"), "api_requests_total");
        assert_eq!(sanitize_name("api requests"), "api_requests");
    }

    #[test]
    fn test_sanitize_invalid_start() {
        assert_eq!(sanitize_name("123metric"), "_123metric");
        assert_eq!(sanitize_name("-metric"), "_metric");
    }

    #[test]
    fn test_sanitize_empty() {
        assert_eq!(sanitize_name(""), "metric");
    }

    #[test]
    fn test_sanitize_length() {
        let long_name = "a".repeat(300);
        let result = sanitize_name(&long_name);
        assert!(result.len() <= MAX_METRIC_NAME_LENGTH);
    }

    #[test]
    fn test_sanitize_strict_injection() {
        assert!(sanitize_name_strict("api_requests").is_ok());
        assert!(sanitize_name_strict("$(whoami)").is_err());
        assert!(sanitize_name_strict("metric;drop").is_err());
    }

    // ------------------------------------------------------------------------
    // Label Value Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_sanitize_label_value_basic() {
        assert_eq!(sanitize_label_value("GET"), "GET");
        assert_eq!(
            sanitize_label_value("value with spaces"),
            "value with spaces"
        );
    }

    #[test]
    fn test_sanitize_label_value_control_chars() {
        // Control characters removed except tab
        assert_eq!(
            sanitize_label_value("value\twith\ttabs"),
            "value\twith\ttabs"
        );
        assert_eq!(
            sanitize_label_value("value\nwith\nnewlines"),
            "valuewithnewlines"
        );
    }

    #[test]
    fn test_sanitize_label_value_strict() {
        assert!(sanitize_label_value_strict("normal value").is_ok());
        assert!(sanitize_label_value_strict("'; DROP TABLE").is_err());
    }
}

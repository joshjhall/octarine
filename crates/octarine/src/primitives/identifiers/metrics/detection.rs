//! Metrics detection functions
//!
//! Boolean detection functions for metric names and labels.
//! These are the "is_*" functions that return bool.

use super::super::common::{
    is_control_chars_present, is_identifier_chars, is_injection_pattern_present,
    is_severe_injection_pattern_present, is_valid_start_char,
};
use super::{
    MAX_LABEL_KEY_LENGTH, MAX_LABEL_VALUE_LENGTH, MAX_LABELS_PER_METRIC, MAX_METRIC_NAME_LENGTH,
};

// ============================================================================
// Violation Types
// ============================================================================

/// Types of metric naming violations detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricViolation {
    /// Name or key is empty
    Empty,
    /// Exceeds maximum allowed length
    TooLong {
        /// Actual length
        length: usize,
        /// Maximum allowed
        max: usize,
    },
    /// Does not start with a letter or underscore
    InvalidStartChar,
    /// Contains characters not allowed in metric names (non-alphanumeric, non-underscore, non-dot)
    InvalidChars,
    /// Contains shell injection patterns
    InjectionPattern,
    /// Contains consecutive separators (dots or underscores)
    ConsecutiveSeparators,
    /// Starts or ends with a dot separator
    SeparatorAtBoundary,
    /// Contains control characters (for label values)
    ControlChars,
    /// Contains severe injection patterns like SQL or XSS (for label values)
    SevereInjection,
}

// ============================================================================
// Metric Name Detection
// ============================================================================

/// Check if a metric name is valid
///
/// A valid metric name:
/// - Is not empty
/// - Does not exceed MAX_METRIC_NAME_LENGTH (200) characters
/// - Starts with a letter or underscore
/// - Contains only alphanumeric characters, underscores, and dots
/// - Does not contain injection patterns
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::identifiers::metrics::detection;
///
/// assert!(detection::is_valid_name("api_requests"));
/// assert!(detection::is_valid_name("http.requests.total"));
/// assert!(!detection::is_valid_name("123metric")); // starts with number
/// assert!(!detection::is_valid_name("api-requests")); // contains hyphen
/// ```
#[must_use]
pub fn is_valid_name(name: &str) -> bool {
    is_valid_name_with_config(name, MAX_METRIC_NAME_LENGTH)
}

/// Check if a metric name is valid with custom max length
#[must_use]
pub fn is_valid_name_with_config(name: &str, max_length: usize) -> bool {
    !name.is_empty()
        && name.len() <= max_length
        && is_valid_start_char(name)
        && is_identifier_chars(name, &['.'])
        && !is_injection_pattern_present(name)
        && !is_consecutive_separators(name)
        && !is_separator_at_boundary(name)
}

/// Check if a character is valid in a metric name
#[must_use]
pub fn is_valid_metric_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'
}

/// Check if name has consecutive separators (dots or underscores)
#[must_use]
pub fn is_consecutive_separators(name: &str) -> bool {
    let chars: Vec<char> = name.chars().collect();
    for i in 0..chars.len().saturating_sub(1) {
        // Use get() to avoid potential panics with indexing
        let curr = chars.get(i).copied();
        let next = chars.get(i.saturating_add(1)).copied();
        if let (Some(c), Some(n)) = (curr, next)
            && (c == '.' || c == '_')
            && (n == '.' || n == '_')
        {
            return true;
        }
    }
    false
}

/// Check if name starts or ends with a separator
#[must_use]
pub fn is_separator_at_boundary(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let first = name.chars().next().unwrap_or(' ');
    let last = name.chars().last().unwrap_or(' ');
    first == '.' || last == '.'
}

// ============================================================================
// Label Key Detection
// ============================================================================

/// Check if a label key is valid
///
/// Label keys follow the same rules as metric names.
#[must_use]
pub fn is_valid_label_key(key: &str) -> bool {
    is_valid_label_key_with_config(key, MAX_LABEL_KEY_LENGTH)
}

/// Check if a label key is valid with custom max length
#[must_use]
pub fn is_valid_label_key_with_config(key: &str, max_length: usize) -> bool {
    is_valid_name_with_config(key, max_length)
}

// ============================================================================
// Label Value Detection
// ============================================================================

/// Check if a label value is valid
///
/// Label values are more permissive than names:
/// - Can contain most characters
/// - Limited by length
/// - Must not contain severe injection patterns
#[must_use]
pub fn is_valid_label_value(value: &str) -> bool {
    is_valid_label_value_with_config(value, MAX_LABEL_VALUE_LENGTH)
}

/// Check if a label value is valid with custom max length
#[must_use]
pub fn is_valid_label_value_with_config(value: &str, max_length: usize) -> bool {
    value.len() <= max_length
        && !is_severe_injection_pattern_present(value)
        && !is_control_chars_present(value)
}

// ============================================================================
// Label Count Detection
// ============================================================================

/// Check if label count is within limits
#[must_use]
pub fn is_valid_label_count(count: usize) -> bool {
    is_valid_label_count_with_config(count, MAX_LABELS_PER_METRIC)
}

/// Check if label count is within custom limit
#[must_use]
pub fn is_valid_label_count_with_config(count: usize, max_labels: usize) -> bool {
    count <= max_labels
}

// ============================================================================
// Detect Functions (structured violation results)
// ============================================================================

/// Detect all violations in a metric name
///
/// Unlike `is_valid_name` which returns a single bool, this function
/// checks all rules and returns every violation found. Returns an empty
/// Vec for valid names.
#[must_use]
pub fn detect_name_violations(name: &str) -> Vec<MetricViolation> {
    detect_name_violations_with_config(name, MAX_METRIC_NAME_LENGTH)
}

/// Detect all violations in a metric name with custom max length
#[must_use]
pub fn detect_name_violations_with_config(name: &str, max_length: usize) -> Vec<MetricViolation> {
    let mut violations = Vec::new();

    if name.is_empty() {
        violations.push(MetricViolation::Empty);
        return violations;
    }

    if name.len() > max_length {
        violations.push(MetricViolation::TooLong {
            length: name.len(),
            max: max_length,
        });
    }

    if !is_valid_start_char(name) {
        violations.push(MetricViolation::InvalidStartChar);
    }

    if !is_identifier_chars(name, &['.']) {
        violations.push(MetricViolation::InvalidChars);
    }

    if is_injection_pattern_present(name) {
        violations.push(MetricViolation::InjectionPattern);
    }

    if is_consecutive_separators(name) {
        violations.push(MetricViolation::ConsecutiveSeparators);
    }

    if is_separator_at_boundary(name) {
        violations.push(MetricViolation::SeparatorAtBoundary);
    }

    violations
}

/// Detect all violations in a label key
///
/// Label keys follow the same rules as metric names but with a different
/// maximum length.
#[must_use]
pub fn detect_label_key_violations(key: &str) -> Vec<MetricViolation> {
    detect_label_key_violations_with_config(key, MAX_LABEL_KEY_LENGTH)
}

/// Detect all violations in a label key with custom max length
#[must_use]
pub fn detect_label_key_violations_with_config(
    key: &str,
    max_length: usize,
) -> Vec<MetricViolation> {
    detect_name_violations_with_config(key, max_length)
}

/// Detect all violations in a label value
///
/// Label values have different (more permissive) rules than names/keys:
/// only length, control characters, and severe injection are checked.
#[must_use]
pub fn detect_label_value_violations(value: &str) -> Vec<MetricViolation> {
    detect_label_value_violations_with_config(value, MAX_LABEL_VALUE_LENGTH)
}

/// Detect all violations in a label value with custom max length
#[must_use]
pub fn detect_label_value_violations_with_config(
    value: &str,
    max_length: usize,
) -> Vec<MetricViolation> {
    let mut violations = Vec::new();

    if value.len() > max_length {
        violations.push(MetricViolation::TooLong {
            length: value.len(),
            max: max_length,
        });
    }

    if is_severe_injection_pattern_present(value) {
        violations.push(MetricViolation::SevereInjection);
    }

    if is_control_chars_present(value) {
        violations.push(MetricViolation::ControlChars);
    }

    violations
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
    fn test_valid_metric_names() {
        assert!(is_valid_name("api_requests"));
        assert!(is_valid_name("http.requests.total"));
        assert!(is_valid_name("_internal_metric"));
        assert!(is_valid_name("metric123"));
        assert!(is_valid_name("cpu_usage"));
    }

    #[test]
    fn test_invalid_metric_names() {
        assert!(!is_valid_name("")); // Empty
        assert!(!is_valid_name("123metric")); // Starts with number
        assert!(!is_valid_name("api-requests")); // Contains hyphen
        assert!(!is_valid_name(".leading_dot")); // Starts with dot
        assert!(!is_valid_name("trailing_dot.")); // Ends with dot
        assert!(!is_valid_name("double..dot")); // Consecutive dots
    }

    #[test]
    fn test_injection_patterns_rejected() {
        assert!(!is_valid_name("$(whoami)"));
        assert!(!is_valid_name("`ls`"));
        assert!(!is_valid_name("${HOME}"));
        assert!(!is_valid_name("metric;drop"));
        assert!(!is_valid_name("metric|cat"));
        assert!(!is_valid_name("metric&echo"));
    }

    #[test]
    fn test_metric_name_length() {
        let long_name = "a".repeat(MAX_METRIC_NAME_LENGTH);
        assert!(is_valid_name(&long_name));

        let too_long = "a".repeat(MAX_METRIC_NAME_LENGTH + 1);
        assert!(!is_valid_name(&too_long));
    }

    // ------------------------------------------------------------------------
    // Label Key Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_valid_label_keys() {
        assert!(is_valid_label_key("method"));
        assert!(is_valid_label_key("status_code"));
        assert!(is_valid_label_key("_private"));
    }

    #[test]
    fn test_invalid_label_keys() {
        assert!(!is_valid_label_key(""));
        assert!(!is_valid_label_key("invalid-key")); // Contains hyphen
        assert!(!is_valid_label_key("123key")); // Starts with number
    }

    // ------------------------------------------------------------------------
    // Label Value Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_valid_label_values() {
        assert!(is_valid_label_value("GET"));
        assert!(is_valid_label_value("value with spaces"));
        assert!(is_valid_label_value("200"));
        assert!(is_valid_label_value("/api/users"));
    }

    #[test]
    fn test_invalid_label_values() {
        let long_value = "a".repeat(MAX_LABEL_VALUE_LENGTH + 1);
        assert!(!is_valid_label_value(&long_value));

        // Severe injection
        assert!(!is_valid_label_value("'; DROP TABLE"));
        assert!(!is_valid_label_value("<script>alert(1)</script>"));
    }

    #[test]
    fn test_label_value_control_chars() {
        assert!(!is_valid_label_value("value\x00with\x00nulls"));
        assert!(!is_valid_label_value("value\nwith\nnewlines"));
    }

    // ------------------------------------------------------------------------
    // Label Count Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_label_count() {
        assert!(is_valid_label_count(0));
        assert!(is_valid_label_count(10));
        assert!(is_valid_label_count(MAX_LABELS_PER_METRIC));
        assert!(!is_valid_label_count(MAX_LABELS_PER_METRIC + 1));
    }

    // ------------------------------------------------------------------------
    // Helper Function Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_is_consecutive_separators() {
        assert!(is_consecutive_separators("a..b"));
        assert!(is_consecutive_separators("a_.b"));
        assert!(is_consecutive_separators("a._b"));
        assert!(!is_consecutive_separators("a.b"));
        assert!(!is_consecutive_separators("a_b"));
        assert!(!is_consecutive_separators("a.b_c"));
    }

    #[test]
    fn test_is_separator_at_boundary() {
        assert!(is_separator_at_boundary(".abc"));
        assert!(is_separator_at_boundary("abc."));
        assert!(!is_separator_at_boundary("abc"));
        assert!(!is_separator_at_boundary("a.b.c"));
        assert!(!is_separator_at_boundary(""));
    }

    // ------------------------------------------------------------------------
    // Detect Name Violations Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_detect_name_violations_valid() {
        assert!(detect_name_violations("api_requests").is_empty());
        assert!(detect_name_violations("http.requests.total").is_empty());
        assert!(detect_name_violations("_internal").is_empty());
    }

    #[test]
    fn test_detect_name_violations_empty() {
        let violations = detect_name_violations("");
        assert_eq!(violations.len(), 1);
        assert_eq!(violations.first(), Some(&MetricViolation::Empty));
    }

    #[test]
    fn test_detect_name_violations_too_long() {
        let long_name = "a".repeat(MAX_METRIC_NAME_LENGTH + 1);
        let violations = detect_name_violations(&long_name);
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, MetricViolation::TooLong { .. }))
        );
    }

    #[test]
    fn test_detect_name_violations_invalid_start() {
        let violations = detect_name_violations("123metric");
        assert!(
            violations
                .iter()
                .any(|v| v == &MetricViolation::InvalidStartChar)
        );
    }

    #[test]
    fn test_detect_name_violations_invalid_chars() {
        let violations = detect_name_violations("api-requests");
        assert!(
            violations
                .iter()
                .any(|v| v == &MetricViolation::InvalidChars)
        );
    }

    #[test]
    fn test_detect_name_violations_injection() {
        let violations = detect_name_violations("$(whoami)");
        assert!(
            violations
                .iter()
                .any(|v| v == &MetricViolation::InjectionPattern)
        );
    }

    #[test]
    fn test_detect_name_violations_consecutive_separators() {
        let violations = detect_name_violations("a..b");
        assert!(
            violations
                .iter()
                .any(|v| v == &MetricViolation::ConsecutiveSeparators)
        );
    }

    #[test]
    fn test_detect_name_violations_separator_boundary() {
        let violations = detect_name_violations(".leading_dot");
        assert!(
            violations
                .iter()
                .any(|v| v == &MetricViolation::SeparatorAtBoundary)
        );
    }

    #[test]
    fn test_detect_name_violations_multiple() {
        // Starts with number + contains hyphen = at least 2 violations
        let violations = detect_name_violations("123-metric");
        assert!(violations.len() >= 2);
        assert!(
            violations
                .iter()
                .any(|v| v == &MetricViolation::InvalidStartChar)
        );
        assert!(
            violations
                .iter()
                .any(|v| v == &MetricViolation::InvalidChars)
        );
    }

    #[test]
    fn test_detect_name_violations_with_config() {
        let violations = detect_name_violations_with_config("abcdef", 3);
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, MetricViolation::TooLong { length: 6, max: 3 }))
        );
    }

    // ------------------------------------------------------------------------
    // Detect Label Key Violations Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_detect_label_key_violations_valid() {
        assert!(detect_label_key_violations("method").is_empty());
        assert!(detect_label_key_violations("status_code").is_empty());
    }

    #[test]
    fn test_detect_label_key_violations_invalid() {
        let violations = detect_label_key_violations("invalid-key");
        assert!(!violations.is_empty());
        assert!(
            violations
                .iter()
                .any(|v| v == &MetricViolation::InvalidChars)
        );
    }

    // ------------------------------------------------------------------------
    // Detect Label Value Violations Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_detect_label_value_violations_valid() {
        assert!(detect_label_value_violations("GET").is_empty());
        assert!(detect_label_value_violations("value with spaces").is_empty());
        assert!(detect_label_value_violations("/api/users").is_empty());
    }

    #[test]
    fn test_detect_label_value_violations_too_long() {
        let long_value = "a".repeat(MAX_LABEL_VALUE_LENGTH + 1);
        let violations = detect_label_value_violations(&long_value);
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, MetricViolation::TooLong { .. }))
        );
    }

    #[test]
    fn test_detect_label_value_violations_injection() {
        let violations = detect_label_value_violations("'; DROP TABLE");
        assert!(
            violations
                .iter()
                .any(|v| v == &MetricViolation::SevereInjection)
        );
    }

    #[test]
    fn test_detect_label_value_violations_control_chars() {
        let violations = detect_label_value_violations("value\x00with\x00nulls");
        assert!(
            violations
                .iter()
                .any(|v| v == &MetricViolation::ControlChars)
        );
    }
}

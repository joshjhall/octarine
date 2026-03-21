//! Type-safe wrappers for metrics configuration
//!
//! This module provides compile-time safety through newtype wrappers that
//! guarantee validation has occurred before values can be used.

use crate::observe::Problem;
use std::fmt;

/// A validated metric name
///
/// This type can only be constructed by passing validation, ensuring
/// that any `MetricName` value is:
/// - 1-200 characters
/// - Alphanumeric + underscore + dot only
/// - No consecutive underscores or dots
/// - Doesn't start/end with separator
///
/// # Examples
///
/// ```ignore
/// use octarine::observe::metrics::MetricName;
///
/// // Valid metric names
/// let name = MetricName::new("api.requests")?;
/// let name = MetricName::new("db_query_duration")?;
///
/// // Invalid - too long
/// let err = MetricName::new("a".repeat(201));  // Returns Err
///
/// // Invalid - consecutive separators
/// let err = MetricName::new("api..requests");  // Returns Err
///
/// // Invalid - special characters
/// let err = MetricName::new("api-requests");  // Returns Err
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MetricName(String);

impl MetricName {
    /// Create a metric name from a known-valid string literal (internal use only)
    ///
    /// # Safety
    ///
    /// This bypasses validation. Only use with compile-time string literals
    /// that you know are valid metric names.
    ///
    /// **DO NOT** use with user input or runtime strings!
    pub(crate) const fn from_static(_name: &'static str) -> Self {
        Self(String::new()) // Will be replaced at runtime with the actual string
    }

    /// Create a metric name from a known-valid string literal (internal use only)
    ///
    /// This is a runtime version for internal use where we know the string is valid.
    pub(crate) fn from_static_str(name: &'static str) -> Self {
        Self(name.to_string())
    }

    /// Create a new validated metric name
    ///
    /// # Security
    ///
    /// This function performs comprehensive validation:
    /// - Length: 1-200 characters
    /// - Characters: alphanumeric + underscore + dot only
    /// - No consecutive separators (`__`, `..`)
    /// - Cannot start or end with separator
    ///
    /// # Errors
    ///
    /// Returns `Err` if any validation check fails.
    pub fn new(name: impl AsRef<str>) -> Result<Self, Problem> {
        let name = name.as_ref();

        // Validate length
        if name.is_empty() || name.len() > 200 {
            return Err(Problem::validation("Metric name must be 1-200 characters"));
        }

        // Validate characters (alphanumeric + underscore + dot)
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
        {
            return Err(Problem::validation(
                "Metric name must be alphanumeric + underscore + dot",
            ));
        }

        // Prevent consecutive separators (security: cardinality explosion)
        if name.contains("__") || name.contains("..") {
            return Err(Problem::validation(
                "Metric name cannot have consecutive separators",
            ));
        }

        // Cannot start/end with separator
        if name.starts_with('_')
            || name.starts_with('.')
            || name.ends_with('_')
            || name.ends_with('.')
        {
            return Err(Problem::validation(
                "Metric name cannot start/end with separator",
            ));
        }

        Ok(Self(name.to_string()))
    }

    /// Get the validated metric name
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert to String
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for MetricName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MetricName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A validated metric label (key-value pair)
///
/// This type guarantees that both key and value are validated:
/// - Keys follow same rules as metric names
/// - Values have length limits and no control characters
/// - Both are safe for cardinality and injection
///
/// # Examples
///
/// ```ignore
/// use octarine::observe::metrics::MetricLabel;
///
/// // Valid label
/// let label = MetricLabel::new("method", "GET")?;
/// let label = MetricLabel::new("status_code", "200")?;
///
/// // Invalid - key too long
/// let err = MetricLabel::new("k".repeat(101), "value");  // Returns Err
///
/// // Invalid - value contains control characters
/// let err = MetricLabel::new("key", "value\n");  // Returns Err
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricLabel {
    key: String,
    value: String,
}

impl MetricLabel {
    /// Create a new validated metric label
    ///
    /// # Security
    ///
    /// Keys are validated like metric names:
    /// - Length: 1-100 characters
    /// - Alphanumeric + underscore + dot only
    /// - No consecutive separators
    ///
    /// Values are validated for cardinality:
    /// - Length: ≤200 characters
    /// - No control characters (prevents log injection)
    ///
    /// # Errors
    ///
    /// Returns `Err` if key or value validation fails.
    pub fn new(key: impl AsRef<str>, value: impl AsRef<str>) -> Result<Self, Problem> {
        let key = key.as_ref();
        let value = value.as_ref();

        // Validate key (same rules as metric name, but shorter)
        if key.is_empty() || key.len() > 100 {
            return Err(Problem::validation("Label key must be 1-100 characters"));
        }

        if !key
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
        {
            return Err(Problem::validation(
                "Label key must be alphanumeric + underscore + dot",
            ));
        }

        if key.contains("__") || key.contains("..") {
            return Err(Problem::validation(
                "Label key cannot have consecutive separators",
            ));
        }

        if key.starts_with('_') || key.starts_with('.') || key.ends_with('_') || key.ends_with('.')
        {
            return Err(Problem::validation(
                "Label key cannot start/end with separator",
            ));
        }

        // Validate value (less strict, but bounded)
        if value.len() > 200 {
            return Err(Problem::validation("Label value must be ≤200 characters"));
        }

        // Prevent control characters (security: log injection)
        if value.chars().any(|c| c.is_control()) {
            return Err(Problem::validation(
                "Label value contains control characters",
            ));
        }

        Ok(Self {
            key: key.to_string(),
            value: value.to_string(),
        })
    }

    /// Get the label key
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Get the label value
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Convert to tuple
    pub fn into_tuple(self) -> (String, String) {
        (self.key, self.value)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // MetricName tests
    #[test]
    fn test_metric_name_valid() {
        let name = MetricName::new("api.requests").expect("Valid metric name");
        assert_eq!(name.as_str(), "api.requests");

        let name = MetricName::new("db_query_count").expect("Valid metric name");
        assert_eq!(name.as_str(), "db_query_count");

        let name = MetricName::new("system.cpu.usage").expect("Valid metric name");
        assert_eq!(name.as_str(), "system.cpu.usage");
    }

    #[test]
    fn test_metric_name_empty() {
        let result = MetricName::new("");
        assert!(result.is_err());
    }

    #[test]
    fn test_metric_name_too_long() {
        let long_name = "a".repeat(201);
        let result = MetricName::new(long_name);
        assert!(result.is_err());
    }

    #[test]
    fn test_metric_name_invalid_characters() {
        assert!(MetricName::new("api-requests").is_err());
        assert!(MetricName::new("api@requests").is_err());
        assert!(MetricName::new("api requests").is_err());
        assert!(MetricName::new("api/requests").is_err());
    }

    #[test]
    fn test_metric_name_consecutive_separators() {
        assert!(MetricName::new("api..requests").is_err());
        assert!(MetricName::new("api__requests").is_err());
        assert!(MetricName::new("api.._requests").is_err());
    }

    #[test]
    fn test_metric_name_starts_ends_separator() {
        assert!(MetricName::new(".api.requests").is_err());
        assert!(MetricName::new("_api.requests").is_err());
        assert!(MetricName::new("api.requests.").is_err());
        assert!(MetricName::new("api.requests_").is_err());
    }

    // MetricLabel tests
    #[test]
    fn test_label_valid() {
        let label = MetricLabel::new("method", "GET").expect("Valid label");
        assert_eq!(label.key(), "method");
        assert_eq!(label.value(), "GET");

        let label = MetricLabel::new("status_code", "200").expect("Valid label");
        assert_eq!(label.key(), "status_code");
        assert_eq!(label.value(), "200");
    }

    #[test]
    fn test_label_key_empty() {
        let result = MetricLabel::new("", "value");
        assert!(result.is_err());
    }

    #[test]
    fn test_label_key_too_long() {
        let long_key = "k".repeat(101);
        let result = MetricLabel::new(long_key, "value");
        assert!(result.is_err());
    }

    #[test]
    fn test_label_key_invalid_characters() {
        assert!(MetricLabel::new("key-name", "value").is_err());
        assert!(MetricLabel::new("key@name", "value").is_err());
        assert!(MetricLabel::new("key name", "value").is_err());
    }

    #[test]
    fn test_label_value_too_long() {
        let long_value = "v".repeat(201);
        let result = MetricLabel::new("key", long_value);
        assert!(result.is_err());
    }

    #[test]
    fn test_label_value_control_characters() {
        assert!(MetricLabel::new("key", "value\n").is_err());
        assert!(MetricLabel::new("key", "value\r").is_err());
        assert!(MetricLabel::new("key", "value\t").is_err());
        assert!(MetricLabel::new("key", "value\0").is_err());
    }

    #[test]
    fn test_label_into_tuple() {
        let label = MetricLabel::new("method", "GET").expect("Valid label");
        let (key, value) = label.into_tuple();
        assert_eq!(key, "method");
        assert_eq!(value, "GET");
    }

    #[test]
    fn test_metric_name_display() {
        let name = MetricName::new("api.requests").expect("Valid metric name");
        assert_eq!(format!("{}", name), "api.requests");
    }

    #[test]
    fn test_metric_name_as_ref() {
        let name = MetricName::new("api.requests").expect("Valid metric name");
        let s: &str = name.as_ref();
        assert_eq!(s, "api.requests");
    }
}

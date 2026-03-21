//! JSON parsing primitives
//!
//! Pure JSON parsing with no security checks. For safe parsing with
//! threat detection, use `security::formats` or `runtime::formats`.

use serde_json::Value;

use crate::primitives::types::{Problem, Result};

use super::super::types::ParseOptions;

/// Parse JSON string into a serde_json Value
///
/// This is a pure parsing operation with no security checks.
/// For untrusted input, use `runtime::formats::SecureJsonReader`.
pub(crate) fn parse_json(input: &str) -> Result<Value> {
    serde_json::from_str(input).map_err(Problem::from)
}

/// Parse JSON string with options
///
/// Applies size limits before parsing. Depth limits are checked
/// during parsing by the security module.
#[allow(dead_code)]
pub(crate) fn parse_json_with_options(input: &str, options: &ParseOptions) -> Result<Value> {
    // Check size limit
    if input.len() > options.max_size {
        return Err(Problem::Parse(format!(
            "JSON input exceeds maximum size: {} > {} bytes",
            input.len(),
            options.max_size
        )));
    }

    parse_json(input)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_parse_json_object() {
        let result = parse_json(r#"{"key": "value"}"#);
        assert!(result.is_ok());
        let value = result.expect("valid json");
        assert_eq!(value["key"], "value");
    }

    #[test]
    fn test_parse_json_array() {
        let result = parse_json("[1, 2, 3]");
        assert!(result.is_ok());
        let value = result.expect("valid json");
        assert!(value.is_array());
    }

    #[test]
    fn test_parse_json_invalid() {
        let result = parse_json("{invalid}");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_json_with_size_limit() {
        let options = ParseOptions::new().with_max_size(10);
        let result = parse_json_with_options(r#"{"key": "this is too long"}"#, &options);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should fail")
                .to_string()
                .contains("exceeds maximum size")
        );
    }

    #[test]
    fn test_parse_json_within_size_limit() {
        let options = ParseOptions::new().with_max_size(1000);
        let result = parse_json_with_options(r#"{"key": "value"}"#, &options);
        assert!(result.is_ok());
    }
}

//! JSON serialization primitives
//!
//! Pure JSON serialization operations.

use serde::Serialize;

use crate::primitives::types::{Problem, Result};

/// Serialize a value to compact JSON string
pub(crate) fn serialize_json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|e| Problem::Parse(e.to_string()))
}

/// Serialize a value to pretty-printed JSON string
pub(crate) fn serialize_json_pretty<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(|e| Problem::Parse(e.to_string()))
}

/// Escape a string for safe JSON embedding
///
/// Handles special characters that need escaping in JSON strings.
#[must_use]
#[allow(dead_code)]
pub(crate) fn escape_json_string(input: &str) -> String {
    // Use serde_json's built-in escaping by serializing and extracting
    // The result includes quotes, so we strip them
    if let Ok(serialized) = serde_json::to_string(input) {
        // Remove surrounding quotes (length is at least 2 for "")
        let len = serialized.len();
        #[allow(clippy::arithmetic_side_effects)]
        serialized[1..len.saturating_sub(1)].to_string()
    } else {
        // Fallback: manual escaping for edge cases
        input
            .chars()
            .flat_map(|c| match c {
                '"' => vec!['\\', '"'],
                '\\' => vec!['\\', '\\'],
                '\n' => vec!['\\', 'n'],
                '\r' => vec!['\\', 'r'],
                '\t' => vec!['\\', 't'],
                c if c.is_control() => {
                    // Unicode escape for control characters
                    let hex = format!("\\u{:04x}", c as u32);
                    hex.chars().collect()
                }
                c => vec![c],
            })
            .collect()
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
    fn test_serialize_json() {
        let value = serde_json::json!({"key": "value"});
        let result = serialize_json(&value);
        assert!(result.is_ok());
        assert_eq!(result.expect("valid"), r#"{"key":"value"}"#);
    }

    #[test]
    fn test_serialize_json_pretty() {
        let value = serde_json::json!({"key": "value"});
        let result = serialize_json_pretty(&value);
        assert!(result.is_ok());
        let pretty = result.expect("valid");
        assert!(pretty.contains('\n'));
        assert!(pretty.contains("  ")); // Indentation
    }

    #[test]
    fn test_escape_json_string() {
        assert_eq!(escape_json_string("hello"), "hello");
        assert_eq!(escape_json_string("hello \"world\""), r#"hello \"world\""#);
        assert_eq!(escape_json_string("line1\nline2"), r"line1\nline2");
        assert_eq!(escape_json_string("tab\there"), r"tab\there");
        assert_eq!(escape_json_string(r"back\slash"), r"back\\slash");
    }

    #[test]
    fn test_escape_json_string_control_chars() {
        let input = "hello\x00world";
        let escaped = escape_json_string(input);
        assert!(escaped.contains("\\u0000"));
    }
}

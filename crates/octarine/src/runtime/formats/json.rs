//! Secure JSON reader
//!
//! Validates JSON against security policies before parsing.

use std::path::Path;

use serde_json::Value as JsonValue;

use crate::observe::{debug, info};
use crate::primitives::data::formats::FormatBuilder;
use crate::primitives::security::formats::{FormatSecurityBuilder, JsonPolicy};
use crate::primitives::types::Result;

/// Secure JSON reader with policy enforcement
///
/// Validates JSON input against security policies (depth, size limits)
/// before parsing. Use this for untrusted input.
///
/// # Example
///
/// ```ignore
/// use octarine::runtime::formats::SecureJsonReader;
///
/// let reader = SecureJsonReader::new();
/// let value = reader.parse(r#"{"key": "value"}"#)?;
///
/// // With custom policy
/// use octarine::security::formats::JsonPolicy;
/// let reader = SecureJsonReader::with_policy(JsonPolicy { max_depth: 10, max_size: 1024 });
/// ```
#[derive(Debug, Clone)]
pub struct SecureJsonReader {
    policy: JsonPolicy,
    format: FormatBuilder,
    security: FormatSecurityBuilder,
}

impl Default for SecureJsonReader {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureJsonReader {
    /// Create a new secure JSON reader with default strict policy
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: JsonPolicy::strict(),
            format: FormatBuilder::new(),
            security: FormatSecurityBuilder::new(),
        }
    }

    /// Create a secure JSON reader with a custom policy
    #[must_use]
    pub fn with_policy(policy: JsonPolicy) -> Self {
        Self {
            policy,
            format: FormatBuilder::new(),
            security: FormatSecurityBuilder::new(),
        }
    }

    /// Parse JSON string securely
    ///
    /// Validates against the security policy before parsing.
    pub fn parse(&self, input: &str) -> Result<JsonValue> {
        debug("runtime.format", "Securely parsing JSON");

        // Validate security
        self.security.validate_json(input, &self.policy)?;

        // Parse
        let result = self.format.parse_json(input)?;

        info("runtime.format", "JSON parsed successfully");
        Ok(result)
    }

    /// Read and parse a JSON file securely
    pub fn read_file(&self, path: impl AsRef<Path>) -> Result<JsonValue> {
        let path = path.as_ref();
        debug(
            "runtime.format",
            format!("Securely reading JSON file: {}", path.display()),
        );

        // Read file
        let content = std::fs::read_to_string(path)?;

        // Validate and parse
        self.parse(&content)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_secure_json_reader_parse() {
        let reader = SecureJsonReader::new();
        let result = reader.parse(r#"{"key": "value"}"#);
        assert!(result.is_ok());
    }

    #[test]
    fn test_secure_json_reader_rejects_deep() {
        let reader = SecureJsonReader::with_policy(JsonPolicy {
            max_depth: 2,
            max_size: 10000,
        });

        let deep = r#"{"a": {"b": {"c": "too deep"}}}"#;
        let result = reader.parse(deep);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_json_reader_read_file() {
        let reader = SecureJsonReader::new();
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.json");

        std::fs::write(&path, r#"{"key": "value"}"#).expect("write file");

        let result = reader.read_file(&path);
        assert!(result.is_ok());
    }
}

//! Secure YAML reader
//!
//! Validates YAML against unsafe tags and anchor bombs before parsing.

use std::path::Path;

use serde_yaml::Value as YamlValue;

use crate::observe::{debug, info};
use crate::primitives::data::formats::FormatBuilder;
use crate::primitives::security::formats::{FormatSecurityBuilder, YamlPolicy};
use crate::primitives::types::Result;

/// Secure YAML reader with code execution prevention
///
/// Validates YAML input against unsafe tags (Python, Ruby, PHP object
/// instantiation) and anchor bombs before parsing. Use this for untrusted input.
///
/// # Example
///
/// ```ignore
/// use octarine::runtime::formats::SecureYamlReader;
///
/// let reader = SecureYamlReader::new();
/// let value = reader.parse("key: value")?;
///
/// // With custom policy
/// use octarine::security::formats::YamlPolicy;
/// let reader = SecureYamlReader::with_policy(YamlPolicy::permissive());
/// ```
#[derive(Debug, Clone)]
pub struct SecureYamlReader {
    policy: YamlPolicy,
    format: FormatBuilder,
    security: FormatSecurityBuilder,
}

impl Default for SecureYamlReader {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureYamlReader {
    /// Create a new secure YAML reader with default strict policy
    ///
    /// By default, unsafe tags and excessive aliases are blocked.
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: YamlPolicy::strict(),
            format: FormatBuilder::new(),
            security: FormatSecurityBuilder::new(),
        }
    }

    /// Create a secure YAML reader with a custom policy
    #[must_use]
    pub fn with_policy(policy: YamlPolicy) -> Self {
        Self {
            policy,
            format: FormatBuilder::new(),
            security: FormatSecurityBuilder::new(),
        }
    }

    /// Parse YAML string securely
    ///
    /// Validates against unsafe tags and the security policy before parsing.
    pub fn parse(&self, input: &str) -> Result<YamlValue> {
        debug("runtime.format", "Securely parsing YAML");

        // Validate security (unsafe tag prevention)
        self.security.validate_yaml(input, &self.policy)?;

        // Parse
        let result = self.format.parse_yaml(input)?;

        info("runtime.format", "YAML parsed successfully");
        Ok(result)
    }

    /// Read and parse a YAML file securely
    pub fn read_file(&self, path: impl AsRef<Path>) -> Result<YamlValue> {
        let path = path.as_ref();
        debug(
            "runtime.format",
            format!("Securely reading YAML file: {}", path.display()),
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
    fn test_secure_yaml_reader_parse() {
        let reader = SecureYamlReader::new();
        let result = reader.parse("key: value");
        assert!(result.is_ok());
    }

    #[test]
    fn test_secure_yaml_reader_blocks_python_exec() {
        let reader = SecureYamlReader::new();

        let unsafe_yaml = "!!python/exec 'import os'";
        let result = reader.parse(unsafe_yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_yaml_reader_blocks_ruby_object() {
        let reader = SecureYamlReader::new();

        let unsafe_yaml = "!!ruby/object:Gem::Requirement";
        let result = reader.parse(unsafe_yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_yaml_reader_allows_normal_yaml() {
        // Use permissive policy to allow anchors/aliases in normal YAML
        let reader = SecureYamlReader::with_policy(YamlPolicy::permissive());

        let normal = r"
defaults: &defaults
  timeout: 30

production:
  <<: *defaults
  debug: false
";
        let result = reader.parse(normal);
        assert!(result.is_ok());
    }

    #[test]
    fn test_secure_yaml_reader_read_file() {
        let reader = SecureYamlReader::new();
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.yaml");

        std::fs::write(&path, "key: value\nlist:\n  - item1\n  - item2").expect("write file");

        let result = reader.read_file(&path);
        assert!(result.is_ok());
    }
}

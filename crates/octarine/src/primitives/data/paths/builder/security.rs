//! Security detection and validation methods
//!
//! Methods for detecting security threats and validating paths.

use super::super::common;
use super::super::filetype;
use super::super::types::{PathDetectionResult, PathValidationResult, SecurityThreat};
use super::core::PathBuilder;

impl PathBuilder {
    /// Detect all security threats in path
    ///
    /// Returns a list of all detected security threats.
    #[must_use]
    pub fn detect_threats(&self, path: &str) -> Vec<SecurityThreat> {
        let mut threats = Vec::new();

        // Check for traversal
        if common::is_parent_references_present(path) {
            threats.push(SecurityThreat::Traversal);
        }

        // Check for encoded traversal
        if common::is_encoded_traversal_present(path) {
            threats.push(SecurityThreat::EncodedTraversal);
        }

        // Check for command injection
        if common::is_command_substitution_present(path) {
            threats.push(SecurityThreat::CommandInjection);
        }

        // Check for variable expansion
        if common::is_variable_expansion_present(path) {
            threats.push(SecurityThreat::VariableExpansion);
        }

        // Check for shell metacharacters
        if common::is_shell_metacharacters_present(path) {
            threats.push(SecurityThreat::ShellMetacharacters);
        }

        // Check for null bytes
        if common::is_null_bytes_present(path) {
            threats.push(SecurityThreat::NullByte);
        }

        // Check for dangerous characters (control chars)
        if common::is_dangerous_characters_present(path) && !common::is_null_bytes_present(path) {
            // Only add if not already captured by null bytes
            threats.push(SecurityThreat::ControlCharacters);
        }

        // Check for encoding attacks
        if common::is_encoding_attack_present(path) {
            threats.push(SecurityThreat::DoubleEncoding);
        }

        threats
    }

    /// Comprehensive path detection (all characteristics)
    ///
    /// Returns a full analysis of the path including type, platform,
    /// and security threats.
    #[must_use]
    pub fn detect(&self, path: &str) -> PathDetectionResult {
        let path_type = self.detect_path_type(path);
        let threats = self.detect_threats(path);
        let extension = common::find_extension(path).map(ToString::to_string);

        PathDetectionResult {
            path_type,
            platform: path_type.platform(),
            file_category: Some(filetype::detect_file_category(path)),
            is_absolute: path_type.is_absolute(),
            is_hidden: self.is_hidden(path),
            has_extension: extension.is_some(),
            extension,
            threats,
        }
    }

    /// Check for directory traversal
    #[must_use]
    pub fn is_traversal_present(&self, path: &str) -> bool {
        common::is_any_traversal_present(path)
    }

    /// Check for command injection patterns
    #[must_use]
    pub fn is_command_injection_present(&self, path: &str) -> bool {
        common::is_any_injection_present(path)
    }

    /// Check for any security threat
    #[must_use]
    pub fn is_threat_present(&self, path: &str) -> bool {
        !self.detect_threats(path).is_empty()
    }

    /// Check if path is safe (no security threats)
    ///
    /// Returns true if the path contains no detected security threats.
    #[must_use]
    pub fn is_safe(&self, path: &str) -> bool {
        !common::is_any_traversal_present(path)
            && !common::is_any_injection_present(path)
            && !common::is_dangerous_characters_present(path)
            && !common::is_encoding_attack_present(path)
    }

    /// Validate path and return detailed result
    ///
    /// Returns a validation result with errors and warnings.
    #[must_use]
    pub fn validate(&self, path: &str) -> PathValidationResult {
        let mut result = PathValidationResult::valid();

        if path.is_empty() {
            return PathValidationResult::invalid("Path is empty");
        }

        // Check for null bytes
        if common::is_null_bytes_present(path) {
            result = result.with_error("Path contains null bytes");
        }

        // Check for traversal
        if common::is_any_traversal_present(path) {
            result = result.with_error("Path contains traversal patterns");
        }

        // Check for injection
        if common::is_any_injection_present(path) {
            result = result.with_error("Path contains injection patterns");
        }

        // Check for encoding attacks
        if common::is_encoding_attack_present(path) {
            result = result.with_error("Path contains encoding attack patterns");
        }

        // Warnings (not errors)
        if common::is_mixed_separators_present(path) {
            result = result.with_warning("Path has mixed separators");
        }

        result
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::super::super::types::PathType;
    use super::*;

    #[test]
    fn test_security_detection() {
        let builder = PathBuilder::new();

        // Traversal
        assert!(builder.is_traversal_present("../../../etc/passwd"));
        assert!(builder.is_traversal_present("/etc/passwd")); // absolute is traversal
        assert!(!builder.is_traversal_present("safe/path/file.txt"));

        // Command injection
        assert!(builder.is_command_injection_present("$(whoami)"));
        assert!(builder.is_command_injection_present("${HOME}"));
        assert!(!builder.is_command_injection_present("safe/path"));
    }

    #[test]
    fn test_detect_threats() {
        let builder = PathBuilder::new();

        let threats = builder.detect_threats("../../../etc/passwd");
        assert!(threats.contains(&SecurityThreat::Traversal));

        let threats = builder.detect_threats("file$(whoami).txt");
        assert!(threats.contains(&SecurityThreat::CommandInjection));

        let threats = builder.detect_threats("safe/path/file.txt");
        assert!(threats.is_empty());
    }

    #[test]
    fn test_is_safe() {
        let builder = PathBuilder::new();

        assert!(builder.is_safe("path/to/file.txt"));
        assert!(builder.is_safe("relative/path"));

        assert!(!builder.is_safe("../../../etc/passwd"));
        assert!(!builder.is_safe("$(whoami)"));
        assert!(!builder.is_safe("file\0.txt"));
    }

    #[test]
    fn test_validate() {
        let builder = PathBuilder::new();

        let result = builder.validate("safe/path/file.txt");
        assert!(result.is_valid);

        let result = builder.validate("../../../etc/passwd");
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());

        let result = builder.validate("");
        assert!(!result.is_valid);
    }

    #[test]
    fn test_detect_comprehensive() {
        let builder = PathBuilder::new();

        let result = builder.detect("/etc/passwd");
        assert_eq!(result.path_type, PathType::UnixAbsolute);
        assert!(result.is_absolute);
        assert!(!result.is_hidden);

        let result = builder.detect(".hidden");
        assert!(result.is_hidden);
    }

    #[test]
    fn test_is_threat_present() {
        let builder = PathBuilder::new();

        assert!(builder.is_threat_present("../../../etc/passwd"));
        assert!(builder.is_threat_present("$(whoami)"));
        assert!(!builder.is_threat_present("safe/path"));
    }
}

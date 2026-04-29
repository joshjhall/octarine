//! Security threat detection delegators for [`PathBuilder`].
//!
//! Methods that delegate to [`SecurityBuilder`] (defined in
//! `crate::security::paths`). The metric-emitting `detect()` method stays
//! in `builder/mod.rs` to keep `define_metrics!`-generated names in scope.

use super::super::PathBuilder;
use crate::security::paths::{SecurityBuilder, SecurityThreat};

impl PathBuilder {
    /// Detect all security threats
    #[must_use]
    pub fn detect_threats(&self, path: &str) -> Vec<SecurityThreat> {
        SecurityBuilder::new().detect_threats(path)
    }

    /// Check if path has any security threat
    #[must_use]
    pub fn is_threat_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_threat_present(path)
    }

    /// Check if path has traversal
    #[must_use]
    pub fn is_traversal_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_traversal_present(path)
    }

    /// Check if path has encoded traversal
    #[must_use]
    pub fn is_encoded_traversal_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_encoded_traversal_present(path)
    }

    /// Check if path has command injection
    #[must_use]
    pub fn is_command_injection_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_command_injection_present(path)
    }

    /// Check if path has variable expansion
    #[must_use]
    pub fn is_variable_expansion_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_variable_expansion_present(path)
    }

    /// Check if path has shell metacharacters
    #[must_use]
    pub fn is_shell_metacharacters_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_shell_metacharacters_present(path)
    }

    /// Check if path has null bytes
    #[must_use]
    pub fn is_null_bytes_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_null_bytes_present(path)
    }

    /// Check if path has control characters
    #[must_use]
    pub fn is_control_characters_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_control_characters_present(path)
    }

    /// Check if path has double encoding
    #[must_use]
    pub fn is_double_encoding_present(&self, path: &str) -> bool {
        SecurityBuilder::new().is_double_encoding_present(path)
    }
}

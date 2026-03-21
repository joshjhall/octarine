//! Format security builder with observe instrumentation
//!
//! Wraps the primitives FormatSecurityBuilder with audit trails.

use crate::observe::{debug, warn};
use crate::primitives::data::formats::FormatType;
use crate::primitives::security::formats::{
    FormatSecurityBuilder as PrimBuilder, FormatThreat, JsonPolicy, XmlPolicy, YamlPolicy,
};
use crate::primitives::types::Result;

/// Builder for format security detection and validation with observability
///
/// This is the Layer 3 wrapper that adds observe instrumentation
/// to the primitives FormatSecurityBuilder.
#[derive(Debug, Clone, Copy, Default)]
pub struct FormatSecurityBuilder {
    inner: PrimBuilder,
}

impl FormatSecurityBuilder {
    /// Create a new format security builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PrimBuilder::new(),
        }
    }

    // ========================================================================
    // XML Security
    // ========================================================================

    /// Check if XML input contains XXE patterns
    ///
    /// Returns true if any XXE-related patterns are detected.
    #[must_use]
    pub fn is_xxe_present(&self, input: &str) -> bool {
        let result = self.inner.is_xxe_present(input);
        if result {
            warn("security.format", "XXE pattern detected in XML input");
        } else {
            debug("security.format", "No XXE patterns found");
        }
        result
    }

    /// Check if XML input contains a DOCTYPE declaration
    #[must_use]
    pub fn is_dtd_present(&self, input: &str) -> bool {
        let result = self.inner.is_dtd_present(input);
        if result {
            debug("security.format", "DTD declaration found in XML");
        }
        result
    }

    /// Check if XML input contains external entity declarations
    #[must_use]
    pub fn is_external_entity_present(&self, input: &str) -> bool {
        let result = self.inner.is_external_entity_present(input);
        if result {
            warn("security.format", "External entity declaration detected");
        }
        result
    }

    /// Detect all XML threats in input
    #[must_use]
    pub fn detect_xml_threats(&self, input: &str) -> Vec<FormatThreat> {
        let threats = self.inner.detect_xml_threats(input);
        if !threats.is_empty() {
            warn(
                "security.format",
                format!("Detected {} XML threat(s)", threats.len()),
            );
        }
        threats
    }

    /// Validate XML input against policy
    pub fn validate_xml(&self, input: &str, policy: &XmlPolicy) -> Result<()> {
        debug("security.format", "Validating XML against policy");
        let result = self.inner.validate_xml(input, policy);
        if result.is_err() {
            warn("security.format", "XML validation failed");
        }
        result
    }

    // ========================================================================
    // JSON Security
    // ========================================================================

    /// Check if JSON input exceeds depth limit
    #[must_use]
    pub fn is_json_depth_exceeded(&self, input: &str, max_depth: usize) -> bool {
        let result = self.inner.is_json_depth_exceeded(input, max_depth);
        if result {
            warn(
                "security.format",
                format!("JSON exceeds depth limit of {}", max_depth),
            );
        }
        result
    }

    /// Check if JSON input exceeds size limit
    #[must_use]
    pub fn is_json_size_exceeded(&self, input: &str, max_size: usize) -> bool {
        let result = self.inner.is_json_size_exceeded(input, max_size);
        if result {
            warn(
                "security.format",
                format!("JSON exceeds size limit of {} bytes", max_size),
            );
        }
        result
    }

    /// Detect all JSON threats according to policy
    #[must_use]
    pub fn detect_json_threats(&self, input: &str, policy: &JsonPolicy) -> Vec<FormatThreat> {
        let threats = self.inner.detect_json_threats(input, policy);
        if !threats.is_empty() {
            warn(
                "security.format",
                format!("Detected {} JSON threat(s)", threats.len()),
            );
        }
        threats
    }

    /// Validate JSON input against policy
    pub fn validate_json(&self, input: &str, policy: &JsonPolicy) -> Result<()> {
        debug("security.format", "Validating JSON against policy");
        let result = self.inner.validate_json(input, policy);
        if result.is_err() {
            warn("security.format", "JSON validation failed");
        }
        result
    }

    // ========================================================================
    // YAML Security
    // ========================================================================

    /// Check if YAML input contains unsafe patterns
    #[must_use]
    pub fn is_yaml_unsafe(&self, input: &str) -> bool {
        let result = self.inner.is_yaml_unsafe(input);
        if result {
            warn("security.format", "Unsafe pattern detected in YAML input");
        } else {
            debug("security.format", "No unsafe patterns found in YAML");
        }
        result
    }

    /// Check if YAML input contains unsafe tags
    #[must_use]
    pub fn is_unsafe_yaml_tag_present(&self, input: &str) -> bool {
        let result = self.inner.is_unsafe_yaml_tag_present(input);
        if result {
            warn(
                "security.format",
                "Unsafe YAML tag detected (code execution risk)",
            );
        }
        result
    }

    /// Check if YAML input shows anchor bomb patterns
    #[must_use]
    pub fn is_yaml_anchor_bomb_present(&self, input: &str) -> bool {
        let result = self.inner.is_yaml_anchor_bomb_present(input);
        if result {
            warn(
                "security.format",
                "YAML anchor bomb pattern detected (DoS risk)",
            );
        }
        result
    }

    /// Detect all YAML threats according to policy
    #[must_use]
    pub fn detect_yaml_threats(&self, input: &str, policy: &YamlPolicy) -> Vec<FormatThreat> {
        let threats = self.inner.detect_yaml_threats(input, policy);
        if !threats.is_empty() {
            warn(
                "security.format",
                format!("Detected {} YAML threat(s)", threats.len()),
            );
        }
        threats
    }

    /// Validate YAML input against policy
    pub fn validate_yaml(&self, input: &str, policy: &YamlPolicy) -> Result<()> {
        debug("security.format", "Validating YAML against policy");
        let result = self.inner.validate_yaml(input, policy);
        if result.is_err() {
            warn("security.format", "YAML validation failed");
        }
        result
    }

    // ========================================================================
    // Generic Operations
    // ========================================================================

    /// Detect threats for a specific format type
    #[must_use]
    pub fn detect_threats(&self, input: &str, format: FormatType) -> Vec<FormatThreat> {
        debug("security.format", "Detecting format threats");
        self.inner.detect_threats(input, format)
    }

    /// Check if input contains any threats for the specified format
    #[must_use]
    pub fn is_dangerous(&self, input: &str, format: FormatType) -> bool {
        let result = self.inner.is_dangerous(input, format);
        if result {
            warn("security.format", "Dangerous content detected");
        }
        result
    }

    /// Validate input with default strict policies
    pub fn validate_strict(&self, input: &str, format: FormatType) -> Result<()> {
        debug("security.format", "Validating with strict policy");
        self.inner.validate_strict(input, format)
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
    fn test_builder_xxe_detection() {
        let builder = FormatSecurityBuilder::new();

        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
        assert!(builder.is_xxe_present(xxe));
        assert!(!builder.is_xxe_present("<root/>"));
    }

    #[test]
    fn test_builder_yaml_unsafe() {
        let builder = FormatSecurityBuilder::new();

        assert!(builder.is_yaml_unsafe("!!python/exec 'import os'"));
        assert!(!builder.is_yaml_unsafe("key: value"));
    }

    #[test]
    fn test_builder_json_depth() {
        let builder = FormatSecurityBuilder::new();

        assert!(builder.is_json_depth_exceeded(r#"{"a":{"b":{"c":1}}}"#, 2));
        assert!(!builder.is_json_depth_exceeded(r#"{"a":{"b":1}}"#, 2));
    }
}

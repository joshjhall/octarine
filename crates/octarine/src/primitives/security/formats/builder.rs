//! Format security builder - unified API for threat detection
//!
//! Provides a consistent interface for detecting and validating
//! security threats in structured data formats.

use crate::primitives::data::formats::FormatType;
use crate::primitives::types::{Problem, Result};

use super::json;
use super::types::{FormatThreat, JsonPolicy, XmlPolicy, YamlPolicy};
use super::xml;
use super::yaml;

/// Builder for format security detection and validation
///
/// This builder provides a unified API for security checks across
/// JSON, XML, and YAML formats. It performs pure operations with
/// no logging or side effects.
///
/// For operations with observability, use `security::formats::FormatSecurityBuilder`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FormatSecurityBuilder;

impl FormatSecurityBuilder {
    /// Create a new format security builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // ========================================================================
    // XML Security
    // ========================================================================

    /// Check if XML input contains XXE patterns
    #[must_use]
    pub fn is_xxe_present(&self, input: &str) -> bool {
        xml::is_xxe_present(input)
    }

    /// Check if XML input contains a DOCTYPE declaration
    #[must_use]
    pub fn is_dtd_present(&self, input: &str) -> bool {
        xml::has_dtd_declaration(input)
    }

    /// Check if XML input contains external entity declarations
    #[must_use]
    pub fn is_external_entity_present(&self, input: &str) -> bool {
        xml::has_external_entity(input)
    }

    /// Detect all XML threats in input
    #[must_use]
    pub fn detect_xml_threats(&self, input: &str) -> Vec<FormatThreat> {
        xml::detect_xml_threats(input)
    }

    /// Validate XML input against policy
    pub fn validate_xml(&self, input: &str, policy: &XmlPolicy) -> Result<()> {
        xml::validate_xml_safe(input, policy)
    }

    // ========================================================================
    // JSON Security
    // ========================================================================

    /// Check if JSON input exceeds depth limit
    #[must_use]
    pub fn is_json_depth_exceeded(&self, input: &str, max_depth: usize) -> bool {
        json::exceeds_depth(input, max_depth)
    }

    /// Check if JSON input exceeds size limit
    #[must_use]
    pub fn is_json_size_exceeded(&self, input: &str, max_size: usize) -> bool {
        json::exceeds_size(input, max_size)
    }

    /// Detect all JSON threats according to policy
    #[must_use]
    pub fn detect_json_threats(&self, input: &str, policy: &JsonPolicy) -> Vec<FormatThreat> {
        json::detect_json_threats(input, policy)
    }

    /// Validate JSON input against policy
    pub fn validate_json(&self, input: &str, policy: &JsonPolicy) -> Result<()> {
        json::validate_json_safe(input, policy)
    }

    // ========================================================================
    // YAML Security
    // ========================================================================

    /// Check if YAML input contains unsafe patterns
    #[must_use]
    pub fn is_yaml_unsafe(&self, input: &str) -> bool {
        yaml::is_yaml_unsafe(input)
    }

    /// Check if YAML input contains unsafe tags
    #[must_use]
    pub fn is_unsafe_yaml_tag_present(&self, input: &str) -> bool {
        yaml::has_unsafe_tag(input)
    }

    /// Check if YAML input shows anchor bomb patterns
    #[must_use]
    pub fn is_yaml_anchor_bomb_present(&self, input: &str) -> bool {
        yaml::has_anchor_bomb(input)
    }

    /// Detect all YAML threats according to policy
    #[must_use]
    pub fn detect_yaml_threats(&self, input: &str, policy: &YamlPolicy) -> Vec<FormatThreat> {
        yaml::detect_yaml_threats(input, policy)
    }

    /// Validate YAML input against policy
    pub fn validate_yaml(&self, input: &str, policy: &YamlPolicy) -> Result<()> {
        yaml::validate_yaml_safe(input, policy)
    }

    // ========================================================================
    // Generic Operations
    // ========================================================================

    /// Detect threats for a specific format type
    #[must_use]
    pub fn detect_threats(&self, input: &str, format: FormatType) -> Vec<FormatThreat> {
        match format {
            FormatType::Json => self.detect_json_threats(input, &JsonPolicy::default()),
            FormatType::Xml => self.detect_xml_threats(input),
            FormatType::Yaml => self.detect_yaml_threats(input, &YamlPolicy::default()),
        }
    }

    /// Check if input contains any threats for the specified format
    #[must_use]
    pub fn is_dangerous(&self, input: &str, format: FormatType) -> bool {
        !self.detect_threats(input, format).is_empty()
    }

    /// Validate input with default strict policies
    pub fn validate_strict(&self, input: &str, format: FormatType) -> Result<()> {
        match format {
            FormatType::Json => self.validate_json(input, &JsonPolicy::strict()),
            FormatType::Xml => self.validate_xml(input, &XmlPolicy::strict()),
            FormatType::Yaml => self.validate_yaml(input, &YamlPolicy::strict()),
        }
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
    fn test_builder_xml_xxe() {
        let builder = FormatSecurityBuilder::new();

        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
        assert!(builder.is_xxe_present(xxe));
        assert!(!builder.is_xxe_present("<root/>"));
    }

    #[test]
    fn test_builder_xml_validation() {
        let builder = FormatSecurityBuilder::new();
        let policy = XmlPolicy::strict();

        assert!(builder.validate_xml("<root/>", &policy).is_ok());
        assert!(builder.validate_xml("<!DOCTYPE html>", &policy).is_err());
    }

    #[test]
    fn test_builder_json_depth() {
        let builder = FormatSecurityBuilder::new();

        assert!(builder.is_json_depth_exceeded(r#"{"a":{"b":{"c":1}}}"#, 2));
        assert!(!builder.is_json_depth_exceeded(r#"{"a":{"b":1}}"#, 2));
    }

    #[test]
    fn test_builder_json_validation() {
        let builder = FormatSecurityBuilder::new();
        let policy = JsonPolicy::strict();

        assert!(builder.validate_json(r#"{"key":"value"}"#, &policy).is_ok());
    }

    #[test]
    fn test_builder_yaml_unsafe() {
        let builder = FormatSecurityBuilder::new();

        assert!(builder.is_yaml_unsafe("!!python/exec 'import os'"));
        assert!(!builder.is_yaml_unsafe("key: value"));
    }

    #[test]
    fn test_builder_yaml_validation() {
        let builder = FormatSecurityBuilder::new();
        let policy = YamlPolicy::strict();

        assert!(builder.validate_yaml("key: value", &policy).is_ok());
        assert!(builder.validate_yaml("!!python/object", &policy).is_err());
    }

    #[test]
    fn test_builder_generic_detect() {
        let builder = FormatSecurityBuilder::new();

        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
        let threats = builder.detect_threats(xxe, FormatType::Xml);
        assert!(!threats.is_empty());
    }

    #[test]
    fn test_builder_is_dangerous() {
        let builder = FormatSecurityBuilder::new();

        assert!(builder.is_dangerous("!!python/exec", FormatType::Yaml));
        assert!(!builder.is_dangerous("key: value", FormatType::Yaml));
    }

    #[test]
    fn test_builder_validate_strict() {
        let builder = FormatSecurityBuilder::new();

        assert!(builder.validate_strict("<root/>", FormatType::Xml).is_ok());
        assert!(
            builder
                .validate_strict("key: value", FormatType::Yaml)
                .is_ok()
        );
        assert!(
            builder
                .validate_strict(r#"{"key":"value"}"#, FormatType::Json)
                .is_ok()
        );
    }
}

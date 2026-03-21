//! Format security shortcut functions
//!
//! Convenience functions for common format security operations.

use crate::primitives::data::formats::FormatType;
use crate::primitives::types::Result;

use super::{FormatSecurityBuilder, FormatThreat, JsonPolicy, XmlPolicy, YamlPolicy};

// ============================================================================
// XML Security Shortcuts
// ============================================================================

/// Check if XML input contains XXE patterns
///
/// Returns true if any XXE-related patterns are detected.
///
/// # Example
///
/// ```ignore
/// use octarine::security::formats::is_xxe_present;
///
/// if is_xxe_present(xml_input) {
///     // Block dangerous XML
/// }
/// ```
#[must_use]
pub fn is_xxe_present(input: &str) -> bool {
    FormatSecurityBuilder::new().is_xxe_present(input)
}

/// Check if XML input contains a DOCTYPE declaration
#[must_use]
pub fn is_dtd_present(input: &str) -> bool {
    FormatSecurityBuilder::new().is_dtd_present(input)
}

/// Validate XML input is safe (no XXE, no DTD by default)
pub fn validate_xml_safe(input: &str) -> Result<()> {
    FormatSecurityBuilder::new().validate_xml(input, &XmlPolicy::strict())
}

/// Detect all XML threats in input
#[must_use]
pub fn detect_xml_threats(input: &str) -> Vec<FormatThreat> {
    FormatSecurityBuilder::new().detect_xml_threats(input)
}

// ============================================================================
// JSON Security Shortcuts
// ============================================================================

/// Check if JSON input exceeds depth limit
#[must_use]
pub fn is_json_depth_exceeded(input: &str, max_depth: usize) -> bool {
    FormatSecurityBuilder::new().is_json_depth_exceeded(input, max_depth)
}

/// Check if JSON input exceeds size limit
#[must_use]
pub fn is_json_size_exceeded(input: &str, max_size: usize) -> bool {
    FormatSecurityBuilder::new().is_json_size_exceeded(input, max_size)
}

/// Validate JSON input is safe (depth and size limits)
pub fn validate_json_safe(input: &str) -> Result<()> {
    FormatSecurityBuilder::new().validate_json(input, &JsonPolicy::strict())
}

/// Detect all JSON threats according to policy
#[must_use]
pub fn detect_json_threats(input: &str, policy: &JsonPolicy) -> Vec<FormatThreat> {
    FormatSecurityBuilder::new().detect_json_threats(input, policy)
}

// ============================================================================
// YAML Security Shortcuts
// ============================================================================

/// Check if YAML input contains unsafe patterns
///
/// Detects unsafe tags (code execution) and anchor bombs (DoS).
///
/// # Example
///
/// ```ignore
/// use octarine::security::formats::is_yaml_unsafe;
///
/// if is_yaml_unsafe(yaml_input) {
///     // Block code execution
/// }
/// ```
#[must_use]
pub fn is_yaml_unsafe(input: &str) -> bool {
    FormatSecurityBuilder::new().is_yaml_unsafe(input)
}

/// Check if YAML input contains unsafe tags
#[must_use]
pub fn is_unsafe_yaml_tag_present(input: &str) -> bool {
    FormatSecurityBuilder::new().is_unsafe_yaml_tag_present(input)
}

/// Validate YAML input is safe (no unsafe tags, limited aliases)
pub fn validate_yaml_safe(input: &str) -> Result<()> {
    FormatSecurityBuilder::new().validate_yaml(input, &YamlPolicy::strict())
}

/// Detect all YAML threats according to policy
#[must_use]
pub fn detect_yaml_threats(input: &str, policy: &YamlPolicy) -> Vec<FormatThreat> {
    FormatSecurityBuilder::new().detect_yaml_threats(input, policy)
}

// ============================================================================
// Generic Security Shortcuts
// ============================================================================

/// Detect threats for a specific format type
#[must_use]
pub fn detect_format_threats(input: &str, format: FormatType) -> Vec<FormatThreat> {
    FormatSecurityBuilder::new().detect_threats(input, format)
}

/// Check if input contains any threats for the specified format
#[must_use]
pub fn is_format_dangerous(input: &str, format: FormatType) -> bool {
    FormatSecurityBuilder::new().is_dangerous(input, format)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_xxe_shortcut() {
        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
        assert!(is_xxe_present(xxe));
        assert!(!is_xxe_present("<root/>"));
    }

    #[test]
    fn test_yaml_unsafe_shortcut() {
        assert!(is_yaml_unsafe("!!python/exec 'import os'"));
        assert!(!is_yaml_unsafe("key: value"));
    }

    #[test]
    fn test_validate_xml_safe_shortcut() {
        assert!(validate_xml_safe("<root/>").is_ok());
        assert!(validate_xml_safe("<!DOCTYPE html>").is_err());
    }

    #[test]
    fn test_validate_yaml_safe_shortcut() {
        assert!(validate_yaml_safe("key: value").is_ok());
        assert!(validate_yaml_safe("!!python/object").is_err());
    }
}

//! Format shortcut functions
//!
//! Convenience functions for common format operations.

use serde::Serialize;
use serde_json::Value as JsonValue;

use crate::primitives::data::formats::{FormatType, XmlDocument};
use crate::primitives::types::Result;

use super::FormatBuilder;

// ============================================================================
// JSON Shortcuts
// ============================================================================

/// Parse JSON content
///
/// # Example
///
/// ```ignore
/// use octarine::data::formats::parse_json;
///
/// let value = parse_json(r#"{"key": "value"}"#)?;
/// ```
pub fn parse_json(input: &str) -> Result<JsonValue> {
    FormatBuilder::new().parse_json(input)
}

/// Serialize value to JSON
pub fn serialize_json<T: Serialize>(value: &T) -> Result<String> {
    FormatBuilder::new().serialize_json(value)
}

/// Serialize value to pretty JSON
pub fn serialize_json_pretty<T: Serialize>(value: &T) -> Result<String> {
    FormatBuilder::new().serialize_json_pretty(value)
}

// ============================================================================
// XML Shortcuts
// ============================================================================

/// Parse XML content
///
/// # Example
///
/// ```ignore
/// use octarine::data::formats::parse_xml;
///
/// let doc = parse_xml("<root><child/></root>")?;
/// ```
pub fn parse_xml(input: &str) -> Result<XmlDocument> {
    FormatBuilder::new().parse_xml(input)
}

/// Serialize XML document to string
pub fn serialize_xml(doc: &XmlDocument) -> Result<String> {
    FormatBuilder::new().serialize_xml(doc)
}

// ============================================================================
// YAML Shortcuts
// ============================================================================

/// Parse YAML content
///
/// # Example
///
/// ```ignore
/// use octarine::data::formats::parse_yaml;
///
/// let value = parse_yaml("key: value")?;
/// ```
pub fn parse_yaml(input: &str) -> Result<serde_yaml::Value> {
    FormatBuilder::new().parse_yaml(input)
}

/// Serialize value to YAML
pub fn serialize_yaml<T: Serialize>(value: &T) -> Result<String> {
    FormatBuilder::new().serialize_yaml(value)
}

// ============================================================================
// Format Detection
// ============================================================================

/// Detect format from content
///
/// Returns `None` if format cannot be determined.
///
/// # Example
///
/// ```ignore
/// use octarine::data::formats::{detect_format, FormatType};
///
/// let format = detect_format(r#"{"key": "value"}"#);
/// assert!(matches!(format, Some(FormatType::Json)));
/// ```
#[must_use]
pub fn detect_format(input: &str) -> Option<FormatType> {
    FormatBuilder::new().detect_format(input)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_parse_json_shortcut() {
        let result = parse_json(r#"{"key": "value"}"#);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_xml_shortcut() {
        let result = parse_xml("<root/>");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_yaml_shortcut() {
        let result = parse_yaml("key: value");
        assert!(result.is_ok());
    }

    #[test]
    fn test_detect_format_shortcut() {
        assert!(matches!(
            detect_format(r#"{"key": "value"}"#),
            Some(FormatType::Json)
        ));
    }

    #[test]
    fn test_serialize_json_shortcut() {
        use serde_json::json;
        let value = json!({"key": "value"});
        let result = serialize_json(&value);
        assert!(result.is_ok());
    }
}

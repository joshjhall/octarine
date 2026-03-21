//! Format builder with observe instrumentation
//!
//! Wraps the primitives FormatBuilder with audit trails.

use serde::Serialize;
use serde_json::Value as JsonValue;

use crate::observe::{debug, warn};
use crate::primitives::data::formats::{FormatBuilder as PrimBuilder, FormatType, XmlDocument};
use crate::primitives::types::Result;

/// Builder for format parsing and serialization with observability
///
/// This is the Layer 3 wrapper that adds observe instrumentation
/// to the primitives FormatBuilder.
#[derive(Debug, Clone, Copy, Default)]
pub struct FormatBuilder {
    inner: PrimBuilder,
}

impl FormatBuilder {
    /// Create a new format builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PrimBuilder::new(),
        }
    }

    // ========================================================================
    // JSON Operations
    // ========================================================================

    /// Parse JSON content
    pub fn parse_json(&self, input: &str) -> Result<JsonValue> {
        debug("format.parse", "Parsing JSON content");
        let result = self.inner.parse_json(input);
        if result.is_err() {
            warn("format.parse", "JSON parsing failed");
        }
        result
    }

    /// Serialize value to JSON
    pub fn serialize_json<T: Serialize>(&self, value: &T) -> Result<String> {
        debug("format.serialize", "Serializing to JSON");
        self.inner.serialize_json(value)
    }

    /// Serialize value to pretty JSON
    pub fn serialize_json_pretty<T: Serialize>(&self, value: &T) -> Result<String> {
        debug("format.serialize", "Serializing to pretty JSON");
        self.inner.serialize_json_pretty(value)
    }

    // ========================================================================
    // XML Operations
    // ========================================================================

    /// Parse XML content
    pub fn parse_xml(&self, input: &str) -> Result<XmlDocument> {
        debug("format.parse", "Parsing XML content");
        let result = self.inner.parse_xml(input);
        if result.is_err() {
            warn("format.parse", "XML parsing failed");
        }
        result
    }

    /// Serialize XML document to string
    pub fn serialize_xml(&self, doc: &XmlDocument) -> Result<String> {
        debug("format.serialize", "Serializing to XML");
        self.inner.serialize_xml(doc)
    }

    // ========================================================================
    // YAML Operations
    // ========================================================================

    /// Parse YAML content
    pub fn parse_yaml(&self, input: &str) -> Result<serde_yaml::Value> {
        debug("format.parse", "Parsing YAML content");
        let result = self.inner.parse_yaml(input);
        if result.is_err() {
            warn("format.parse", "YAML parsing failed");
        }
        result
    }

    /// Serialize value to YAML
    pub fn serialize_yaml<T: Serialize>(&self, value: &T) -> Result<String> {
        debug("format.serialize", "Serializing to YAML");
        self.inner.serialize_yaml(value)
    }

    // ========================================================================
    // Format Detection
    // ========================================================================

    /// Detect format from content
    #[must_use]
    pub fn detect_format(&self, input: &str) -> Option<FormatType> {
        debug("format.detect", "Detecting format from content");
        let format = self.inner.detect_from_content(input);
        if format.is_none() {
            debug("format.detect", "Could not detect format");
        }
        format
    }

    /// Detect format from file extension
    #[must_use]
    pub fn detect_from_extension(&self, ext: &str) -> Option<FormatType> {
        self.inner.detect_from_extension(ext)
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
    fn test_builder_parse_json() {
        let builder = FormatBuilder::new();
        let result = builder.parse_json(r#"{"key": "value"}"#);
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_parse_xml() {
        let builder = FormatBuilder::new();
        let result = builder.parse_xml("<root><child/></root>");
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_parse_yaml() {
        let builder = FormatBuilder::new();
        let result = builder.parse_yaml("key: value");
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_detect_format() {
        let builder = FormatBuilder::new();

        assert!(matches!(
            builder.detect_format(r#"{"key": "value"}"#),
            Some(FormatType::Json)
        ));
        assert!(matches!(
            builder.detect_format("<root/>"),
            Some(FormatType::Xml)
        ));
        assert!(matches!(
            builder.detect_format("key: value"),
            Some(FormatType::Yaml)
        ));
    }
}

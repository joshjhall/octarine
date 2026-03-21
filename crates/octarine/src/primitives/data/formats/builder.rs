//! Format builder - unified API for format operations
//!
//! Provides a consistent interface for parsing and serializing
//! JSON, XML, and YAML formats.

use serde::Serialize;
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;

use crate::primitives::types::{Problem, Result};

use super::json;
use super::types::{FormatType, ParseOptions};
use super::xml::{self, XmlDocument};
use super::yaml;

/// Builder for format parsing and serialization operations
///
/// This builder provides a unified API for working with structured
/// data formats. It performs pure operations with no security checks.
///
/// For untrusted input, use `runtime::formats` which combines
/// security validation with parsing.
#[derive(Debug, Clone, Copy, Default)]
pub struct FormatBuilder;

impl FormatBuilder {
    /// Create a new format builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // ========================================================================
    // Format Detection
    // ========================================================================

    /// Detect the format type from file extension
    #[must_use]
    pub fn detect_from_extension(&self, ext: &str) -> Option<FormatType> {
        FormatType::from_extension(ext)
    }

    /// Detect the format type from content heuristics
    #[must_use]
    pub fn detect_from_content(&self, content: &str) -> Option<FormatType> {
        FormatType::detect_from_content(content)
    }

    // ========================================================================
    // JSON Operations
    // ========================================================================

    /// Parse JSON string
    pub fn parse_json(&self, input: &str) -> Result<JsonValue> {
        json::parse_json(input)
    }

    /// Parse JSON string with options
    #[allow(dead_code)]
    pub fn parse_json_with_options(
        &self,
        input: &str,
        options: &ParseOptions,
    ) -> Result<JsonValue> {
        json::parse_json_with_options(input, options)
    }

    /// Serialize value to JSON string
    pub fn serialize_json<T: Serialize>(&self, value: &T) -> Result<String> {
        json::serialize_json(value)
    }

    /// Serialize value to pretty-printed JSON string
    pub fn serialize_json_pretty<T: Serialize>(&self, value: &T) -> Result<String> {
        json::serialize_json_pretty(value)
    }

    // ========================================================================
    // XML Operations
    // ========================================================================

    /// Parse XML string
    pub fn parse_xml(&self, input: &str) -> Result<XmlDocument> {
        xml::parse_xml(input)
    }

    /// Serialize XML document to string
    pub fn serialize_xml(&self, doc: &XmlDocument) -> Result<String> {
        xml::serialize_xml(doc)
    }

    // ========================================================================
    // YAML Operations
    // ========================================================================

    /// Parse YAML string
    pub fn parse_yaml(&self, input: &str) -> Result<YamlValue> {
        yaml::parse_yaml(input)
    }

    /// Parse YAML string with options
    #[allow(dead_code)]
    pub fn parse_yaml_with_options(
        &self,
        input: &str,
        options: &ParseOptions,
    ) -> Result<YamlValue> {
        yaml::parse_yaml_with_options(input, options)
    }

    /// Serialize value to YAML string
    pub fn serialize_yaml<T: Serialize>(&self, value: &T) -> Result<String> {
        yaml::serialize_yaml(value)
    }

    // ========================================================================
    // Generic Operations
    // ========================================================================

    /// Parse content as the specified format
    #[allow(dead_code)]
    pub fn parse(&self, input: &str, format: FormatType) -> Result<ParsedContent> {
        match format {
            FormatType::Json => self.parse_json(input).map(ParsedContent::Json),
            FormatType::Xml => self.parse_xml(input).map(ParsedContent::Xml),
            FormatType::Yaml => self.parse_yaml(input).map(ParsedContent::Yaml),
        }
    }

    /// Parse content, auto-detecting format
    #[allow(dead_code)]
    pub fn parse_auto(&self, input: &str) -> Result<ParsedContent> {
        let format = self
            .detect_from_content(input)
            .ok_or_else(|| Problem::Parse("Unable to detect format".into()))?;
        self.parse(input, format)
    }
}

/// Parsed content from any supported format
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ParsedContent {
    /// Parsed JSON value
    Json(JsonValue),
    /// Parsed XML document
    Xml(XmlDocument),
    /// Parsed YAML value
    Yaml(YamlValue),
}

#[allow(dead_code)]
impl ParsedContent {
    /// Get the format type of this content
    #[must_use]
    pub fn format_type(&self) -> FormatType {
        match self {
            Self::Json(_) => FormatType::Json,
            Self::Xml(_) => FormatType::Xml,
            Self::Yaml(_) => FormatType::Yaml,
        }
    }

    /// Try to get as JSON value
    #[must_use]
    pub fn as_json(&self) -> Option<&JsonValue> {
        match self {
            Self::Json(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get as XML document
    #[must_use]
    pub fn as_xml(&self) -> Option<&XmlDocument> {
        match self {
            Self::Xml(d) => Some(d),
            _ => None,
        }
    }

    /// Try to get as YAML value
    #[must_use]
    pub fn as_yaml(&self) -> Option<&YamlValue> {
        match self {
            Self::Yaml(v) => Some(v),
            _ => None,
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
    fn test_builder_parse_json() {
        let builder = FormatBuilder::new();
        let result = builder.parse_json(r#"{"key": "value"}"#);
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_parse_xml() {
        let builder = FormatBuilder::new();
        let result = builder.parse_xml("<root/>");
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

        assert_eq!(
            builder.detect_from_extension("json"),
            Some(FormatType::Json)
        );
        assert_eq!(builder.detect_from_extension("xml"), Some(FormatType::Xml));
        assert_eq!(
            builder.detect_from_extension("yaml"),
            Some(FormatType::Yaml)
        );
    }

    #[test]
    fn test_builder_detect_from_content() {
        let builder = FormatBuilder::new();

        assert_eq!(
            builder.detect_from_content(r#"{"key": "value"}"#),
            Some(FormatType::Json)
        );
        assert_eq!(
            builder.detect_from_content("<root/>"),
            Some(FormatType::Xml)
        );
        assert_eq!(
            builder.detect_from_content("key: value"),
            Some(FormatType::Yaml)
        );
    }

    #[test]
    fn test_builder_parse_auto() {
        let builder = FormatBuilder::new();

        let json_result = builder.parse_auto(r#"{"key": "value"}"#);
        assert!(json_result.is_ok());
        assert_eq!(json_result.expect("valid").format_type(), FormatType::Json);

        let xml_result = builder.parse_auto("<root/>");
        assert!(xml_result.is_ok());
        assert_eq!(xml_result.expect("valid").format_type(), FormatType::Xml);
    }

    #[test]
    fn test_builder_serialize_json() {
        let builder = FormatBuilder::new();
        let value = serde_json::json!({"key": "value"});

        let compact = builder.serialize_json(&value).expect("valid");
        assert!(!compact.contains('\n'));

        let pretty = builder.serialize_json_pretty(&value).expect("valid");
        assert!(pretty.contains('\n'));
    }

    #[test]
    fn test_parsed_content_accessors() {
        let builder = FormatBuilder::new();

        let content = builder
            .parse(r#"{"key": "value"}"#, FormatType::Json)
            .expect("valid");
        assert!(content.as_json().is_some());
        assert!(content.as_xml().is_none());
        assert!(content.as_yaml().is_none());
    }
}

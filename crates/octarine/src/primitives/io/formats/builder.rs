//! Format I/O builder
//!
//! Unified API for format-aware file operations.

use std::path::Path;

use crate::primitives::data::formats::FormatType;
use crate::primitives::types::Result;

use super::reading::{read_format_file, read_format_string};
use super::types::{FormatReadOptions, FormatWriteOptions, ReadResult};
use super::writing::{write_format_file, write_format_string};

/// Builder for format-aware I/O operations
///
/// Provides a unified API for reading and writing structured
/// data files (JSON, XML, YAML) with automatic format detection.
#[derive(Debug, Clone, Copy, Default)]
pub struct FormatIoBuilder;

impl FormatIoBuilder {
    /// Create a new format I/O builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // ========================================================================
    // Reading Operations
    // ========================================================================

    /// Read a file with automatic format detection
    ///
    /// Format is detected from file extension or content.
    pub fn read_file(&self, path: &Path) -> Result<ReadResult> {
        read_format_file(path, &FormatReadOptions::default())
    }

    /// Read a file with specific options
    pub fn read_file_with_options(
        &self,
        path: &Path,
        options: &FormatReadOptions,
    ) -> Result<ReadResult> {
        read_format_file(path, options)
    }

    /// Read a JSON file
    pub fn read_json_file(&self, path: &Path) -> Result<ReadResult> {
        read_format_file(path, &FormatReadOptions::json())
    }

    /// Read an XML file
    pub fn read_xml_file(&self, path: &Path) -> Result<ReadResult> {
        read_format_file(path, &FormatReadOptions::xml())
    }

    /// Read a YAML file
    pub fn read_yaml_file(&self, path: &Path) -> Result<ReadResult> {
        read_format_file(path, &FormatReadOptions::yaml())
    }

    /// Detect format from string content
    pub fn read_string(&self, content: &str) -> Result<ReadResult> {
        read_format_string(content, &FormatReadOptions::default())
    }

    /// Read string with explicit format
    pub fn read_string_as(&self, content: &str, format: FormatType) -> Result<ReadResult> {
        let options = match format {
            FormatType::Json => FormatReadOptions::json(),
            FormatType::Xml => FormatReadOptions::xml(),
            FormatType::Yaml => FormatReadOptions::yaml(),
        };
        read_format_string(content, &options)
    }

    // ========================================================================
    // Writing Operations
    // ========================================================================

    /// Write content to a file
    pub fn write_file(&self, path: &Path, content: &str, format: FormatType) -> Result<()> {
        let options = match format {
            FormatType::Json => FormatWriteOptions::json(),
            FormatType::Xml => FormatWriteOptions::xml(),
            FormatType::Yaml => FormatWriteOptions::yaml(),
        };
        write_format_file(path, content, &options)
    }

    /// Write content with specific options
    pub fn write_file_with_options(
        &self,
        path: &Path,
        content: &str,
        options: &FormatWriteOptions,
    ) -> Result<()> {
        write_format_file(path, content, options)
    }

    /// Write JSON content to a file
    pub fn write_json_file(&self, path: &Path, content: &str) -> Result<()> {
        write_format_file(path, content, &FormatWriteOptions::json())
    }

    /// Write XML content to a file
    pub fn write_xml_file(&self, path: &Path, content: &str) -> Result<()> {
        write_format_file(path, content, &FormatWriteOptions::xml())
    }

    /// Write YAML content to a file
    pub fn write_yaml_file(&self, path: &Path, content: &str) -> Result<()> {
        write_format_file(path, content, &FormatWriteOptions::yaml())
    }

    /// Format content for a specific format
    pub fn format_string(&self, content: &str, format: FormatType) -> Result<String> {
        let options = match format {
            FormatType::Json => FormatWriteOptions::json(),
            FormatType::Xml => FormatWriteOptions::xml(),
            FormatType::Yaml => FormatWriteOptions::yaml(),
        };
        write_format_string(content, &options)
    }

    /// Format content with specific options
    pub fn format_string_with_options(
        &self,
        content: &str,
        options: &FormatWriteOptions,
    ) -> Result<String> {
        write_format_string(content, options)
    }

    // ========================================================================
    // Format Detection
    // ========================================================================

    /// Detect format from file path (extension-based)
    #[must_use]
    pub fn detect_format_from_path(&self, path: &Path) -> Option<FormatType> {
        path.extension()
            .and_then(|ext| ext.to_str())
            .and_then(FormatType::from_extension)
    }

    /// Detect format from content
    #[must_use]
    pub fn detect_format_from_content(&self, content: &str) -> Option<FormatType> {
        let trimmed = content.trim();

        // JSON: starts with { or [
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            return Some(FormatType::Json);
        }

        // XML: starts with <
        if trimmed.starts_with('<') {
            return Some(FormatType::Xml);
        }

        // YAML: document marker or key: value pattern
        if trimmed.starts_with("---")
            || (trimmed.contains(": ") && !trimmed.starts_with('{'))
            || trimmed.starts_with("- ")
        {
            return Some(FormatType::Yaml);
        }

        None
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
    fn test_builder_creation() {
        let _builder = FormatIoBuilder::new();
    }

    #[test]
    fn test_read_and_write_json() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.json");

        let content = r#"{"key": "value"}"#;

        builder.write_json_file(&path, content).expect("write");

        let result = builder.read_json_file(&path).expect("read");
        assert!(matches!(result.format, FormatType::Json));
        assert_eq!(result.content, content);
    }

    #[test]
    fn test_read_and_write_xml() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.xml");

        let content = "<root><child/></root>";

        builder.write_xml_file(&path, content).expect("write");

        let result = builder.read_xml_file(&path).expect("read");
        assert!(matches!(result.format, FormatType::Xml));
        assert_eq!(result.content, content);
    }

    #[test]
    fn test_read_and_write_yaml() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.yaml");

        let content = "key: value";

        builder.write_yaml_file(&path, content).expect("write");

        let result = builder.read_yaml_file(&path).expect("read");
        assert!(matches!(result.format, FormatType::Yaml));
        assert_eq!(result.content, content);
    }

    #[test]
    fn test_auto_detect_from_extension() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("config.json");

        let content = r#"{"setting": true}"#;
        builder
            .write_file(&path, content, FormatType::Json)
            .expect("write");

        let result = builder.read_file(&path).expect("read");
        assert!(matches!(result.format, FormatType::Json));
    }

    #[test]
    fn test_detect_format_from_path() {
        let builder = FormatIoBuilder::new();

        assert!(matches!(
            builder.detect_format_from_path(Path::new("config.json")),
            Some(FormatType::Json)
        ));
        assert!(matches!(
            builder.detect_format_from_path(Path::new("data.xml")),
            Some(FormatType::Xml)
        ));
        assert!(matches!(
            builder.detect_format_from_path(Path::new("settings.yaml")),
            Some(FormatType::Yaml)
        ));
        assert!(matches!(
            builder.detect_format_from_path(Path::new("settings.yml")),
            Some(FormatType::Yaml)
        ));
        assert!(
            builder
                .detect_format_from_path(Path::new("unknown.txt"))
                .is_none()
        );
    }

    #[test]
    fn test_detect_format_from_content() {
        let builder = FormatIoBuilder::new();

        assert!(matches!(
            builder.detect_format_from_content(r#"{"key": "value"}"#),
            Some(FormatType::Json)
        ));
        assert!(matches!(
            builder.detect_format_from_content("<root/>"),
            Some(FormatType::Xml)
        ));
        assert!(matches!(
            builder.detect_format_from_content("---\nkey: value"),
            Some(FormatType::Yaml)
        ));
        assert!(matches!(
            builder.detect_format_from_content("key: value"),
            Some(FormatType::Yaml)
        ));
    }

    #[test]
    fn test_read_string() {
        let builder = FormatIoBuilder::new();

        let result = builder.read_string(r#"{"key": "value"}"#).expect("read");
        assert!(matches!(result.format, FormatType::Json));

        let result = builder.read_string("<root/>").expect("read");
        assert!(matches!(result.format, FormatType::Xml));
    }

    #[test]
    fn test_read_string_as_explicit_format() {
        let builder = FormatIoBuilder::new();

        let result = builder
            .read_string_as("key: value", FormatType::Yaml)
            .expect("read");
        assert!(matches!(result.format, FormatType::Yaml));
    }
}

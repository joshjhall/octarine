//! Format I/O builder with observe instrumentation
//!
//! Wraps the primitives FormatIoBuilder with audit trails.

use std::path::Path;

use crate::observe::{debug, warn};
use crate::primitives::data::formats::FormatType;
use crate::primitives::io::formats::{
    FormatIoBuilder as PrimBuilder, FormatReadOptions, FormatWriteOptions, ReadResult,
};
use crate::primitives::types::Result;

/// Builder for format-aware I/O operations with observability
///
/// This is the Layer 3 wrapper that adds observe instrumentation
/// to the primitives FormatIoBuilder.
#[derive(Debug, Clone, Copy, Default)]
pub struct FormatIoBuilder {
    inner: PrimBuilder,
}

impl FormatIoBuilder {
    /// Create a new format I/O builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PrimBuilder::new(),
        }
    }

    // ========================================================================
    // Reading Operations
    // ========================================================================

    /// Read a file with automatic format detection
    pub fn read_file(&self, path: &Path) -> Result<ReadResult> {
        debug("io.format", format!("Reading file: {}", path.display()));
        let result = self.inner.read_file(path);
        if result.is_err() {
            warn(
                "io.format",
                format!("Failed to read file: {}", path.display()),
            );
        }
        result
    }

    /// Read a file with specific options
    pub fn read_file_with_options(
        &self,
        path: &Path,
        options: &FormatReadOptions,
    ) -> Result<ReadResult> {
        debug(
            "io.format",
            format!("Reading file with options: {}", path.display()),
        );
        self.inner.read_file_with_options(path, options)
    }

    /// Read a JSON file
    pub fn read_json_file(&self, path: &Path) -> Result<ReadResult> {
        debug(
            "io.format",
            format!("Reading JSON file: {}", path.display()),
        );
        self.inner.read_json_file(path)
    }

    /// Read an XML file
    pub fn read_xml_file(&self, path: &Path) -> Result<ReadResult> {
        debug("io.format", format!("Reading XML file: {}", path.display()));
        self.inner.read_xml_file(path)
    }

    /// Read a YAML file
    pub fn read_yaml_file(&self, path: &Path) -> Result<ReadResult> {
        debug(
            "io.format",
            format!("Reading YAML file: {}", path.display()),
        );
        self.inner.read_yaml_file(path)
    }

    // ========================================================================
    // Writing Operations
    // ========================================================================

    /// Write content to a file
    pub fn write_file(&self, path: &Path, content: &str, format: FormatType) -> Result<()> {
        debug(
            "io.format",
            format!("Writing {:?} file: {}", format, path.display()),
        );
        let result = self.inner.write_file(path, content, format);
        if result.is_err() {
            warn(
                "io.format",
                format!("Failed to write file: {}", path.display()),
            );
        }
        result
    }

    /// Write content with specific options
    pub fn write_file_with_options(
        &self,
        path: &Path,
        content: &str,
        options: &FormatWriteOptions,
    ) -> Result<()> {
        debug(
            "io.format",
            format!("Writing file with options: {}", path.display()),
        );
        self.inner.write_file_with_options(path, content, options)
    }

    /// Write JSON content to a file
    pub fn write_json_file(&self, path: &Path, content: &str) -> Result<()> {
        debug(
            "io.format",
            format!("Writing JSON file: {}", path.display()),
        );
        self.inner.write_json_file(path, content)
    }

    /// Write XML content to a file
    pub fn write_xml_file(&self, path: &Path, content: &str) -> Result<()> {
        debug("io.format", format!("Writing XML file: {}", path.display()));
        self.inner.write_xml_file(path, content)
    }

    /// Write YAML content to a file
    pub fn write_yaml_file(&self, path: &Path, content: &str) -> Result<()> {
        debug(
            "io.format",
            format!("Writing YAML file: {}", path.display()),
        );
        self.inner.write_yaml_file(path, content)
    }

    // ========================================================================
    // Format Detection
    // ========================================================================

    /// Detect format from file path
    #[must_use]
    pub fn detect_format_from_path(&self, path: &Path) -> Option<FormatType> {
        self.inner.detect_format_from_path(path)
    }

    /// Detect format from content
    #[must_use]
    pub fn detect_format_from_content(&self, content: &str) -> Option<FormatType> {
        self.inner.detect_format_from_content(content)
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
    fn test_builder_read_write_json() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.json");

        let content = r#"{"key": "value"}"#;
        builder.write_json_file(&path, content).expect("write");

        let result = builder.read_json_file(&path).expect("read");
        assert!(matches!(result.format, FormatType::Json));
    }

    #[test]
    fn test_builder_detect_format() {
        let builder = FormatIoBuilder::new();

        assert!(matches!(
            builder.detect_format_from_path(Path::new("data.json")),
            Some(FormatType::Json)
        ));
        assert!(matches!(
            builder.detect_format_from_content("<root/>"),
            Some(FormatType::Xml)
        ));
    }

    #[test]
    fn test_builder_read_write_xml_roundtrip() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("doc.xml");
        let content = "<root><child/></root>";

        builder.write_xml_file(&path, content).expect("write xml");
        let result = builder.read_xml_file(&path).expect("read xml");
        assert!(matches!(result.format, FormatType::Xml));
        // Content round-trips byte-for-byte.
        assert_eq!(result.content, content);
    }

    #[test]
    fn test_builder_read_write_yaml_roundtrip() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("cfg.yaml");
        let content = "key: value";

        builder.write_yaml_file(&path, content).expect("write yaml");
        let result = builder.read_yaml_file(&path).expect("read yaml");
        assert!(matches!(result.format, FormatType::Yaml));
        assert_eq!(result.content, content);
    }

    #[test]
    fn test_write_file_dispatches_on_format() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("temp dir");

        // write_file with an explicit format, then auto-detected read back.
        let path = dir.path().join("auto.yaml");
        builder
            .write_file(&path, "a: 1", FormatType::Yaml)
            .expect("write");
        let result = builder.read_file(&path).expect("read");
        assert!(matches!(result.format, FormatType::Yaml));
    }

    #[test]
    fn test_read_file_auto_detects_by_extension() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("data.json");
        builder.write_json_file(&path, r#"{"a":1}"#).expect("write");
        let result = builder.read_file(&path).expect("read");
        assert!(matches!(result.format, FormatType::Json));
    }

    #[test]
    fn test_read_missing_file_is_err() {
        // The Layer 3 wrapper must surface the primitive read error (and it
        // logs a warning on the failure path).
        let builder = FormatIoBuilder::new();
        let result = builder.read_file(Path::new("/nonexistent/definitely/missing.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_read_json_file_missing_is_err() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("nope.json");
        assert!(builder.read_json_file(&path).is_err());
    }

    #[test]
    fn test_write_to_unwritable_path_is_err() {
        // Writing into a directory that does not exist must error and trip the
        // warn() branch in write_file.
        let builder = FormatIoBuilder::new();
        let path = Path::new("/nonexistent/dir/out.json");
        let result = builder.write_file(path, r#"{"k":1}"#, FormatType::Json);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_file_with_options() {
        use crate::primitives::io::formats::FormatReadOptions;
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("data.json");
        builder
            .write_json_file(&path, r#"{"ok":true}"#)
            .expect("write");

        let opts = FormatReadOptions::json();
        let result = builder
            .read_file_with_options(&path, &opts)
            .expect("read w/ options");
        assert!(matches!(result.format, FormatType::Json));
    }

    #[test]
    fn test_write_file_with_options() {
        use crate::primitives::io::formats::FormatWriteOptions;
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("out.json");

        let opts = FormatWriteOptions::json();
        builder
            .write_file_with_options(&path, r#"{"k":1}"#, &opts)
            .expect("write w/ options");
        assert!(path.exists());
        let result = builder.read_json_file(&path).expect("read");
        assert!(matches!(result.format, FormatType::Json));
    }

    #[test]
    fn test_detect_format_from_path_variants() {
        let builder = FormatIoBuilder::new();
        assert!(matches!(
            builder.detect_format_from_path(Path::new("a.yaml")),
            Some(FormatType::Yaml)
        ));
        assert!(matches!(
            builder.detect_format_from_path(Path::new("a.yml")),
            Some(FormatType::Yaml)
        ));
        assert!(matches!(
            builder.detect_format_from_path(Path::new("a.xml")),
            Some(FormatType::Xml)
        ));
        // Unknown extension yields None.
        assert!(
            builder
                .detect_format_from_path(Path::new("a.bin"))
                .is_none()
        );
        // No extension yields None.
        assert!(
            builder
                .detect_format_from_path(Path::new("noext"))
                .is_none()
        );
    }

    #[test]
    fn test_detect_format_from_content_variants() {
        let builder = FormatIoBuilder::new();
        // JSON object and array.
        assert!(matches!(
            builder.detect_format_from_content(r#"{"a":1}"#),
            Some(FormatType::Json)
        ));
        assert!(matches!(
            builder.detect_format_from_content("[1,2,3]"),
            Some(FormatType::Json)
        ));
        // XML.
        assert!(matches!(
            builder.detect_format_from_content("<a/>"),
            Some(FormatType::Xml)
        ));
        // YAML document marker and key: value form.
        assert!(matches!(
            builder.detect_format_from_content("---\nk: v"),
            Some(FormatType::Yaml)
        ));
        assert!(matches!(
            builder.detect_format_from_content("- item"),
            Some(FormatType::Yaml)
        ));
        // Unrecognized content yields None.
        assert!(builder.detect_format_from_content("plain text").is_none());
    }
}

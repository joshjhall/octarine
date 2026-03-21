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
}

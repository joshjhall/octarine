//! Format I/O shortcut functions
//!
//! Convenience functions for common format file operations.

use std::path::Path;

use crate::primitives::data::formats::FormatType;
use crate::primitives::types::Result;

use super::{FormatIoBuilder, ReadResult};

// ============================================================================
// Reading Shortcuts
// ============================================================================

/// Read a file with automatic format detection
///
/// # Example
///
/// ```ignore
/// use octarine::io::formats::read_format_file;
/// use std::path::Path;
///
/// let result = read_format_file(Path::new("config.json"))?;
/// println!("Content: {}", result.content);
/// ```
pub fn read_format_file(path: &Path) -> Result<ReadResult> {
    FormatIoBuilder::new().read_file(path)
}

/// Read a JSON file
pub fn read_json_file(path: &Path) -> Result<ReadResult> {
    FormatIoBuilder::new().read_json_file(path)
}

/// Read an XML file
pub fn read_xml_file(path: &Path) -> Result<ReadResult> {
    FormatIoBuilder::new().read_xml_file(path)
}

/// Read a YAML file
pub fn read_yaml_file(path: &Path) -> Result<ReadResult> {
    FormatIoBuilder::new().read_yaml_file(path)
}

// ============================================================================
// Writing Shortcuts
// ============================================================================

/// Write content to a file with format validation
///
/// # Example
///
/// ```ignore
/// use octarine::io::formats::{write_format_file, FormatType};
/// use std::path::Path;
///
/// write_format_file(Path::new("data.yaml"), "key: value", FormatType::Yaml)?;
/// ```
pub fn write_format_file(path: &Path, content: &str, format: FormatType) -> Result<()> {
    FormatIoBuilder::new().write_file(path, content, format)
}

/// Write JSON content to a file
pub fn write_json_file(path: &Path, content: &str) -> Result<()> {
    FormatIoBuilder::new().write_json_file(path, content)
}

/// Write XML content to a file
pub fn write_xml_file(path: &Path, content: &str) -> Result<()> {
    FormatIoBuilder::new().write_xml_file(path, content)
}

/// Write YAML content to a file
pub fn write_yaml_file(path: &Path, content: &str) -> Result<()> {
    FormatIoBuilder::new().write_yaml_file(path, content)
}

// ============================================================================
// Format Detection Shortcuts
// ============================================================================

/// Detect format from file path (extension-based)
#[must_use]
pub fn detect_format_from_path(path: &Path) -> Option<FormatType> {
    FormatIoBuilder::new().detect_format_from_path(path)
}

/// Detect format from content
#[must_use]
pub fn detect_format_from_content(content: &str) -> Option<FormatType> {
    FormatIoBuilder::new().detect_format_from_content(content)
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
    fn test_read_write_json_shortcut() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.json");

        write_json_file(&path, r#"{"key": "value"}"#).expect("write");
        let result = read_json_file(&path).expect("read");
        assert!(matches!(result.format, FormatType::Json));
    }

    #[test]
    fn test_detect_format_shortcuts() {
        assert!(matches!(
            detect_format_from_path(Path::new("config.yaml")),
            Some(FormatType::Yaml)
        ));
        assert!(matches!(
            detect_format_from_content("<root/>"),
            Some(FormatType::Xml)
        ));
    }
}

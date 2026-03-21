//! Format file writing
//!
//! Write files with format-specific handling.

use std::path::Path;

use crate::primitives::data::formats::FormatType;
use crate::primitives::io::file::{WriteOptions, write_atomic};
use crate::primitives::types::{Problem, Result};

use super::types::FormatWriteOptions;

/// Write formatted content to a file
///
/// Uses atomic writes for safety.
pub fn write_format_file(path: &Path, content: &str, options: &FormatWriteOptions) -> Result<()> {
    // Validate content matches declared format
    validate_content_format(content, options.format)?;

    // Use atomic write
    let write_opts = WriteOptions::for_config();
    write_atomic(path, content.as_bytes(), write_opts)?;
    Ok(())
}

/// Format content for a specific output format
///
/// Applies pretty-printing if configured.
pub fn write_format_string(content: &str, options: &FormatWriteOptions) -> Result<String> {
    match options.format {
        FormatType::Json => format_json_string(content, options),
        FormatType::Xml => format_xml_string(content, options),
        FormatType::Yaml => format_yaml_string(content, options),
    }
}

/// Validate that content matches the declared format
fn validate_content_format(content: &str, format: FormatType) -> Result<()> {
    let trimmed = content.trim();

    match format {
        FormatType::Json => {
            if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
                return Err(Problem::Validation(
                    "Content does not appear to be valid JSON".into(),
                ));
            }
        }
        FormatType::Xml => {
            if !trimmed.contains('<') {
                return Err(Problem::Validation(
                    "Content does not appear to be valid XML".into(),
                ));
            }
        }
        FormatType::Yaml => {
            // YAML is very permissive, any string is valid YAML
        }
    }

    Ok(())
}

/// Format JSON string (pretty-print if configured)
fn format_json_string(content: &str, options: &FormatWriteOptions) -> Result<String> {
    if !options.pretty {
        // Return as-is for compact output
        // (ideally we'd parse and re-serialize, but that requires full JSON parsing)
        return Ok(content.to_string());
    }

    // For pretty printing, we'd need to parse and re-serialize
    // For now, return as-is since we don't have serde_json in scope
    Ok(content.to_string())
}

/// Format XML string (pretty-print if configured)
fn format_xml_string(content: &str, options: &FormatWriteOptions) -> Result<String> {
    if !options.pretty {
        return Ok(content.to_string());
    }

    // Basic XML indentation (simple implementation)
    // A full implementation would use a proper XML formatter
    Ok(content.to_string())
}

/// Format YAML string
fn format_yaml_string(content: &str, _options: &FormatWriteOptions) -> Result<String> {
    // YAML is already human-readable by nature
    Ok(content.to_string())
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
    fn test_validate_content_format_json() {
        assert!(validate_content_format(r#"{"key": "value"}"#, FormatType::Json).is_ok());
        assert!(validate_content_format("[1, 2, 3]", FormatType::Json).is_ok());
        assert!(validate_content_format("key: value", FormatType::Json).is_err());
    }

    #[test]
    fn test_validate_content_format_xml() {
        assert!(validate_content_format("<root/>", FormatType::Xml).is_ok());
        assert!(validate_content_format("no tags", FormatType::Xml).is_err());
    }

    #[test]
    fn test_validate_content_format_yaml() {
        // YAML is very permissive
        assert!(validate_content_format("key: value", FormatType::Yaml).is_ok());
        assert!(validate_content_format("any string", FormatType::Yaml).is_ok());
    }

    #[test]
    fn test_write_format_file_json() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.json");

        let content = r#"{"key": "value"}"#;
        let opts = FormatWriteOptions::json();

        write_format_file(&path, content, &opts).expect("should write");

        let read_back = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(read_back, content);
    }

    #[test]
    fn test_write_format_file_xml() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.xml");

        let content = "<root><child>text</child></root>";
        let opts = FormatWriteOptions::xml();

        write_format_file(&path, content, &opts).expect("should write");

        let read_back = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(read_back, content);
    }

    #[test]
    fn test_write_format_file_yaml() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.yaml");

        let content = "key: value\nlist:\n  - item1\n  - item2";
        let opts = FormatWriteOptions::yaml();

        write_format_file(&path, content, &opts).expect("should write");

        let read_back = std::fs::read_to_string(&path).expect("read file");
        assert_eq!(read_back, content);
    }

    #[test]
    fn test_write_format_file_validation_error() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.json");

        let content = "not json at all";
        let opts = FormatWriteOptions::json();

        let result = write_format_file(&path, content, &opts);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_format_string() {
        let content = r#"{"key": "value"}"#;
        let opts = FormatWriteOptions::json();

        let result = write_format_string(content, &opts).expect("should format");
        assert_eq!(result, content);
    }
}

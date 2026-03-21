//! Format file reading
//!
//! Read files with automatic format detection.

use std::path::Path;

use crate::primitives::data::formats::FormatType;
use crate::primitives::types::{Problem, Result};

use super::types::{FormatReadOptions, ReadResult};

/// Read a file and detect its format
///
/// Format is detected from:
/// 1. Explicit expected_format in options
/// 2. File extension
/// 3. Content inspection
pub fn read_format_file(path: &Path, options: &FormatReadOptions) -> Result<ReadResult> {
    // Read file content
    let content = std::fs::read_to_string(path)?;

    // Check size limit
    if content.len() > options.max_size {
        return Err(Problem::Validation(format!(
            "File exceeds maximum size: {} > {} bytes",
            content.len(),
            options.max_size
        )));
    }

    // Detect format
    let format = detect_format(&content, path, options)?;

    // Validate format if requested
    if options.validate_format {
        validate_format_content(&content, format)?;
    }

    Ok(ReadResult::new(content, format))
}

/// Read format content from a string
///
/// Uses content inspection for format detection.
pub fn read_format_string(content: &str, options: &FormatReadOptions) -> Result<ReadResult> {
    // Check size limit
    if content.len() > options.max_size {
        return Err(Problem::Validation(format!(
            "Content exceeds maximum size: {} > {} bytes",
            content.len(),
            options.max_size
        )));
    }

    // Detect format from options or content
    let format = if let Some(fmt) = options.expected_format {
        fmt
    } else {
        detect_format_from_content(content).unwrap_or(FormatType::Json)
    };

    // Validate format if requested
    if options.validate_format {
        validate_format_content(content, format)?;
    }

    Ok(ReadResult::new(content.to_string(), format))
}

/// Detect format from content, path, and options
fn detect_format(content: &str, path: &Path, options: &FormatReadOptions) -> Result<FormatType> {
    // Use explicit format if provided
    if let Some(fmt) = options.expected_format {
        return Ok(fmt);
    }

    // Try extension first
    if let Some(fmt) = detect_format_from_extension(path) {
        return Ok(fmt);
    }

    // Fall back to content inspection
    detect_format_from_content(content).ok_or_else(|| {
        Problem::Validation(format!(
            "Could not detect format of file '{}'",
            path.display()
        ))
    })
}

/// Detect format from file extension
fn detect_format_from_extension(path: &Path) -> Option<FormatType> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .and_then(FormatType::from_extension)
}

/// Detect format from content
fn detect_format_from_content(content: &str) -> Option<FormatType> {
    let trimmed = content.trim();

    // JSON: starts with { or [
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return Some(FormatType::Json);
    }

    // XML: starts with < (but not YAML)
    if trimmed.starts_with('<') {
        return Some(FormatType::Xml);
    }

    // YAML: common YAML patterns
    if is_likely_yaml(trimmed) {
        return Some(FormatType::Yaml);
    }

    None
}

/// Check if content looks like YAML
fn is_likely_yaml(content: &str) -> bool {
    // YAML document marker
    if content.starts_with("---") {
        return true;
    }

    // Key-value pattern (key: value)
    if content.contains(": ") || content.contains(":\n") {
        // But not if it looks like JSON or XML
        if !content.starts_with('{') && !content.starts_with('<') {
            return true;
        }
    }

    // YAML list pattern
    if content.starts_with("- ") {
        return true;
    }

    false
}

/// Basic format validation
fn validate_format_content(content: &str, format: FormatType) -> Result<()> {
    match format {
        FormatType::Json => validate_json_basic(content),
        FormatType::Xml => validate_xml_basic(content),
        FormatType::Yaml => validate_yaml_basic(content),
    }
}

/// Basic JSON validation (balanced braces)
fn validate_json_basic(content: &str) -> Result<()> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("Empty JSON content".into()));
    }

    // Should start with { or [
    if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        return Err(Problem::Validation(
            "JSON should start with '{' or '['".into(),
        ));
    }

    // Check balanced brackets
    let mut depth = 0i32;
    for c in trimmed.chars() {
        match c {
            '{' | '[' => depth = depth.saturating_add(1),
            '}' | ']' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth < 0 {
            return Err(Problem::Validation("Unbalanced JSON brackets".into()));
        }
    }

    if depth != 0 {
        return Err(Problem::Validation("Unbalanced JSON brackets".into()));
    }

    Ok(())
}

/// Basic XML validation (has tags)
fn validate_xml_basic(content: &str) -> Result<()> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("Empty XML content".into()));
    }

    // Should contain at least one tag
    if !trimmed.contains('<') || !trimmed.contains('>') {
        return Err(Problem::Validation("XML should contain tags".into()));
    }

    Ok(())
}

/// Basic YAML validation (not empty, reasonable structure)
fn validate_yaml_basic(content: &str) -> Result<()> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("Empty YAML content".into()));
    }

    Ok(())
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
    fn test_detect_format_from_extension() {
        let json_path = Path::new("/tmp/config.json");
        assert!(matches!(
            detect_format_from_extension(json_path),
            Some(FormatType::Json)
        ));

        let xml_path = Path::new("/tmp/config.xml");
        assert!(matches!(
            detect_format_from_extension(xml_path),
            Some(FormatType::Xml)
        ));

        let yaml_path = Path::new("/tmp/config.yaml");
        assert!(matches!(
            detect_format_from_extension(yaml_path),
            Some(FormatType::Yaml)
        ));

        let yml_path = Path::new("/tmp/config.yml");
        assert!(matches!(
            detect_format_from_extension(yml_path),
            Some(FormatType::Yaml)
        ));

        let unknown_path = Path::new("/tmp/config.txt");
        assert!(detect_format_from_extension(unknown_path).is_none());
    }

    #[test]
    fn test_detect_format_from_content_json() {
        assert!(matches!(
            detect_format_from_content(r#"{"key": "value"}"#),
            Some(FormatType::Json)
        ));
        assert!(matches!(
            detect_format_from_content(r#"[1, 2, 3]"#),
            Some(FormatType::Json)
        ));
    }

    #[test]
    fn test_detect_format_from_content_xml() {
        assert!(matches!(
            detect_format_from_content("<root/>"),
            Some(FormatType::Xml)
        ));
        assert!(matches!(
            detect_format_from_content("<?xml version=\"1.0\"?><root/>"),
            Some(FormatType::Xml)
        ));
    }

    #[test]
    fn test_detect_format_from_content_yaml() {
        assert!(matches!(
            detect_format_from_content("---\nkey: value"),
            Some(FormatType::Yaml)
        ));
        assert!(matches!(
            detect_format_from_content("key: value\nother: data"),
            Some(FormatType::Yaml)
        ));
        assert!(matches!(
            detect_format_from_content("- item1\n- item2"),
            Some(FormatType::Yaml)
        ));
    }

    #[test]
    fn test_validate_json_basic() {
        assert!(validate_json_basic(r#"{"key": "value"}"#).is_ok());
        assert!(validate_json_basic(r#"[1, 2, 3]"#).is_ok());
        assert!(validate_json_basic("").is_err());
        assert!(validate_json_basic("key: value").is_err());
    }

    #[test]
    fn test_validate_xml_basic() {
        assert!(validate_xml_basic("<root/>").is_ok());
        assert!(validate_xml_basic("").is_err());
        assert!(validate_xml_basic("no tags here").is_err());
    }

    #[test]
    fn test_validate_yaml_basic() {
        assert!(validate_yaml_basic("key: value").is_ok());
        assert!(validate_yaml_basic("").is_err());
    }

    #[test]
    fn test_read_format_string() {
        let opts = FormatReadOptions::default();
        let result = read_format_string(r#"{"key": "value"}"#, &opts).expect("should parse");
        assert!(matches!(result.format, FormatType::Json));
    }

    #[test]
    fn test_read_format_file_json() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.json");

        std::fs::write(&path, r#"{"key": "value"}"#).expect("write file");

        let opts = FormatReadOptions::default();
        let result = read_format_file(&path, &opts).expect("should read");
        assert!(matches!(result.format, FormatType::Json));
        assert_eq!(result.content, r#"{"key": "value"}"#);
    }

    #[test]
    fn test_read_format_file_size_limit() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("large.json");

        let large_content = "{\"data\": \"".to_string() + &"x".repeat(1000) + "\"}";
        std::fs::write(&path, &large_content).expect("write file");

        let opts = FormatReadOptions::default().max_size(100);
        let result = read_format_file(&path, &opts);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_format_file_explicit_format() {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("data.txt"); // Unknown extension

        std::fs::write(&path, "key: value").expect("write file");

        let opts = FormatReadOptions::yaml().skip_validation();
        let result = read_format_file(&path, &opts).expect("should read");
        assert!(matches!(result.format, FormatType::Yaml));
    }
}

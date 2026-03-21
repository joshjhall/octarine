//! Shared types for structured data formats
//!
//! These types are shared across data, security, and io format modules.

use std::fmt;

// ============================================================================
// Format Type Enumeration
// ============================================================================

/// Structured data format type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormatType {
    /// JSON format
    Json,
    /// XML format
    Xml,
    /// YAML format
    Yaml,
}

impl FormatType {
    /// Get the canonical file extension for this format
    #[must_use]
    pub const fn extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Xml => "xml",
            Self::Yaml => "yaml",
        }
    }

    /// Get the MIME type for this format
    #[must_use]
    pub const fn mime_type(&self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Xml => "application/xml",
            Self::Yaml => "application/x-yaml",
        }
    }

    /// Try to detect format from file extension
    #[must_use]
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "json" => Some(Self::Json),
            "xml" => Some(Self::Xml),
            "yaml" | "yml" => Some(Self::Yaml),
            _ => None,
        }
    }

    /// Try to detect format from content heuristics
    ///
    /// This uses simple heuristics and may not be 100% accurate.
    /// For definitive format detection, attempt parsing.
    #[must_use]
    pub fn detect_from_content(content: &str) -> Option<Self> {
        let trimmed = content.trim_start();

        // XML detection - starts with <? or <
        if trimmed.starts_with("<?xml") || trimmed.starts_with('<') {
            return Some(Self::Xml);
        }

        // JSON detection - starts with { or [
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            return Some(Self::Json);
        }

        // YAML detection - has key: value pattern or starts with ---
        if trimmed.starts_with("---") {
            return Some(Self::Yaml);
        }

        // Check for YAML key: value pattern (simple heuristic)
        if let Some(first_line) = trimmed.lines().next()
            && first_line.contains(": ")
            && !first_line.starts_with('{')
        {
            return Some(Self::Yaml);
        }

        None
    }
}

impl fmt::Display for FormatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => write!(f, "JSON"),
            Self::Xml => write!(f, "XML"),
            Self::Yaml => write!(f, "YAML"),
        }
    }
}

// ============================================================================
// Parse Options
// ============================================================================

/// Options for parsing structured data
#[derive(Debug, Clone)]
pub struct ParseOptions {
    /// Maximum nesting depth allowed (default: 64)
    pub max_depth: usize,
    /// Maximum content size in bytes (default: 10MB)
    pub max_size: usize,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

impl ParseOptions {
    /// Create new parse options with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum depth
    #[must_use]
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Set maximum size in bytes
    #[must_use]
    pub fn with_max_size(mut self, size: usize) -> Self {
        self.max_size = size;
        self
    }

    /// Create strict options (lower limits for untrusted input)
    #[must_use]
    pub fn strict() -> Self {
        Self {
            max_depth: 32,
            max_size: 1024 * 1024, // 1MB
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_type_extension() {
        assert_eq!(FormatType::Json.extension(), "json");
        assert_eq!(FormatType::Xml.extension(), "xml");
        assert_eq!(FormatType::Yaml.extension(), "yaml");
    }

    #[test]
    fn test_format_type_mime() {
        assert_eq!(FormatType::Json.mime_type(), "application/json");
        assert_eq!(FormatType::Xml.mime_type(), "application/xml");
        assert_eq!(FormatType::Yaml.mime_type(), "application/x-yaml");
    }

    #[test]
    fn test_format_type_from_extension() {
        assert_eq!(FormatType::from_extension("json"), Some(FormatType::Json));
        assert_eq!(FormatType::from_extension("JSON"), Some(FormatType::Json));
        assert_eq!(FormatType::from_extension("xml"), Some(FormatType::Xml));
        assert_eq!(FormatType::from_extension("yaml"), Some(FormatType::Yaml));
        assert_eq!(FormatType::from_extension("yml"), Some(FormatType::Yaml));
        assert_eq!(FormatType::from_extension("txt"), None);
    }

    #[test]
    fn test_format_type_detect_json() {
        assert_eq!(
            FormatType::detect_from_content(r#"{"key": "value"}"#),
            Some(FormatType::Json)
        );
        assert_eq!(
            FormatType::detect_from_content("[1, 2, 3]"),
            Some(FormatType::Json)
        );
        assert_eq!(
            FormatType::detect_from_content("  { \"nested\": {} }"),
            Some(FormatType::Json)
        );
    }

    #[test]
    fn test_format_type_detect_xml() {
        assert_eq!(
            FormatType::detect_from_content("<?xml version=\"1.0\"?><root/>"),
            Some(FormatType::Xml)
        );
        assert_eq!(
            FormatType::detect_from_content("<root><child/></root>"),
            Some(FormatType::Xml)
        );
    }

    #[test]
    fn test_format_type_detect_yaml() {
        assert_eq!(
            FormatType::detect_from_content("---\nkey: value"),
            Some(FormatType::Yaml)
        );
        assert_eq!(
            FormatType::detect_from_content("key: value\nother: data"),
            Some(FormatType::Yaml)
        );
    }

    #[test]
    fn test_parse_options_default() {
        let opts = ParseOptions::default();
        assert_eq!(opts.max_depth, 64);
        assert_eq!(opts.max_size, 10 * 1024 * 1024);
    }

    #[test]
    fn test_parse_options_strict() {
        let opts = ParseOptions::strict();
        assert_eq!(opts.max_depth, 32);
        assert_eq!(opts.max_size, 1024 * 1024);
    }

    #[test]
    fn test_parse_options_builder() {
        let opts = ParseOptions::new().with_max_depth(16).with_max_size(1000);
        assert_eq!(opts.max_depth, 16);
        assert_eq!(opts.max_size, 1000);
    }
}

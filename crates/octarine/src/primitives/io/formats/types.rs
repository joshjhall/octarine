//! Format I/O types
//!
//! Options and results for format-aware file operations.

use crate::primitives::data::formats::FormatType;

/// Options for reading format files
#[derive(Debug, Clone)]
pub struct FormatReadOptions {
    /// Maximum file size to read (bytes)
    pub max_size: usize,
    /// Expected format (None = auto-detect)
    pub expected_format: Option<FormatType>,
    /// Whether to validate content matches format
    pub validate_format: bool,
}

impl Default for FormatReadOptions {
    fn default() -> Self {
        Self {
            max_size: 10 * 1024 * 1024, // 10MB
            expected_format: None,
            validate_format: true,
        }
    }
}

impl FormatReadOptions {
    /// Create options expecting JSON
    #[must_use]
    pub fn json() -> Self {
        Self {
            expected_format: Some(FormatType::Json),
            ..Default::default()
        }
    }

    /// Create options expecting XML
    #[must_use]
    pub fn xml() -> Self {
        Self {
            expected_format: Some(FormatType::Xml),
            ..Default::default()
        }
    }

    /// Create options expecting YAML
    #[must_use]
    pub fn yaml() -> Self {
        Self {
            expected_format: Some(FormatType::Yaml),
            ..Default::default()
        }
    }

    /// Set maximum file size
    #[must_use]
    pub fn max_size(mut self, size: usize) -> Self {
        self.max_size = size;
        self
    }

    /// Disable format validation
    #[must_use]
    pub fn skip_validation(mut self) -> Self {
        self.validate_format = false;
        self
    }
}

/// Options for writing format files
#[derive(Debug, Clone)]
pub struct FormatWriteOptions {
    /// Format to write as
    pub format: FormatType,
    /// Whether to pretty-print output
    pub pretty: bool,
    /// Indentation for pretty-printing
    pub indent: usize,
}

impl Default for FormatWriteOptions {
    fn default() -> Self {
        Self {
            format: FormatType::Json,
            pretty: true,
            indent: 2,
        }
    }
}

impl FormatWriteOptions {
    /// Create JSON write options
    #[must_use]
    pub fn json() -> Self {
        Self {
            format: FormatType::Json,
            ..Default::default()
        }
    }

    /// Create XML write options
    #[must_use]
    pub fn xml() -> Self {
        Self {
            format: FormatType::Xml,
            ..Default::default()
        }
    }

    /// Create YAML write options
    #[must_use]
    pub fn yaml() -> Self {
        Self {
            format: FormatType::Yaml,
            ..Default::default()
        }
    }

    /// Create compact (non-pretty) output
    #[must_use]
    pub fn compact(mut self) -> Self {
        self.pretty = false;
        self
    }

    /// Set indentation level
    #[must_use]
    pub fn indent(mut self, spaces: usize) -> Self {
        self.indent = spaces;
        self
    }
}

/// Result of reading a format file
#[derive(Debug, Clone)]
pub struct ReadResult {
    /// Raw content of the file
    pub content: String,
    /// Detected or specified format
    pub format: FormatType,
}

impl ReadResult {
    /// Create a new read result
    #[must_use]
    pub fn new(content: String, format: FormatType) -> Self {
        Self { content, format }
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
    fn test_read_options_defaults() {
        let opts = FormatReadOptions::default();
        assert_eq!(opts.max_size, 10 * 1024 * 1024);
        assert!(opts.expected_format.is_none());
        assert!(opts.validate_format);
    }

    #[test]
    fn test_read_options_json() {
        let opts = FormatReadOptions::json();
        assert!(matches!(opts.expected_format, Some(FormatType::Json)));
    }

    #[test]
    fn test_read_options_builder() {
        let opts = FormatReadOptions::yaml().max_size(1024).skip_validation();
        assert!(matches!(opts.expected_format, Some(FormatType::Yaml)));
        assert_eq!(opts.max_size, 1024);
        assert!(!opts.validate_format);
    }

    #[test]
    fn test_write_options_defaults() {
        let opts = FormatWriteOptions::default();
        assert!(matches!(opts.format, FormatType::Json));
        assert!(opts.pretty);
        assert_eq!(opts.indent, 2);
    }

    #[test]
    fn test_write_options_compact() {
        let opts = FormatWriteOptions::json().compact();
        assert!(!opts.pretty);
    }

    #[test]
    fn test_read_result() {
        let result = ReadResult::new("{}".into(), FormatType::Json);
        assert_eq!(result.content, "{}");
        assert!(matches!(result.format, FormatType::Json));
    }
}

//! Data facade for unified format and normalization access
//!
//! The `Data` facade provides a single entry point to all data-related
//! operations in octarine. It answers the question: "How should this be structured?"
//!
//! # Example
//!
//! ```
//! use octarine::data::Data;
//!
//! let data = Data::new();
//!
//! // Path normalization
//! let path_data = data.paths();
//!
//! // URL normalization
//! let network_data = data.network();
//!
//! // Text sanitization (takes input string)
//! let text_data = data.text("user input");
//! ```

use super::network::UrlNormalizationBuilder;
use super::paths::PathBuilder;
use super::text::TextBuilder;

#[cfg(feature = "formats")]
use super::formats::FormatBuilder;

/// Unified facade for all data operations (FORMAT concern)
///
/// The Data facade provides access to domain-specific data builders
/// that handle normalization, parsing, and sanitization.
///
/// All operations automatically emit observe events for audit trails.
///
/// # Domains
///
/// | Domain | Builder | Purpose |
/// |--------|---------|---------|
/// | `paths` | [`PathBuilder`] | Path normalization, joining |
/// | `network` | [`UrlNormalizationBuilder`] | URL path normalization |
/// | `text` | [`TextBuilder`] | Text sanitization, encoding |
/// | `formats` | [`FormatBuilder`] | JSON/XML/YAML parsing |
///
/// # Example
///
/// ```
/// use octarine::data::Data;
///
/// let data = Data::new();
///
/// // Normalize a path
/// let clean_path = data.paths().normalize("/app/../data/./file.txt");
///
/// // Sanitize text for logging
/// let safe_text = data.text("user\ninput\twith\x00nulls")
///     .sanitize_for_log()
///     .finish();
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Data;

impl Data {
    /// Create a new Data facade
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Access path data operations
    ///
    /// Provides normalization and manipulation for:
    /// - Path normalization (resolving `.` and `..`)
    /// - Path joining and construction
    /// - Filename extraction and validation
    /// - Platform-specific path handling
    ///
    /// # Example
    ///
    /// ```
    /// use octarine::data::Data;
    ///
    /// let data = Data::new();
    ///
    /// // Basic path operations
    /// let paths = data.paths();
    ///
    /// // Check path characteristics
    /// assert!(paths.is_absolute("/home/user"));
    /// assert!(paths.is_relative("./config"));
    /// ```
    #[must_use]
    pub fn paths(&self) -> PathBuilder {
        PathBuilder::new()
    }

    /// Access network/URL data operations
    ///
    /// Provides normalization for:
    /// - URL path normalization
    /// - Query string handling
    /// - Fragment normalization
    ///
    /// # Example
    ///
    /// ```
    /// use octarine::data::Data;
    ///
    /// let data = Data::new();
    ///
    /// // Normalize URL paths
    /// let network = data.network();
    /// let normalized = network.normalize("/api/../users/./profile");
    /// ```
    #[must_use]
    pub fn network(&self) -> UrlNormalizationBuilder {
        UrlNormalizationBuilder::new()
    }

    /// Create a text builder for the given input
    ///
    /// Provides sanitization and detection for:
    /// - Control character detection and removal
    /// - ANSI escape sequence stripping
    /// - Log injection prevention
    /// - Unicode normalization (NFC, NFKC)
    /// - Zero-width character detection
    ///
    /// # Example
    ///
    /// ```
    /// use octarine::data::Data;
    ///
    /// let data = Data::new();
    ///
    /// // Sanitize text for safe logging
    /// let text = data.text("user\x00input\nwith\tcontrol");
    /// let safe = text.sanitize_for_log().finish();
    /// ```
    #[must_use]
    pub fn text<'a>(&self, input: &'a str) -> TextBuilder<'a> {
        TextBuilder::new(input)
    }

    /// Access format parsing operations (requires `formats` feature)
    ///
    /// Provides parsing and serialization for:
    /// - JSON parsing and serialization
    /// - XML parsing and serialization
    /// - YAML parsing and serialization
    /// - Format detection
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::data::Data;
    ///
    /// let data = Data::new();
    ///
    /// // Parse JSON
    /// let formats = data.formats();
    /// let value: serde_json::Value = formats.parse_json(r#"{"key": "value"}"#).unwrap();
    ///
    /// // Detect format
    /// let detected = formats.detect_format(content);
    /// ```
    #[cfg(feature = "formats")]
    #[must_use]
    pub fn formats(&self) -> FormatBuilder {
        FormatBuilder::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_facade_creation() {
        let data = Data::new();
        // Verify we can access each builder
        let _ = data.paths();
        let _ = data.network();
        let _ = data.text("test input");
    }

    #[test]
    fn test_data_is_copy() {
        let data = Data::new();
        let copy = data;
        let _ = data.paths();
        let _ = copy.paths();
    }

    #[test]
    fn test_data_is_default() {
        let data = Data;
        let _ = data.paths();
    }

    #[test]
    fn test_paths_operations() {
        let data = Data::new();
        let paths = data.paths();

        assert!(paths.is_absolute("/home/user"));
        assert!(!paths.is_absolute("relative/path"));
    }

    #[test]
    fn test_text_operations() {
        let data = Data::new();
        let text = data.text("test\x00null");

        // Test sanitization
        let safe = text.sanitize_for_log().finish();
        assert!(!safe.contains('\x00'));
    }

    #[cfg(feature = "formats")]
    #[test]
    #[allow(clippy::expect_used)]
    fn test_formats_operations() {
        let data = Data::new();
        let formats = data.formats();

        let result: serde_json::Value = formats
            .parse_json(r#"{"key": "value"}"#)
            .expect("valid JSON should parse");
        assert_eq!(result.get("key").and_then(|v| v.as_str()), Some("value"));
    }
}

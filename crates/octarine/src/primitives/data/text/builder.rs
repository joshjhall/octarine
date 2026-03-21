//! Text Builder
//!
//! Fluent builder API for text detection and sanitization operations.
//!
//! # Example
//!
//! ```rust,ignore
//! use crate::primitives::data::text::{TextBuilder, TextConfig};
//!
//! // Detection
//! let has_issues = TextBuilder::new("user\x00input")
//!     .is_control_chars_present();
//!
//! // Transform chain
//! let safe = TextBuilder::new("input\nwith\x1B[31mcolors")
//!     .sanitize_for_log()
//!     .strip_ansi()
//!     .truncate(100)
//!     .finish();
//!
//! // With custom config
//! let config = TextConfig::strict();
//! let safe = TextBuilder::new(input)
//!     .with_config(config)
//!     .sanitize_for_log()
//!     .finish();
//! ```

// Allow dead_code: These are Layer 1 primitives that will be used by observe module
#![allow(dead_code)]

use std::borrow::Cow;

use super::control;
use super::log::{self, TextConfig};
use super::unicode;

// ============================================================================
// TextBuilder
// ============================================================================

/// Fluent builder for text detection and sanitization operations
///
/// Provides a chainable API for:
/// - **Detection**: Check for dangerous characters, patterns (`is_*`)
/// - **Transformation**: Sanitize, strip, escape, truncate (`sanitize_*`, `strip_*`)
/// - **Finish**: Extract the processed text (`finish`, `into_string`)
///
/// # Naming Conventions
///
/// - `is_*` → `bool` (detection, does not modify text)
/// - `detect_*` → `Vec<T>` (find all occurrences)
/// - `count_*` → `usize` (count occurrences)
/// - `sanitize_*`, `strip_*`, `escape_*`, `truncate` → `Self` (chainable transform)
///
/// # Example
///
/// ```rust,ignore
/// use crate::primitives::data::text::{TextBuilder, TextConfig};
///
/// // Check and transform
/// let builder = TextBuilder::new(user_input);
/// if builder.is_dangerous_control_chars_present() {
///     let safe = builder.sanitize_for_log().finish();
/// }
///
/// // With config
/// let safe = TextBuilder::new(input)
///     .with_config(TextConfig::strict())
///     .sanitize_for_log()
///     .finish();
/// ```
#[derive(Debug, Clone)]
pub struct TextBuilder<'a> {
    text: Cow<'a, str>,
    config: TextConfig,
}

impl<'a> TextBuilder<'a> {
    // ========================================================================
    // Construction
    // ========================================================================

    /// Create a new text builder with the given input
    #[inline]
    pub fn new(input: &'a str) -> Self {
        Self {
            text: Cow::Borrowed(input),
            config: TextConfig::default(),
        }
    }

    /// Create a text builder from an owned String
    #[inline]
    pub fn from_string(input: String) -> TextBuilder<'static> {
        TextBuilder {
            text: Cow::Owned(input),
            config: TextConfig::default(),
        }
    }

    // ========================================================================
    // Configuration
    // ========================================================================

    /// Use custom configuration
    #[must_use]
    pub fn with_config(mut self, config: TextConfig) -> Self {
        self.config = config;
        self
    }

    /// Use strict configuration (escape everything, ASCII only, length limited)
    #[must_use]
    pub fn with_strict_config(mut self) -> Self {
        self.config = TextConfig::strict();
        self
    }

    /// Use relaxed configuration (allow newlines, keep unicode)
    #[must_use]
    pub fn with_relaxed_config(mut self) -> Self {
        self.config = TextConfig::relaxed();
        self
    }

    /// Use JSON-safe configuration (escape for JSON string embedding)
    #[must_use]
    pub fn with_json_config(mut self) -> Self {
        self.config = TextConfig::json_safe();
        self
    }

    /// Get the current configuration
    #[inline]
    pub fn config(&self) -> &TextConfig {
        &self.config
    }

    // ========================================================================
    // Detection (is_* -> bool)
    // ========================================================================

    /// Check if text contains any control characters (ASCII 0x00-0x1F, 0x7F)
    #[inline]
    pub fn is_control_chars_present(&self) -> bool {
        control::is_control_chars_present(&self.text)
    }

    /// Check if text contains dangerous control characters (excludes tab, newline, CR)
    #[inline]
    pub fn is_dangerous_control_chars_present(&self) -> bool {
        control::is_dangerous_control_chars_present(&self.text)
    }

    /// Check if text contains null bytes
    #[inline]
    pub fn is_null_bytes_present(&self) -> bool {
        control::is_null_bytes_present(&self.text)
    }

    /// Check if text contains ANSI escape sequences
    #[inline]
    pub fn is_ansi_escapes_present(&self) -> bool {
        control::is_ansi_escapes_present(&self.text)
    }

    /// Check if text contains CRLF sequences (newlines or carriage returns)
    #[inline]
    pub fn is_crlf_present(&self) -> bool {
        control::is_crlf_present(&self.text)
    }

    /// Check if text contains newlines only
    #[inline]
    pub fn is_newlines_present(&self) -> bool {
        control::is_newlines_present(&self.text)
    }

    /// Check if text contains carriage returns only
    #[inline]
    pub fn is_carriage_returns_present(&self) -> bool {
        control::is_carriage_returns_present(&self.text)
    }

    /// Check if text contains cursor control sequences
    #[inline]
    pub fn is_cursor_controls_present(&self) -> bool {
        control::is_cursor_controls_present(&self.text)
    }

    /// Check if text contains bell characters
    #[inline]
    pub fn is_bell_present(&self) -> bool {
        control::is_bell_present(&self.text)
    }

    /// Check if text contains backspace characters
    #[inline]
    pub fn is_backspace_present(&self) -> bool {
        control::is_backspace_present(&self.text)
    }

    /// Check if text contains zero-width characters
    #[inline]
    pub fn is_zero_width_chars_present(&self) -> bool {
        control::is_zero_width_chars_present(&self.text)
    }

    /// Check if text contains bidirectional override characters
    #[inline]
    pub fn is_bidi_overrides_present(&self) -> bool {
        control::is_bidi_overrides_present(&self.text)
    }

    /// Check if text is safe for log output (no modifications needed)
    #[inline]
    pub fn is_log_safe(&self) -> bool {
        log::is_log_safe(&self.text)
    }

    // ========================================================================
    // Unicode Detection (is_* -> bool)
    // ========================================================================

    /// Check if text contains mixed scripts (potential homograph attack)
    ///
    /// Returns true if the text contains characters from multiple scripts
    /// that could be used for spoofing (e.g., Cyrillic mixed with Latin).
    #[inline]
    pub fn is_mixed_script_present(&self) -> bool {
        unicode::is_mixed_script_present(&self.text)
    }

    /// Check if text uses only a single script (safe for identifiers)
    #[inline]
    pub fn is_single_script(&self) -> bool {
        unicode::is_single_script(&self.text)
    }

    /// Check if text contains confusable characters
    #[inline]
    pub fn is_confusable_chars_present(&self) -> bool {
        unicode::is_confusable_chars_present(&self.text)
    }

    /// Check if text contains format control characters
    #[inline]
    pub fn is_format_chars_present(&self) -> bool {
        unicode::is_format_chars_present(&self.text)
    }

    /// Check if text contains private use area characters
    #[inline]
    pub fn is_private_use_present(&self) -> bool {
        unicode::is_private_use_present(&self.text)
    }

    /// Check if text is already in NFC normalized form
    #[inline]
    pub fn is_nfc(&self) -> bool {
        unicode::is_nfc(&self.text)
    }

    /// Check if text is already in NFKC normalized form
    #[inline]
    pub fn is_nfkc(&self) -> bool {
        unicode::is_nfkc(&self.text)
    }

    /// Check if text is Unicode-secure (no threats detected)
    #[inline]
    pub fn is_unicode_secure(&self) -> bool {
        unicode::is_unicode_secure(&self.text)
    }

    /// Check if a string is confusable with this text
    #[inline]
    pub fn is_confusable_with(&self, other: &str) -> bool {
        unicode::is_confusable_with(&self.text, other)
    }

    /// Check if text is safe for use as an identifier
    #[inline]
    pub fn is_identifier_safe(&self) -> bool {
        unicode::is_identifier_safe(&self.text)
    }

    // ========================================================================
    // Detection (detect_* -> Vec, count_* -> usize)
    // ========================================================================

    /// Detect positions of all control characters
    #[inline]
    pub fn detect_control_char_positions(&self) -> Vec<usize> {
        control::detect_control_char_positions(&self.text)
    }

    /// Count the number of control characters
    #[inline]
    pub fn count_control_chars(&self) -> usize {
        control::count_control_chars(&self.text)
    }

    /// Perform comprehensive Unicode security analysis
    #[inline]
    pub fn detect_unicode_threats(&self) -> unicode::UnicodeSecurityResult {
        unicode::detect_unicode_threats(&self.text)
    }

    /// Get the skeleton of the text for confusable comparison
    #[inline]
    pub fn skeleton(&self) -> String {
        unicode::skeleton(&self.text)
    }

    // ========================================================================
    // Transform (chainable, modifies internal text)
    // ========================================================================

    /// Sanitize text for safe log output using current config
    #[must_use]
    pub fn sanitize_for_log(mut self) -> Self {
        let sanitized = log::sanitize_for_log_with_config(&self.text, &self.config);
        self.text = Cow::Owned(sanitized.into_owned());
        self
    }

    /// Strip ANSI escape sequences
    #[must_use]
    pub fn strip_ansi(mut self) -> Self {
        let stripped = log::strip_ansi_escapes(&self.text);
        self.text = Cow::Owned(stripped.into_owned());
        self
    }

    /// Strip dangerous control characters (keeps tab, newline, CR)
    #[must_use]
    pub fn strip_control_chars(mut self) -> Self {
        let stripped = log::strip_control_chars(&self.text);
        self.text = Cow::Owned(stripped.into_owned());
        self
    }

    /// Escape line breaks as literal \n and \r
    #[must_use]
    pub fn escape_line_breaks(mut self) -> Self {
        let escaped = log::escape_line_breaks(&self.text);
        self.text = Cow::Owned(escaped.into_owned());
        self
    }

    /// Truncate text to maximum length with suffix
    #[must_use]
    pub fn truncate(mut self, max_length: usize) -> Self {
        let truncated =
            log::truncate_for_log(&self.text, max_length, self.config.truncation_suffix);
        self.text = Cow::Owned(truncated.into_owned());
        self
    }

    /// Truncate text with custom suffix
    #[must_use]
    pub fn truncate_with_suffix(mut self, max_length: usize, suffix: &str) -> Self {
        let truncated = log::truncate_for_log(&self.text, max_length, suffix);
        self.text = Cow::Owned(truncated.into_owned());
        self
    }

    // ========================================================================
    // Unicode Transform (chainable, modifies internal text)
    // ========================================================================

    /// Normalize text to NFC (Canonical Composition)
    ///
    /// NFC is the recommended default normalization form.
    #[must_use]
    pub fn normalize_nfc(mut self) -> Self {
        let normalized = unicode::normalize_nfc(&self.text);
        self.text = Cow::Owned(normalized);
        self
    }

    /// Normalize text to NFKC (Compatibility Composition)
    ///
    /// NFKC is more aggressive than NFC - also handles ligatures, width variants.
    #[must_use]
    pub fn normalize_nfkc(mut self) -> Self {
        let normalized = unicode::normalize_nfkc(&self.text);
        self.text = Cow::Owned(normalized);
        self
    }

    /// Normalize text to NFD (Canonical Decomposition)
    #[must_use]
    pub fn normalize_nfd(mut self) -> Self {
        let normalized = unicode::normalize_nfd(&self.text);
        self.text = Cow::Owned(normalized);
        self
    }

    /// Normalize text to NFKD (Compatibility Decomposition)
    #[must_use]
    pub fn normalize_nfkd(mut self) -> Self {
        let normalized = unicode::normalize_nfkd(&self.text);
        self.text = Cow::Owned(normalized);
        self
    }

    /// Strip format control characters (invisible chars like zero-width joiners)
    #[must_use]
    pub fn strip_format_chars(mut self) -> Self {
        let stripped = unicode::strip_format_chars(&self.text);
        self.text = Cow::Owned(stripped);
        self
    }

    /// Strip zero-width characters
    #[must_use]
    pub fn strip_zero_width(mut self) -> Self {
        let stripped = unicode::strip_zero_width(&self.text);
        self.text = Cow::Owned(stripped);
        self
    }

    /// Strip bidirectional override characters
    #[must_use]
    pub fn strip_bidi_overrides(mut self) -> Self {
        let stripped = unicode::strip_bidi_overrides(&self.text);
        self.text = Cow::Owned(stripped);
        self
    }

    /// Sanitize text for Unicode security
    ///
    /// Removes format characters, private use characters, and normalizes to NFC.
    #[must_use]
    pub fn sanitize_unicode(mut self) -> Self {
        let sanitized = unicode::sanitize_unicode(&self.text);
        self.text = Cow::Owned(sanitized);
        self
    }

    // ========================================================================
    // Finish
    // ========================================================================

    /// Get the current text as a reference
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Finish and return the processed text
    #[inline]
    pub fn finish(self) -> Cow<'a, str> {
        self.text
    }

    /// Finish and return as owned String
    #[inline]
    pub fn into_string(self) -> String {
        self.text.into_owned()
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
    fn test_detection_control_chars() {
        assert!(TextBuilder::new("hello\x00world").is_control_chars_present());
        assert!(!TextBuilder::new("hello world").is_control_chars_present());
    }

    #[test]
    fn test_detection_ansi() {
        assert!(TextBuilder::new("\x1B[31mred\x1B[0m").is_ansi_escapes_present());
        assert!(!TextBuilder::new("plain text").is_ansi_escapes_present());
    }

    #[test]
    fn test_detection_crlf() {
        assert!(TextBuilder::new("line1\nline2").is_crlf_present());
        assert!(TextBuilder::new("text\rmore").is_crlf_present());
        assert!(!TextBuilder::new("single line").is_crlf_present());
    }

    #[test]
    fn test_detection_log_safe() {
        assert!(TextBuilder::new("Hello, World!").is_log_safe());
        assert!(!TextBuilder::new("has\nnewline").is_log_safe());
    }

    #[test]
    fn test_count_control_chars() {
        assert_eq!(TextBuilder::new("hello").count_control_chars(), 0);
        assert_eq!(
            TextBuilder::new("hello\x00\x01world").count_control_chars(),
            2
        );
    }

    #[test]
    fn test_detect_positions() {
        let positions = TextBuilder::new("a\x00b\x01c").detect_control_char_positions();
        assert_eq!(positions, vec![1, 3]);
    }

    #[test]
    fn test_sanitize_for_log() {
        let result = TextBuilder::new("line1\nline2").sanitize_for_log().finish();
        assert_eq!(result, "line1\\nline2");
    }

    #[test]
    fn test_strip_ansi() {
        let result = TextBuilder::new("\x1B[31mred\x1B[0m text")
            .strip_ansi()
            .finish();
        assert_eq!(result, "red text");
    }

    #[test]
    fn test_strip_control_chars() {
        let result = TextBuilder::new("hello\x00\x07world")
            .strip_control_chars()
            .finish();
        assert_eq!(result, "helloworld");
    }

    #[test]
    fn test_escape_line_breaks() {
        let result = TextBuilder::new("line1\nline2\r\nline3")
            .escape_line_breaks()
            .finish();
        assert_eq!(result, "line1\\nline2\\r\\nline3");
    }

    #[test]
    fn test_truncate() {
        let result = TextBuilder::new("Hello, World!").truncate(10).finish();
        assert_eq!(result, "Hello, ...");
    }

    #[test]
    fn test_truncate_with_suffix() {
        let result = TextBuilder::new("Hello, World!")
            .truncate_with_suffix(12, "[...]")
            .finish();
        assert_eq!(result, "Hello, [...]");
    }

    #[test]
    fn test_chaining() {
        let result = TextBuilder::new("text\x1B[31m\nwith\x00issues")
            .strip_ansi()
            .strip_control_chars()
            .escape_line_breaks()
            .finish();
        assert_eq!(result, "text\\nwithissues");
    }

    #[test]
    fn test_with_strict_config() {
        let result = TextBuilder::new("Tab\there")
            .with_strict_config()
            .sanitize_for_log()
            .finish();
        assert_eq!(result, "Tab\\there");
    }

    #[test]
    fn test_with_relaxed_config() {
        let result = TextBuilder::new("line1\nline2")
            .with_relaxed_config()
            .sanitize_for_log()
            .finish();
        assert_eq!(result, "line1\nline2");
    }

    #[test]
    fn test_with_custom_config() {
        let config = TextConfig::default().with_max_length(15);
        let result = TextBuilder::new("This is a longer string")
            .with_config(config)
            .sanitize_for_log()
            .finish();
        assert!(result.len() <= 15);
    }

    #[test]
    fn test_combined_detection_and_transform() {
        let builder = TextBuilder::new("user\x00input");

        if builder.is_dangerous_control_chars_present() {
            let safe = builder.strip_control_chars().finish();
            assert_eq!(safe, "userinput");
        }
    }

    #[test]
    fn test_as_str() {
        let builder = TextBuilder::new("hello");
        assert_eq!(builder.as_str(), "hello");
    }

    #[test]
    fn test_into_string() {
        let result = TextBuilder::new("hello").sanitize_for_log().into_string();
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_from_string() {
        let owned = String::from("owned input");
        let result = TextBuilder::from_string(owned).sanitize_for_log().finish();
        assert_eq!(result, "owned input");
    }

    #[test]
    fn test_config_access() {
        let config = TextConfig::strict();
        let builder = TextBuilder::new("test").with_config(config);
        assert!(builder.config().escape_tabs);
    }
}

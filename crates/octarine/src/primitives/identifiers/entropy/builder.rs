//! Entropy identifier builder with configurable thresholds
//!
//! Provides a fluent API for configuring and running entropy-based detection,
//! consistent with other domain builders (Personal, Financial, etc.).

use super::detection::{
    detect_high_entropy_strings_with_config, is_high_entropy, is_high_entropy_base64,
    is_high_entropy_hex, is_high_entropy_with_config,
};
use super::types::EntropyConfig;
use crate::primitives::identifiers::types::IdentifierMatch;

/// Builder for entropy-based identifier detection
///
/// Wraps entropy detection functions with a configurable `EntropyConfig`.
/// Default thresholds: Base64 >= 4.5, Hex >= 3.0, min length 20.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::entropy::EntropyBuilder;
///
/// // Default thresholds
/// let builder = EntropyBuilder::new();
/// assert!(builder.is_high_entropy("aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0z"));
///
/// // Custom thresholds
/// let strict = EntropyBuilder::new()
///     .with_base64_threshold(5.0)
///     .with_hex_threshold(3.5);
/// ```
#[derive(Debug, Clone)]
pub struct EntropyBuilder {
    config: EntropyConfig,
}

impl Default for EntropyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyBuilder {
    /// Create a new EntropyBuilder with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: EntropyConfig::default(),
        }
    }

    // =========================================================================
    // Configuration Methods (fluent API)
    // =========================================================================

    /// Set the Base64 entropy threshold (default: 4.5)
    #[must_use]
    pub fn with_base64_threshold(mut self, threshold: f64) -> Self {
        self.config.base64_threshold = threshold;
        self
    }

    /// Set the Hex entropy threshold (default: 3.0)
    #[must_use]
    pub fn with_hex_threshold(mut self, threshold: f64) -> Self {
        self.config.hex_threshold = threshold;
        self
    }

    /// Set the minimum string length for analysis (default: 20)
    #[must_use]
    pub fn with_min_length(mut self, min_length: usize) -> Self {
        self.config.min_length = min_length;
        self
    }

    /// Enable or disable the digit penalty (default: true)
    #[must_use]
    pub fn with_digit_penalty(mut self, enabled: bool) -> Self {
        self.config.digit_penalty = enabled;
        self
    }

    /// Enable or disable known pattern exclusion (default: true)
    #[must_use]
    pub fn with_exclude_known(mut self, enabled: bool) -> Self {
        self.config.exclude_known_patterns = enabled;
        self
    }

    // =========================================================================
    // Detection Methods
    // =========================================================================

    /// Check if a string has high entropy using the configured thresholds
    #[must_use]
    pub fn is_high_entropy(&self, value: &str) -> bool {
        is_high_entropy_with_config(value, &self.config)
    }

    /// Check if a string has high entropy using the Base64 threshold
    ///
    /// Uses the default Base64 threshold regardless of builder config.
    #[must_use]
    pub fn is_high_entropy_base64(&self, value: &str) -> bool {
        is_high_entropy_base64(value)
    }

    /// Check if a string has high entropy using the Hex threshold
    ///
    /// Uses the default Hex threshold regardless of builder config.
    #[must_use]
    pub fn is_high_entropy_hex(&self, value: &str) -> bool {
        is_high_entropy_hex(value)
    }

    /// Detect high-entropy strings in text using the configured thresholds
    #[must_use]
    pub fn detect_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detect_high_entropy_strings_with_config(text, &self.config)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_default() {
        let builder = EntropyBuilder::new();
        // Default thresholds should match EntropyConfig defaults
        assert!((builder.config.base64_threshold - 4.5).abs() < f64::EPSILON);
        assert!((builder.config.hex_threshold - 3.0).abs() < f64::EPSILON);
        assert_eq!(builder.config.min_length, 20);
        assert!(builder.config.digit_penalty);
        assert!(builder.config.exclude_known_patterns);
    }

    #[test]
    fn test_builder_default_trait() {
        let builder = EntropyBuilder::default();
        assert!((builder.config.base64_threshold - 4.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fluent_base64_threshold() {
        let builder = EntropyBuilder::new().with_base64_threshold(5.0);
        assert!((builder.config.base64_threshold - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fluent_hex_threshold() {
        let builder = EntropyBuilder::new().with_hex_threshold(3.5);
        assert!((builder.config.hex_threshold - 3.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fluent_min_length() {
        let builder = EntropyBuilder::new().with_min_length(10);
        assert_eq!(builder.config.min_length, 10);
    }

    #[test]
    fn test_fluent_digit_penalty() {
        let builder = EntropyBuilder::new().with_digit_penalty(false);
        assert!(!builder.config.digit_penalty);
    }

    #[test]
    fn test_fluent_exclude_known() {
        let builder = EntropyBuilder::new().with_exclude_known(false);
        assert!(!builder.config.exclude_known_patterns);
    }

    #[test]
    fn test_fluent_chaining() {
        let builder = EntropyBuilder::new()
            .with_base64_threshold(5.0)
            .with_hex_threshold(3.5)
            .with_min_length(10)
            .with_digit_penalty(false)
            .with_exclude_known(false);
        assert!((builder.config.base64_threshold - 5.0).abs() < f64::EPSILON);
        assert!((builder.config.hex_threshold - 3.5).abs() < f64::EPSILON);
        assert_eq!(builder.config.min_length, 10);
        assert!(!builder.config.digit_penalty);
        assert!(!builder.config.exclude_known_patterns);
    }

    #[test]
    fn test_is_high_entropy_default() {
        let builder = EntropyBuilder::new();
        assert!(builder.is_high_entropy("aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0z"));
        assert!(!builder.is_high_entropy("hello"));
    }

    #[test]
    fn test_is_high_entropy_strict_threshold() {
        let builder = EntropyBuilder::new().with_base64_threshold(5.5);
        // Moderate entropy string should fail with strict threshold
        assert!(!builder.is_high_entropy("abcdefghijklmnopqrst"));
    }

    #[test]
    fn test_is_high_entropy_loose_threshold() {
        let builder = EntropyBuilder::new()
            .with_base64_threshold(2.0)
            .with_min_length(10);
        // Even moderate strings pass loose threshold
        assert!(builder.is_high_entropy("abcdefghijk"));
    }

    #[test]
    fn test_detect_in_text_default() {
        let builder = EntropyBuilder::new();
        let text = r#"val = "Rq7mX9nB3pL2wK8jF5hT4vD6cE1fG0aH""#;
        let matches = builder.detect_in_text(text);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_detect_in_text_custom_config() {
        let builder = EntropyBuilder::new()
            .with_base64_threshold(2.0)
            .with_min_length(10);
        let text = "token abcdefghijk";
        let matches = builder.detect_in_text(text);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_detect_in_text_empty() {
        let builder = EntropyBuilder::new();
        assert!(builder.detect_in_text("").is_empty());
    }

    #[test]
    fn test_is_high_entropy_base64_method() {
        let builder = EntropyBuilder::new();
        assert!(builder.is_high_entropy_base64("odJFCrnl2edlBDdz1C5Jau2RJtBRnlWmTSHf6pW"));
        assert!(!builder.is_high_entropy_base64("short"));
    }

    #[test]
    fn test_is_high_entropy_hex_method() {
        let builder = EntropyBuilder::new();
        assert!(builder.is_high_entropy_hex("a3f8b2c9e1d047569ab8cd3ef0123456"));
        assert!(!builder.is_high_entropy_hex("short"));
    }
}

//! Confidence scoring builder with configurable context analysis
//!
//! Provides a fluent API for configuring and running context-aware confidence
//! scoring, consistent with other domain builders (Entropy, Personal, etc.).

use super::context::ContextAnalyzer;
use super::types::ContextConfig;
use crate::primitives::identifiers::IdentifierType;
use crate::primitives::identifiers::common::KeywordLanguage;

/// Builder for context-aware confidence scoring
///
/// Wraps `ContextAnalyzer` with a fluent configuration API.
/// Default configuration uses Presidio defaults (window: 100, boost: 0.35).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::confidence::ConfidenceBuilder;
/// use octarine::primitives::identifiers::IdentifierType;
///
/// // Default configuration
/// let builder = ConfidenceBuilder::new();
/// let score = builder.analyze("SSN: 123-45-6789", 5, 16, &IdentifierType::Ssn);
///
/// // Custom configuration
/// let custom = ConfidenceBuilder::new()
///     .with_window_size(50)
///     .with_boost_factor(0.5);
/// ```
#[derive(Debug, Clone)]
pub struct ConfidenceBuilder {
    config: ContextConfig,
}

impl Default for ConfidenceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfidenceBuilder {
    /// Create a new ConfidenceBuilder with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ContextConfig::default(),
        }
    }

    // =========================================================================
    // Configuration Methods (fluent API)
    // =========================================================================

    /// Set the context window size in characters (default: 100)
    ///
    /// Controls how many characters before and after the match are searched
    /// for contextual keywords.
    #[must_use]
    pub fn with_window_size(mut self, size: usize) -> Self {
        self.config.window_size = size;
        self
    }

    /// Set the confidence boost factor (default: 0.35)
    ///
    /// The additive boost applied to the base confidence score when
    /// context keywords are found.
    #[must_use]
    pub fn with_boost_factor(mut self, factor: f64) -> Self {
        self.config.boost_factor = factor;
        self
    }

    /// Restrict keyword matching to a single language (default: all languages)
    ///
    /// Without a hint every language's keyword table is scanned. A hint narrows
    /// matching to the named language, raising precision on a corpus whose
    /// language is known.
    #[must_use]
    pub fn with_language(mut self, language: KeywordLanguage) -> Self {
        self.config.language = Some(language);
        self
    }

    /// Restrict keyword matching to the language named by a tag.
    ///
    /// Accepts ISO 639-1 codes and BCP-47 tags case-insensitively (`"it"`,
    /// `"it-IT"`, `"zh-Hans"`). An **unrecognized tag leaves the analyzer
    /// unhinted** — scanning all languages — rather than matching nothing, so a
    /// typo'd hint degrades to the default instead of silently suppressing
    /// every context boost.
    #[must_use]
    pub fn with_language_hint(mut self, tag: impl AsRef<str>) -> Self {
        if let Some(language) = KeywordLanguage::from_tag(tag.as_ref()) {
            self.config.language = Some(language);
        }
        self
    }

    /// Set the maximum confidence score (default: 0.95)
    ///
    /// Caps the boosted confidence to prevent false certainty.
    #[must_use]
    pub fn with_max_confidence(mut self, max: f64) -> Self {
        self.config.max_confidence = max;
        self
    }

    // =========================================================================
    // Analysis Methods
    // =========================================================================

    /// Analyze context around a match and return a confidence score.
    ///
    /// Delegates to `ContextAnalyzer::analyze` with the configured settings.
    #[must_use]
    pub fn analyze(
        &self,
        text: &str,
        match_start: usize,
        match_end: usize,
        entity_type: &IdentifierType,
    ) -> f64 {
        let analyzer = ContextAnalyzer::with_config(self.config.clone());
        analyzer.analyze(text, match_start, match_end, entity_type)
    }

    /// Check whether context keywords are present near the match.
    ///
    /// Delegates to `ContextAnalyzer::is_context_present` with the configured settings.
    #[must_use]
    pub fn is_context_present(
        &self,
        text: &str,
        match_start: usize,
        match_end: usize,
        entity_type: &IdentifierType,
    ) -> bool {
        let analyzer = ContextAnalyzer::with_config(self.config.clone());
        analyzer.is_context_present(text, match_start, match_end, entity_type)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_default() {
        let builder = ConfidenceBuilder::new();
        assert_eq!(builder.config.window_size, 100);
        assert!((builder.config.boost_factor - 0.35).abs() < f64::EPSILON);
        assert!((builder.config.max_confidence - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_builder_default_trait() {
        let builder = ConfidenceBuilder::default();
        assert_eq!(builder.config.window_size, 100);
    }

    #[test]
    fn test_fluent_window_size() {
        let builder = ConfidenceBuilder::new().with_window_size(50);
        assert_eq!(builder.config.window_size, 50);
    }

    #[test]
    fn test_fluent_boost_factor() {
        let builder = ConfidenceBuilder::new().with_boost_factor(0.5);
        assert!((builder.config.boost_factor - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fluent_max_confidence() {
        let builder = ConfidenceBuilder::new().with_max_confidence(0.9);
        assert!((builder.config.max_confidence - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fluent_chaining() {
        let builder = ConfidenceBuilder::new()
            .with_window_size(200)
            .with_boost_factor(0.25)
            .with_max_confidence(0.8);
        assert_eq!(builder.config.window_size, 200);
        assert!((builder.config.boost_factor - 0.25).abs() < f64::EPSILON);
        assert!((builder.config.max_confidence - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_analyze_with_context() {
        let builder = ConfidenceBuilder::new();
        let text = "SSN: 123-45-6789";
        let score = builder.analyze(text, 5, 16, &IdentifierType::Ssn);
        assert!(score > 0.5, "Expected boosted score, got {}", score);
    }

    #[test]
    fn test_analyze_without_context() {
        let builder = ConfidenceBuilder::new();
        let text = "code: 123-45-6789";
        let score = builder.analyze(text, 6, 17, &IdentifierType::Ssn);
        assert!(
            (score - 0.5).abs() < f64::EPSILON,
            "Expected base confidence, got {}",
            score
        );
    }

    #[test]
    fn test_analyze_custom_config() {
        let builder = ConfidenceBuilder::new()
            .with_boost_factor(0.25)
            .with_max_confidence(0.8);
        let text = "SSN: 123-45-6789";
        let score = builder.analyze(text, 5, 16, &IdentifierType::Ssn);
        let expected = 0.5 + 0.25;
        assert!(
            (score - expected).abs() < f64::EPSILON,
            "Expected {}, got {}",
            expected,
            score
        );
    }

    #[test]
    fn test_is_context_present_true() {
        let builder = ConfidenceBuilder::new();
        let text = "social security number: 123-45-6789";
        assert!(builder.is_context_present(text, 24, 35, &IdentifierType::Ssn));
    }

    #[test]
    fn test_is_context_present_false() {
        let builder = ConfidenceBuilder::new();
        let text = "the number is 123-45-6789";
        assert!(!builder.is_context_present(text, 14, 25, &IdentifierType::Ssn));
    }

    #[test]
    fn test_custom_window_size_affects_detection() {
        // With narrow window, keyword outside range should not match
        let narrow = ConfidenceBuilder::new().with_window_size(3);
        let text = "ssn                 123-45-6789";
        assert!(!narrow.is_context_present(text, 20, 31, &IdentifierType::Ssn));

        // With wide window, same keyword should match
        let wide = ConfidenceBuilder::new().with_window_size(25);
        assert!(wide.is_context_present(text, 20, 31, &IdentifierType::Ssn));
    }

    #[test]
    fn test_with_language_filters() {
        let text = "codice fiscale: RSSMRA85T10A562S";

        let italian = ConfidenceBuilder::new().with_language(KeywordLanguage::It);
        assert!(italian.is_context_present(text, 16, 32, &IdentifierType::ItalyFiscalCode));

        // A different language must NOT match — proves the hint filters.
        let swedish = ConfidenceBuilder::new().with_language(KeywordLanguage::Sv);
        assert!(!swedish.is_context_present(text, 16, 32, &IdentifierType::ItalyFiscalCode));
    }

    #[test]
    fn test_with_language_hint_parses_tags() {
        let text = "codice fiscale: RSSMRA85T10A562S";
        for tag in ["it", "IT", "it-IT", "it_it", " it "] {
            let builder = ConfidenceBuilder::new().with_language_hint(tag);
            assert!(
                builder.is_context_present(text, 16, 32, &IdentifierType::ItalyFiscalCode),
                "tag {tag:?} should resolve to Italian"
            );
        }
    }

    #[test]
    fn test_unknown_language_hint_falls_back_to_all() {
        // An unrecognized tag must leave the builder unhinted, not match
        // nothing. Italian text still matches via the scan-all default.
        let builder = ConfidenceBuilder::new().with_language_hint("klingon");
        let text = "codice fiscale: RSSMRA85T10A562S";
        assert!(builder.is_context_present(text, 16, 32, &IdentifierType::ItalyFiscalCode));
    }

    #[test]
    fn test_language_hint_affects_the_score_path_too() {
        // The hint tests above all go through is_context_present; assert the
        // score-producing path honors it as well.
        let text = "codice fiscale: RSSMRA85T10A562S";

        let italian = ConfidenceBuilder::new().with_language(KeywordLanguage::It);
        assert!(italian.analyze(text, 16, 32, &IdentifierType::ItalyFiscalCode) > 0.5);

        let swedish = ConfidenceBuilder::new().with_language(KeywordLanguage::Sv);
        let score = swedish.analyze(text, 16, 32, &IdentifierType::ItalyFiscalCode);
        assert!(
            (score - 0.5).abs() < f64::EPSILON,
            "wrong-language hint should leave base confidence, got {score}"
        );
    }

    #[test]
    fn test_unknown_hint_does_not_clear_a_prior_hint() {
        // A bad tag after a good one must not silently widen the scan back to
        // all languages — the earlier explicit choice wins.
        let builder = ConfidenceBuilder::new()
            .with_language(KeywordLanguage::Sv)
            .with_language_hint("nonsense");
        let text = "codice fiscale: RSSMRA85T10A562S";
        assert!(!builder.is_context_present(text, 16, 32, &IdentifierType::ItalyFiscalCode));
    }
}

//! Confidence scoring builder with configurable context analysis
//!
//! Provides a fluent API for configuring and running context-aware confidence
//! scoring, consistent with other domain builders (Entropy, Personal, etc.).

use super::context::ContextAnalyzer;
use super::types::ContextConfig;
use crate::primitives::identifiers::IdentifierType;

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
}

//! Context-aware confidence scoring via keyword matching
//!
//! Examines text windows around identifier matches and boosts confidence
//! when contextual keywords are found nearby. Implements the Presidio-style
//! context enhancement approach.

use super::keywords::context_keywords;
use super::types::ContextConfig;
use crate::primitives::identifiers::IdentifierType;

// ============================================================================
// ContextAnalyzer
// ============================================================================

/// Analyzes text surrounding identifier matches for contextual keywords.
///
/// When keywords like "social security" appear near a pattern matching
/// `123-45-6789`, the confidence that this is a real SSN increases
/// significantly.
///
/// # Algorithm
///
/// 1. Extract a text window (configurable size) before and after the match
/// 2. Lowercase the window for case-insensitive matching
/// 3. Check if any keyword from the entity's dictionary appears in the window
/// 4. If found: boost confidence by `boost_factor`, capped at `max_confidence`
/// 5. If not found: return base confidence unchanged
///
/// A single boost is applied regardless of how many keywords match
/// (no double-boosting).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::confidence::ContextAnalyzer;
/// use octarine::primitives::identifiers::IdentifierType;
///
/// let analyzer = ContextAnalyzer::new();
///
/// // "social security" nearby → boosted confidence
/// let text = "My social security number is 123-45-6789";
/// let score = analyzer.analyze(text, 29, 40, &IdentifierType::Ssn);
/// assert!(score > 0.5); // Boosted above base
///
/// // No context → base confidence
/// let text = "The code is 123-45-6789";
/// let score = analyzer.analyze(text, 12, 23, &IdentifierType::Ssn);
/// assert!((score - 0.5).abs() < f64::EPSILON); // Base confidence
/// ```
#[derive(Debug, Clone)]
pub struct ContextAnalyzer {
    config: ContextConfig,
}

/// Base confidence score when no context is present.
const BASE_CONFIDENCE: f64 = 0.5;

impl Default for ContextAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextAnalyzer {
    /// Create a new analyzer with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ContextConfig::default(),
        }
    }

    /// Create a new analyzer with custom configuration.
    #[must_use]
    pub fn with_config(config: ContextConfig) -> Self {
        Self { config }
    }

    /// Analyze context around a match and return a confidence score.
    ///
    /// Returns a confidence score between 0.0 and `max_confidence`:
    /// - Base confidence (0.5) when no context keywords are found
    /// - Boosted confidence (base + boost_factor, capped) when keywords are found
    ///
    /// # Arguments
    ///
    /// * `text` - The full text being analyzed
    /// * `match_start` - Start byte offset of the identifier match
    /// * `match_end` - End byte offset of the identifier match
    /// * `entity_type` - The type of identifier that was matched
    #[must_use]
    pub fn analyze(
        &self,
        text: &str,
        match_start: usize,
        match_end: usize,
        entity_type: &IdentifierType,
    ) -> f64 {
        if self.has_keyword_in_window(text, match_start, match_end, entity_type) {
            // Boost and cap
            let boosted = BASE_CONFIDENCE + self.config.boost_factor;
            if boosted > self.config.max_confidence {
                self.config.max_confidence
            } else {
                boosted
            }
        } else {
            BASE_CONFIDENCE
        }
    }

    /// Check whether context keywords are present near the match.
    ///
    /// Returns `true` if at least one keyword from the entity's dictionary
    /// appears within the configured window around the match position.
    #[must_use]
    pub fn is_context_present(
        &self,
        text: &str,
        match_start: usize,
        match_end: usize,
        entity_type: &IdentifierType,
    ) -> bool {
        self.has_keyword_in_window(text, match_start, match_end, entity_type)
    }

    /// Internal: check if any keyword appears in the window around the match.
    fn has_keyword_in_window(
        &self,
        text: &str,
        match_start: usize,
        match_end: usize,
        entity_type: &IdentifierType,
    ) -> bool {
        let keywords = context_keywords(entity_type);
        if keywords.is_empty() {
            return false;
        }

        // Calculate window boundaries (byte offsets, clamped to text bounds)
        let window_start = match_start.saturating_sub(self.config.window_size);
        let window_end = match_end
            .saturating_add(self.config.window_size)
            .min(text.len());

        // Extract window text safely (handle UTF-8 boundaries)
        let window = match text.get(window_start..window_end) {
            Some(w) => w,
            None => {
                // Fall back to the full text if byte offsets are on char boundaries
                // that don't align. This is defensive — callers should provide
                // valid byte offsets from regex/pattern matches.
                return false;
            }
        };

        // Case-insensitive: lowercase the window (keywords are already lowercase)
        let window_lower = window.to_lowercase();

        // Check for any keyword — first match is sufficient (no double-boost)
        keywords.iter().any(|kw| window_lower.contains(kw))
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
    fn test_ssn_with_context() {
        let analyzer = ContextAnalyzer::new();
        let text = "My social security number is 123-45-6789";
        let score = analyzer.analyze(text, 29, 40, &IdentifierType::Ssn);
        assert!(
            score > BASE_CONFIDENCE,
            "Expected boosted score, got {}",
            score
        );
    }

    #[test]
    fn test_ssn_without_context() {
        let analyzer = ContextAnalyzer::new();
        let text = "The code is 123-45-6789 for reference";
        let score = analyzer.analyze(text, 12, 23, &IdentifierType::Ssn);
        assert!(
            (score - BASE_CONFIDENCE).abs() < f64::EPSILON,
            "Expected base confidence, got {}",
            score
        );
    }

    #[test]
    fn test_credit_card_with_context() {
        let analyzer = ContextAnalyzer::new();
        let text = "Please enter your credit card number: 4111-1111-1111-1111";
        let score = analyzer.analyze(text, 38, 57, &IdentifierType::CreditCard);
        assert!(score > BASE_CONFIDENCE);
    }

    #[test]
    fn test_case_insensitive() {
        let analyzer = ContextAnalyzer::new();
        let text = "SOCIAL SECURITY number: 123-45-6789";
        let score = analyzer.analyze(text, 24, 35, &IdentifierType::Ssn);
        assert!(
            score > BASE_CONFIDENCE,
            "Case-insensitive match should boost, got {}",
            score
        );
    }

    #[test]
    fn test_no_double_boost() {
        let analyzer = ContextAnalyzer::new();
        // Multiple keywords present: "ssn" and "social security"
        let text = "SSN / social security number: 123-45-6789";
        let score = analyzer.analyze(text, 30, 41, &IdentifierType::Ssn);

        // Should be exactly base + boost_factor, not double
        let expected = BASE_CONFIDENCE + 0.35;
        assert!(
            (score - expected).abs() < f64::EPSILON,
            "Expected single boost {}, got {}",
            expected,
            score
        );
    }

    #[test]
    fn test_window_boundary_inside() {
        // Keyword just inside the window → should match
        let config = ContextConfig {
            window_size: 20,
            ..ContextConfig::default()
        };
        let analyzer = ContextAnalyzer::with_config(config);

        // "ssn" at position 0-3, match at position 5-16
        let text = "ssn: 123-45-6789";
        assert!(analyzer.is_context_present(text, 5, 16, &IdentifierType::Ssn));
    }

    #[test]
    fn test_window_boundary_outside() {
        // Keyword outside the window → should not match
        let config = ContextConfig {
            window_size: 3,
            ..ContextConfig::default()
        };
        let analyzer = ContextAnalyzer::with_config(config);

        // "ssn" is at the start, but window of 3 chars before match at position 20
        // won't reach it
        let text = "ssn                 123-45-6789";
        assert!(!analyzer.is_context_present(text, 20, 31, &IdentifierType::Ssn));
    }

    #[test]
    fn test_unknown_type_no_keywords() {
        let analyzer = ContextAnalyzer::new();
        let text = "some random text with unknown identifier 12345";
        let score = analyzer.analyze(text, 41, 46, &IdentifierType::Unknown);
        assert!(
            (score - BASE_CONFIDENCE).abs() < f64::EPSILON,
            "Unknown type should return base confidence"
        );
    }

    #[test]
    fn test_is_context_present_true() {
        let analyzer = ContextAnalyzer::new();
        let text = "email address: user@example.com";
        assert!(analyzer.is_context_present(text, 15, 30, &IdentifierType::Email));
    }

    #[test]
    fn test_is_context_present_false() {
        let analyzer = ContextAnalyzer::new();
        let text = "contact: user@example.com";
        // "contact" is in the email keywords, so this should be true
        assert!(analyzer.is_context_present(text, 9, 25, &IdentifierType::Email));

        // No keywords at all
        let text = "here is user@example.com";
        assert!(!analyzer.is_context_present(text, 8, 24, &IdentifierType::Unknown));
    }

    #[test]
    fn test_max_confidence_cap() {
        let config = ContextConfig {
            boost_factor: 0.6,
            max_confidence: 0.9,
            ..ContextConfig::default()
        };
        let analyzer = ContextAnalyzer::with_config(config);

        let text = "ssn: 123-45-6789";
        let score = analyzer.analyze(text, 5, 16, &IdentifierType::Ssn);
        // base 0.5 + 0.6 = 1.1, capped at 0.9
        assert!(
            (score - 0.9).abs() < f64::EPSILON,
            "Score should be capped at max_confidence, got {}",
            score
        );
    }

    #[test]
    fn test_custom_config() {
        let config = ContextConfig {
            window_size: 200,
            boost_factor: 0.25,
            max_confidence: 0.8,
        };
        let analyzer = ContextAnalyzer::with_config(config);

        let text = "ssn: 123-45-6789";
        let score = analyzer.analyze(text, 5, 16, &IdentifierType::Ssn);
        let expected = BASE_CONFIDENCE + 0.25;
        assert!(
            (score - expected).abs() < f64::EPSILON,
            "Expected {}, got {}",
            expected,
            score
        );
    }

    #[test]
    fn test_default_impl() {
        let analyzer = ContextAnalyzer::default();
        let text = "ssn: 123-45-6789";
        let score = analyzer.analyze(text, 5, 16, &IdentifierType::Ssn);
        assert!(score > BASE_CONFIDENCE);
    }

    #[test]
    fn test_empty_text() {
        let analyzer = ContextAnalyzer::new();
        let score = analyzer.analyze("", 0, 0, &IdentifierType::Ssn);
        assert!(
            (score - BASE_CONFIDENCE).abs() < f64::EPSILON,
            "Empty text should return base confidence"
        );
    }

    #[test]
    fn test_keyword_after_match() {
        let analyzer = ContextAnalyzer::new();
        // Keyword appears after the match
        let text = "123-45-6789 is my social security number";
        let score = analyzer.analyze(text, 0, 11, &IdentifierType::Ssn);
        assert!(
            score > BASE_CONFIDENCE,
            "Keyword after match should boost, got {}",
            score
        );
    }
}

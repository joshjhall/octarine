//! Context-aware confidence scoring via keyword matching
//!
//! Examines text windows around identifier matches and boosts confidence
//! when contextual keywords are found nearby. Implements the Presidio-style
//! context enhancement approach.

use super::keywords::context_keywords;
use super::types::ContextConfig;
use crate::primitives::identifiers::IdentifierType;
use crate::primitives::identifiers::common::KeywordLanguage;

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

/// Whether `c` belongs to a script written without spaces between words.
///
/// Han, kana, hangul, and Thai text runs together, so there is no word boundary
/// to look for on that side of a match — a keyword abutting such a character is
/// a legitimate hit, not an accidental infix.
fn is_unspaced_script(c: char) -> bool {
    matches!(c,
        '\u{3040}'..='\u{30FF}'   // hiragana + katakana
        | '\u{3400}'..='\u{4DBF}' // CJK unified ideographs extension A
        | '\u{4E00}'..='\u{9FFF}' // CJK unified ideographs
        | '\u{F900}'..='\u{FAFF}' // CJK compatibility ideographs
        | '\u{AC00}'..='\u{D7AF}' // hangul syllables
        | '\u{1100}'..='\u{11FF}' // hangul jamo
        | '\u{0E00}'..='\u{0E7F}' // Thai
    )
}

/// Whether `keyword` occurs in `text` at word boundaries.
///
/// Plain substring matching over-fires on short keywords: French `"nom"` would
/// match inside `"nomination"`, and Turkish `"ad"` inside `"adres"`, boosting
/// confidence on text that says nothing about a name. Both keywords are correct
/// and worth keeping, so the boundary check lives here rather than the shorter
/// entries being deleted from the tables.
///
/// A boundary is the start/end of the text, a non-alphanumeric character, or a
/// character from a script written **without** spaces (Han, kana, hangul,
/// Thai). That last clause is what makes the rule safe for mixed-script
/// keywords: Japanese `"apiキー"` inside `"apiキーを教えてください"`, or a bare
/// `"iban"` inside `"您的iban账号是"`, have native characters — not spaces —
/// on either side, and would be rejected by a naive alphanumeric-only test.
/// The decision is made per **adjacent character**, not from the keyword's own
/// script, because a keyword may mix both.
///
/// `text` is expected to be already lowercased (the analyzer lowercases the
/// window); keywords are lowercase by table invariant.
fn is_keyword_in_text(text: &str, keyword: &str) -> bool {
    let is_boundary =
        |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric() || is_unspaced_script(c));

    text.match_indices(keyword).any(|(start, matched)| {
        let before = text.get(..start).and_then(|s| s.chars().next_back());
        let after = text
            .get(start.saturating_add(matched.len())..)
            .and_then(|s| s.chars().next());
        is_boundary(before) && is_boundary(after)
    })
}

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

    /// Restrict keyword matching to a single language.
    ///
    /// Without a hint the analyzer scans every language's table, matching any
    /// known keyword regardless of script. A hint narrows matching to the named
    /// language, which raises precision when the corpus language is known.
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::confidence::ContextAnalyzer;
    /// use octarine::primitives::identifiers::common::KeywordLanguage;
    /// use octarine::primitives::identifiers::IdentifierType;
    ///
    /// let analyzer = ContextAnalyzer::new().with_language(KeywordLanguage::It);
    /// let text = "codice fiscale: RSSMRA85T10A562S";
    /// assert!(analyzer.is_context_present(text, 16, 32, &IdentifierType::ItalyFiscalCode));
    /// ```
    #[must_use]
    pub fn with_language(mut self, language: KeywordLanguage) -> Self {
        self.config.language = Some(language);
        self
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
        if self.is_keyword_in_window_present(text, match_start, match_end, entity_type) {
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
        self.is_keyword_in_window_present(text, match_start, match_end, entity_type)
    }

    /// Internal: check if any keyword appears in the window around the match.
    fn is_keyword_in_window_present(
        &self,
        text: &str,
        match_start: usize,
        match_end: usize,
        entity_type: &IdentifierType,
    ) -> bool {
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

        // With a language hint, scan only that language's table. With no hint,
        // scan every language — matching any known keyword regardless of script,
        // preserving the pre-refactor behavior where non-Latin keywords lived in
        // the same list. First match is sufficient (no double-boost).
        let is_keyword_present = |language: KeywordLanguage| {
            context_keywords(entity_type, language)
                .iter()
                .any(|kw| is_keyword_in_text(&window_lower, kw))
        };

        match self.config.language {
            Some(language) => is_keyword_present(language),
            None => KeywordLanguage::all().any(is_keyword_present),
        }
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
            ..ContextConfig::default()
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
    fn test_short_keyword_does_not_match_inside_a_word() {
        // Turkish "ad" (name) must not boost on "adres" (address), and French
        // "nom" must not boost on "nomination". Under plain substring matching
        // both of these fire.
        let analyzer = ContextAnalyzer::new().with_language(KeywordLanguage::Tr);
        let text = "adres: 12345678901";
        assert!(!analyzer.is_context_present(text, 7, 18, &IdentifierType::PersonalName));

        let french = ContextAnalyzer::new().with_language(KeywordLanguage::Fr);
        let text = "nomination 12345678901";
        assert!(!french.is_context_present(text, 11, 22, &IdentifierType::PersonalName));
    }

    #[test]
    fn test_short_keyword_still_matches_as_a_whole_word() {
        // The boundary check must not cost recall: the same short keywords must
        // still match when they stand alone, including next to punctuation.
        let analyzer = ContextAnalyzer::new().with_language(KeywordLanguage::Tr);
        assert!(analyzer.is_context_present(
            "ad: Mehmet Yilmaz",
            4,
            17,
            &IdentifierType::PersonalName
        ));

        let french = ContextAnalyzer::new().with_language(KeywordLanguage::Fr);
        assert!(french.is_context_present(
            "nom: Jean Dupont",
            5,
            16,
            &IdentifierType::PersonalName
        ));
        // ...and at the very start/end of the window.
        assert!(french.is_context_present("Jean Dupont nom", 0, 11, &IdentifierType::PersonalName));
    }

    #[test]
    fn test_boundary_check_is_accent_aware() {
        // A boundary is any NON-alphanumeric char, and `char::is_alphanumeric`
        // is Unicode-aware — so an accented letter abutting the keyword is NOT
        // a boundary. German "name" must not match inside "nachnamen".
        let analyzer = ContextAnalyzer::new().with_language(KeywordLanguage::De);
        assert!(!analyzer.is_context_present(
            "nachnamen 123-45-6789",
            10,
            21,
            &IdentifierType::PersonalName
        ));
    }

    #[test]
    fn test_mixed_script_keyword_matches_glued_to_native_text() {
        // A keyword mixing ASCII with a non-spaced script ("apiキー", "api密钥")
        // sits flush against native characters in real sentences — there is no
        // space to find. Deciding the rule from the KEYWORD's script rather
        // than the ADJACENT character silently killed every one of these.
        let japanese = ContextAnalyzer::new().with_language(KeywordLanguage::Ja);
        assert!(japanese.is_context_present(
            "apiキーを教えてください sk_live_abcdef",
            34,
            51,
            &IdentifierType::ApiKey
        ));

        let chinese = ContextAnalyzer::new().with_language(KeywordLanguage::ZhHans);
        assert!(chinese.is_context_present(
            "api密钥是sk_live_abcdef",
            13,
            30,
            &IdentifierType::ApiKey
        ));
    }

    #[test]
    fn test_ascii_keyword_matches_inside_unspaced_text() {
        // A pure-ASCII keyword ("iban") in CJK text has native characters on
        // both sides, never spaces. It must still match.
        let chinese = ContextAnalyzer::new().with_language(KeywordLanguage::ZhHans);
        assert!(chinese.is_context_present(
            "您的iban账号是DE89370400440532013000",
            16,
            38,
            &IdentifierType::Iban
        ));
    }

    #[test]
    fn test_unspaced_boundary_does_not_leak_into_latin() {
        // The unspaced-script escape must not weaken the Latin rule: Turkish
        // "ad" is still rejected inside "adres", where the adjacent character
        // is a Latin letter, not a CJK one.
        let turkish = ContextAnalyzer::new().with_language(KeywordLanguage::Tr);
        assert!(!turkish.is_context_present(
            "adres: 12345678901",
            7,
            18,
            &IdentifierType::PersonalName
        ));
    }

    #[test]
    fn test_first_occurrence_invalid_later_one_valid() {
        // The match walk must not stop at the first boundary-failing hit:
        // "ad" is embedded in "adres" first, then stands alone.
        let turkish = ContextAnalyzer::new().with_language(KeywordLanguage::Tr);
        assert!(turkish.is_context_present(
            "adres yok, ad: Mehmet",
            15,
            21,
            &IdentifierType::PersonalName
        ));
    }

    #[test]
    fn test_non_spaced_scripts_still_substring_match() {
        // Japanese/Chinese/Thai have no word boundaries, so those keywords must
        // keep matching by substring — the boundary rule must not silently
        // disable every CJK keyword.
        let japanese = ContextAnalyzer::new().with_language(KeywordLanguage::Ja);
        assert!(japanese.is_context_present(
            "お客様の電話番号は090-1234-5678です",
            27,
            40,
            &IdentifierType::PhoneNumber
        ));

        let thai = ContextAnalyzer::new().with_language(KeywordLanguage::Th);
        assert!(thai.is_context_present(
            "เลขประจำตัวประชาชน 1234567890123",
            55,
            68,
            &IdentifierType::ThailandTnin
        ));
    }

    #[test]
    fn test_italian_hint_matches_italian_keyword() {
        // Acceptance criterion from #667: an Italian hint reports context for
        // an Italian codice fiscale label.
        let analyzer = ContextAnalyzer::new().with_language(KeywordLanguage::It);
        let text = "codice fiscale: RSSMRA85T10A562S";
        assert!(analyzer.is_context_present(text, 16, 32, &IdentifierType::ItalyFiscalCode));
    }

    #[test]
    fn test_wrong_language_hint_does_not_match() {
        // The hint must actually filter. A German hint on Italian text must NOT
        // report context — if `with_language` were a no-op this would still
        // match via the Italian table and the test would pass vacuously.
        let analyzer = ContextAnalyzer::new().with_language(KeywordLanguage::De);
        let text = "codice fiscale: RSSMRA85T10A562S";
        assert!(!analyzer.is_context_present(text, 16, 32, &IdentifierType::ItalyFiscalCode));
    }

    #[test]
    fn test_no_hint_scans_all_languages() {
        // Default behavior is unchanged: with no hint the same Italian text
        // matches, because every language table is scanned.
        let analyzer = ContextAnalyzer::new();
        let text = "codice fiscale: RSSMRA85T10A562S";
        assert!(analyzer.is_context_present(text, 16, 32, &IdentifierType::ItalyFiscalCode));
    }

    #[test]
    fn test_hint_still_matches_english_when_english() {
        // A hint narrows rather than disables: English text under an English
        // hint behaves exactly as the unhinted analyzer does.
        let analyzer = ContextAnalyzer::new().with_language(KeywordLanguage::En);
        let text = "social security number is 123-45-6789";
        assert!(analyzer.is_context_present(text, 26, 37, &IdentifierType::Ssn));

        // ...and the same English text under a Thai hint does not.
        let thai = ContextAnalyzer::new().with_language(KeywordLanguage::Th);
        assert!(!thai.is_context_present(text, 26, 37, &IdentifierType::Ssn));
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

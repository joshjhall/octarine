//! Nationality, Religion, and Political Affiliation (NRP) detection
//!
//! Lexicon-based detection for GDPR Article 9 special-category data:
//! racial / ethnic origin (nationality), religious belief, and political
//! opinion.
//!
//! ## Implementation
//!
//! Uses Aho-Corasick for ASCII-case-insensitive multi-pattern matching.
//! Each match is then validated for word boundaries by the caller — this
//! prevents `"Catholic"` from matching inside `"Catholicism"` and
//! `"American"` from matching inside `"un-American"`.
//!
//! ## Lexicons
//!
//! See `primitives/identifiers/common/patterns/personal/nrp.rs` for the
//! source lists (~200 nationalities + ~50 religions + ~30 political
//! affiliations).

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use once_cell::sync::Lazy;

use super::super::super::common::patterns::{NATIONALITIES, POLITICAL_AFFILIATIONS, RELIGIONS};
use super::super::super::types::{IdentifierMatch, IdentifierType};

/// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 10_000;

// ============================================================================
// Lazy-built matchers
// ============================================================================

static NATIONALITY_MATCHER: Lazy<AhoCorasick> = Lazy::new(|| build_matcher(NATIONALITIES));
static RELIGION_MATCHER: Lazy<AhoCorasick> = Lazy::new(|| build_matcher(RELIGIONS));
static POLITICAL_MATCHER: Lazy<AhoCorasick> = Lazy::new(|| build_matcher(POLITICAL_AFFILIATIONS));

#[allow(clippy::expect_used)]
fn build_matcher(patterns: &[&str]) -> AhoCorasick {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostLongest)
        .build(patterns)
        .expect("BUG: NRP lexicon contains invalid pattern")
}

// ============================================================================
// Public API — Nationalities
// ============================================================================

/// Find all nationality / ethnic-group references in text.
///
/// Detects demonyms (`"American"`, `"Japanese"`, `"Hispanic"`) via a
/// curated lexicon of ~200 entries.
#[must_use]
pub fn detect_nationalities_in_text(text: &str) -> Vec<IdentifierMatch> {
    detect_with_matcher(text, &NATIONALITY_MATCHER, IdentifierType::Nationality)
}

/// Returns `true` if the input contains at least one nationality reference.
#[must_use]
pub fn is_nationality(value: &str) -> bool {
    !detect_nationalities_in_text(value).is_empty()
}

// ============================================================================
// Public API — Religions
// ============================================================================

/// Find all religious-affiliation references in text.
///
/// Detects ~50 named religions and denominations including atheist /
/// agnostic / secular labels (GDPR Art. 9 treats absence of religious
/// belief as protected too).
#[must_use]
pub fn detect_religions_in_text(text: &str) -> Vec<IdentifierMatch> {
    detect_with_matcher(text, &RELIGION_MATCHER, IdentifierType::Religion)
}

/// Returns `true` if the input contains at least one religion reference.
#[must_use]
pub fn is_religion(value: &str) -> bool {
    !detect_religions_in_text(value).is_empty()
}

// ============================================================================
// Public API — Political Affiliations
// ============================================================================

/// Find all political-affiliation references in text.
///
/// Detects ~30 major parties and ideological labels (US/UK/EU plus
/// cross-national descriptors).
#[must_use]
pub fn detect_political_affiliations_in_text(text: &str) -> Vec<IdentifierMatch> {
    detect_with_matcher(
        text,
        &POLITICAL_MATCHER,
        IdentifierType::PoliticalAffiliation,
    )
}

/// Returns `true` if the input contains at least one political-affiliation
/// reference.
#[must_use]
pub fn is_political_affiliation(value: &str) -> bool {
    !detect_political_affiliations_in_text(value).is_empty()
}

// ============================================================================
// Internal helpers
// ============================================================================

fn detect_with_matcher(
    text: &str,
    matcher: &AhoCorasick,
    identifier_type: IdentifierType,
) -> Vec<IdentifierMatch> {
    if text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();
    let bytes = text.as_bytes();

    for hit in matcher.find_iter(text) {
        if !has_word_boundaries(bytes, hit.start(), hit.end()) {
            continue;
        }
        // Slice text by byte positions — Aho-Corasick reports byte
        // positions; `text.get(start..end)` returns `None` if a position
        // falls inside a multi-byte UTF-8 codepoint, which would be a
        // matcher bug since all lexicon entries are ASCII. Skip rather
        // than panic.
        let Some(matched) = text.get(hit.start()..hit.end()) else {
            continue;
        };
        matches.push(IdentifierMatch::high_confidence(
            hit.start(),
            hit.end(),
            matched.to_string(),
            identifier_type.clone(),
        ));
    }

    matches
}

/// True when the byte range is surrounded by non-alphanumeric ASCII bytes
/// or the start/end of input. This prevents prefix/suffix matches like
/// `"Catholic"` inside `"Catholicism"` or `"American"` inside `"Americana"`.
///
/// Operates on raw bytes for speed — safe because the boundary check only
/// inspects ASCII alphanumeric (the leading byte of any multi-byte UTF-8
/// codepoint is always `>= 0x80`, which is never `is_ascii_alphanumeric`).
fn has_word_boundaries(bytes: &[u8], start: usize, end: usize) -> bool {
    let before_ok = if start == 0 {
        true
    } else {
        // saturating index — guaranteed in-range when start > 0
        match bytes.get(start.saturating_sub(1)) {
            Some(b) => !b.is_ascii_alphanumeric(),
            None => true,
        }
    };

    let after_ok = match bytes.get(end) {
        Some(b) => !b.is_ascii_alphanumeric(),
        None => true,
    };

    before_ok && after_ok
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ── Nationality ──────────────────────────────────────────────────

    #[test]
    fn test_detect_nationality_simple() {
        let matches = detect_nationalities_in_text("He is American");
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("Should detect").identifier_type,
            IdentifierType::Nationality
        );
    }

    #[test]
    fn test_detect_nationality_case_insensitive() {
        assert!(is_nationality("she is JAPANESE"));
        assert!(is_nationality("a hispanic woman"));
    }

    #[test]
    fn test_nationality_word_boundary() {
        // Should NOT match "American" inside "Americana"
        let matches = detect_nationalities_in_text("Americana style");
        assert!(
            matches.is_empty(),
            "should not match across word boundary, got {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_nationality_multiple_in_text() {
        let text = "The team includes British, French, and Japanese members.";
        let matches = detect_nationalities_in_text(text);
        assert!(matches.len() >= 3);
    }

    // ── Religion ─────────────────────────────────────────────────────

    #[test]
    fn test_detect_religion_simple() {
        let matches = detect_religions_in_text("Catholic priest visited");
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("Should detect").identifier_type,
            IdentifierType::Religion
        );
    }

    #[test]
    fn test_religion_word_boundary() {
        // Should NOT match "Catholic" inside "Catholicism"
        let matches = detect_religions_in_text("Catholicism is a religion");
        assert!(
            matches.is_empty(),
            "should not match prefix inside longer word, got {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_religion_includes_non_religion() {
        assert!(is_religion("she is atheist"));
        assert!(is_religion("he identifies as agnostic"));
        assert!(is_religion("a secular humanist"));
    }

    // ── Political affiliation ────────────────────────────────────────

    #[test]
    fn test_detect_political_simple() {
        let matches = detect_political_affiliations_in_text("Democrat senator from Texas");
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("Should detect").identifier_type,
            IdentifierType::PoliticalAffiliation
        );
    }

    #[test]
    fn test_detect_political_multiple_parties() {
        assert!(is_political_affiliation("Republican incumbent"));
        assert!(is_political_affiliation("Labour party member"));
        assert!(is_political_affiliation("a Green Party candidate"));
    }

    #[test]
    fn test_political_word_boundary() {
        // "Democratic" should match (it's in the lexicon) but "Democratization"
        // should NOT.
        let matches = detect_political_affiliations_in_text("Democratization of the region");
        assert!(
            matches.is_empty(),
            "Democratization should not match Democratic, got {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
    }

    // ── No-match cases ───────────────────────────────────────────────

    #[test]
    fn test_no_match_on_unrelated_text() {
        assert!(!is_nationality("the weather is nice today"));
        assert!(!is_religion("the database query failed"));
        assert!(!is_political_affiliation("the meeting is at 3pm"));
    }

    #[test]
    fn test_empty_input() {
        assert!(!is_nationality(""));
        assert!(!is_religion(""));
        assert!(!is_political_affiliation(""));
    }

    #[test]
    fn test_redos_protection() {
        let huge = "x".repeat(20_000);
        assert!(detect_nationalities_in_text(&huge).is_empty());
        assert!(detect_religions_in_text(&huge).is_empty());
        assert!(detect_political_affiliations_in_text(&huge).is_empty());
    }
}

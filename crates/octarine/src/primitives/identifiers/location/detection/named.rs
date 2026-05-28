//! Free-text named-location detection (cities + countries)
//!
//! Aho-Corasick scanning over the [`gazetteer`] lexicon of ~280 countries
//! and ~1,500 major cities. Detects place names in arbitrary text without
//! requiring NER — the no-ML fallback path for HIPAA Safe Harbor
//! geographic-info redaction and the Presidio CRIT-2 parity gap.
//!
//! ## Confidence model
//!
//! - **High** — match + location-context keyword (`live in`, `visiting`,
//!   `from`, `located in`, `address`, etc.) within ±60 bytes of the match.
//! - **Medium** — match + no context keyword.
//! - **Low** — match is in [`AMBIGUOUS_PLACE_NAMES`] (common English word
//!   that is also a place name) and no context keyword present.
//!
//! Low-confidence matches are still returned so audit consumers see them;
//! redaction layers can filter on confidence.
//!
//! ## Word boundaries
//!
//! Matches are only accepted when both sides of the byte range are
//! non-alphanumeric ASCII (or input start/end). This prevents `"Paris"`
//! matching inside `"ParisHilton"` and `"London"` matching inside
//! `"Londoner"`.
//!
//! ## ReDoS protection
//!
//! Inputs longer than [`MAX_INPUT_LENGTH`] return an empty `Vec`. Aho-Corasick
//! itself is O(n) in input length, but the bound caps memory + work.
//!
//! [`gazetteer`]: super::super::super::common::patterns::location::gazetteer
//! [`AMBIGUOUS_PLACE_NAMES`]: super::super::super::common::patterns::location::gazetteer::AMBIGUOUS_PLACE_NAMES

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use once_cell::sync::Lazy;

use super::super::super::common::patterns::location::gazetteer::{
    AMBIGUOUS_PLACE_NAMES, CITIES, COUNTRIES,
};
use super::super::super::confidence::context_keywords;
use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};

/// Maximum input length for ReDoS protection.
const MAX_INPUT_LENGTH: usize = 10_000;

/// Window (in bytes) on each side of a match used to scan for
/// location-context keywords.
const CONTEXT_WINDOW_BYTES: usize = 60;

// ============================================================================
// Lazy-built matchers
// ============================================================================

static CITY_MATCHER: Lazy<AhoCorasick> = Lazy::new(|| build_matcher(CITIES));
static COUNTRY_MATCHER: Lazy<AhoCorasick> = Lazy::new(|| build_matcher(COUNTRIES));
static AMBIGUOUS_MATCHER: Lazy<AhoCorasick> = Lazy::new(|| build_matcher(AMBIGUOUS_PLACE_NAMES));

#[allow(clippy::expect_used)]
fn build_matcher(patterns: &[&str]) -> AhoCorasick {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostLongest)
        .build(patterns)
        .expect("BUG: gazetteer lexicon contains invalid pattern")
}

// ============================================================================
// Public API
// ============================================================================

/// Find all named locations (cities + countries) in free text.
///
/// Returns `IdentifierMatch` records with byte spans, the matched text, and
/// a confidence level reflecting context-keyword presence.
#[must_use]
pub fn detect_named_locations_in_text(text: &str) -> Vec<IdentifierMatch> {
    if text.is_empty() || text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();
    let bytes = text.as_bytes();

    scan_with(&CITY_MATCHER, text, bytes, &mut matches);
    scan_with(&COUNTRY_MATCHER, text, bytes, &mut matches);

    matches
}

/// Returns `true` if the input contains at least one named location.
#[must_use]
pub fn is_named_location(value: &str) -> bool {
    !detect_named_locations_in_text(value).is_empty()
}

// ============================================================================
// Internal helpers
// ============================================================================

fn scan_with(matcher: &AhoCorasick, text: &str, bytes: &[u8], matches: &mut Vec<IdentifierMatch>) {
    for hit in matcher.find_iter(text) {
        if !has_word_boundaries(bytes, hit.start(), hit.end()) {
            continue;
        }
        // Slice text by byte positions; skip rather than panic if the hit
        // falls inside a multi-byte UTF-8 codepoint (would indicate a
        // matcher bug since lexicon entries are Latin-1).
        let Some(matched) = text.get(hit.start()..hit.end()) else {
            continue;
        };

        let has_context = is_in_location_context(text, hit.start(), hit.end());
        let is_ambiguous = matches_ambiguous(matched);

        let confidence = if has_context {
            // Context boost dominates: even ambiguous words become High.
            DetectionConfidence::High
        } else if is_ambiguous {
            DetectionConfidence::Low
        } else {
            DetectionConfidence::Medium
        };

        matches.push(IdentifierMatch::new(
            hit.start(),
            hit.end(),
            matched.to_string(),
            IdentifierType::NamedLocation,
            confidence,
        ));
    }
}

/// True when the byte range is bounded by non-alphanumeric ASCII bytes
/// (or input start/end). Mirrors the helper in `personal/detection/nrp.rs`
/// — operates on raw bytes for speed; safe because the boundary check
/// only inspects ASCII alphanumeric (the leading byte of any multi-byte
/// UTF-8 codepoint is always ≥ 0x80, which is never `is_ascii_alphanumeric`).
fn has_word_boundaries(bytes: &[u8], start: usize, end: usize) -> bool {
    let before_ok = if start == 0 {
        true
    } else {
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

/// Case-insensitive scan of the ±[`CONTEXT_WINDOW_BYTES`] window around a
/// match for any location-context keyword registered against
/// [`IdentifierType::NamedLocation`].
///
/// Uses byte-position arithmetic with [`saturating_sub`] and `min` to stay
/// in-range. Window endpoints are then snapped to UTF-8 codepoint
/// boundaries by walking the surrounding bytes — slicing on a non-boundary
/// byte panics, so a non-ASCII codepoint inside the window must not cause
/// a split mid-codepoint.
fn is_in_location_context(text: &str, match_start: usize, match_end: usize) -> bool {
    let keywords = context_keywords(&IdentifierType::NamedLocation);
    if keywords.is_empty() {
        return false;
    }

    let window_start = floor_char_boundary(text, match_start.saturating_sub(CONTEXT_WINDOW_BYTES));
    let window_end = ceil_char_boundary(
        text,
        match_end
            .saturating_add(CONTEXT_WINDOW_BYTES)
            .min(text.len()),
    );

    // `floor`/`ceil` guarantee both endpoints are codepoint boundaries.
    let Some(window) = text.get(window_start..window_end) else {
        return false;
    };
    let window_lower = window.to_lowercase();

    keywords.iter().any(|kw| window_lower.contains(kw))
}

/// Round `pos` down to the nearest UTF-8 codepoint boundary. Returns 0 if
/// no earlier boundary exists. Used instead of the unstable
/// `str::floor_char_boundary` API.
fn floor_char_boundary(text: &str, pos: usize) -> usize {
    let mut p = pos.min(text.len());
    while p > 0 && !text.is_char_boundary(p) {
        p = p.saturating_sub(1);
    }
    p
}

/// Round `pos` up to the nearest UTF-8 codepoint boundary. Returns
/// `text.len()` if no later boundary exists.
fn ceil_char_boundary(text: &str, pos: usize) -> usize {
    let mut p = pos.min(text.len());
    while p < text.len() && !text.is_char_boundary(p) {
        p = p.saturating_add(1);
    }
    p
}

/// True when the matched text equals (case-insensitively) any entry in
/// [`AMBIGUOUS_PLACE_NAMES`]. Uses the same Aho-Corasick automaton on the
/// matched substring rather than a linear scan over the deny-list per
/// match.
fn matches_ambiguous(matched: &str) -> bool {
    // For the small ambiguous set, a direct overall-match check is fine:
    // we want to know whether the entire matched token is ambiguous, not
    // whether an ambiguous substring appears inside a larger place name.
    AMBIGUOUS_MATCHER
        .find_iter(matched)
        .any(|hit| hit.start() == 0 && hit.end() == matched.len() && matched.len() == hit.len())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ── Basic detection ──────────────────────────────────────────────

    #[test]
    fn test_detect_city_simple() {
        let matches = detect_named_locations_in_text("I live in Paris");
        assert!(!matches.is_empty(), "expected at least one match");
        let first = matches.first().expect("at least one match");
        assert_eq!(first.identifier_type, IdentifierType::NamedLocation);
        assert_eq!(first.matched_text, "Paris");
        assert_eq!(
            first.confidence,
            DetectionConfidence::High,
            "context 'live in' should boost to High"
        );
    }

    #[test]
    fn test_detect_country_simple() {
        let matches = detect_named_locations_in_text("I'm visiting Japan");
        assert!(!matches.is_empty());
        let first = matches.first().expect("match");
        assert_eq!(first.matched_text, "Japan");
        assert_eq!(first.confidence, DetectionConfidence::High);
    }

    #[test]
    fn test_detect_city_without_context_is_medium() {
        let matches = detect_named_locations_in_text("Berlin is the capital");
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("match").confidence,
            DetectionConfidence::Medium,
            "no context keyword should yield Medium"
        );
    }

    #[test]
    fn test_detect_country_without_context_is_medium() {
        let matches = detect_named_locations_in_text("Germany has many cities");
        let germany = matches
            .iter()
            .find(|m| m.matched_text == "Germany")
            .expect("should detect Germany");
        assert_eq!(germany.confidence, DetectionConfidence::Medium);
    }

    // ── Context-keyword boost ────────────────────────────────────────

    #[test]
    fn test_context_keyword_from() {
        let matches = detect_named_locations_in_text("She's from Germany originally");
        let germany = matches
            .iter()
            .find(|m| m.matched_text == "Germany")
            .expect("should detect Germany");
        assert_eq!(germany.confidence, DetectionConfidence::High);
    }

    #[test]
    fn test_context_keyword_located_in() {
        let matches = detect_named_locations_in_text("The office is located in Tokyo");
        let tokyo = matches
            .iter()
            .find(|m| m.matched_text == "Tokyo")
            .expect("should detect Tokyo");
        assert_eq!(tokyo.confidence, DetectionConfidence::High);
    }

    #[test]
    fn test_context_keyword_hometown() {
        let matches = detect_named_locations_in_text("My hometown is Dublin");
        let dublin = matches
            .iter()
            .find(|m| m.matched_text == "Dublin")
            .expect("should detect Dublin");
        assert_eq!(dublin.confidence, DetectionConfidence::High);
    }

    // ── Ambiguous-word handling ──────────────────────────────────────

    #[test]
    fn test_ambiguous_word_without_context_is_low() {
        let matches = detect_named_locations_in_text("Reading this carefully");
        let reading = matches
            .iter()
            .find(|m| m.matched_text == "Reading")
            .expect("should still detect ambiguous word");
        assert_eq!(
            reading.confidence,
            DetectionConfidence::Low,
            "ambiguous word without context should be Low"
        );
    }

    #[test]
    fn test_ambiguous_word_with_context_is_high() {
        let matches = detect_named_locations_in_text("address: 123 Reading St");
        let reading = matches
            .iter()
            .find(|m| m.matched_text == "Reading")
            .expect("should detect Reading");
        assert_eq!(
            reading.confidence,
            DetectionConfidence::High,
            "'address' context should boost ambiguous word to High"
        );
    }

    #[test]
    fn test_non_ambiguous_city_stays_medium_without_context() {
        let matches = detect_named_locations_in_text("Tokyo is large");
        let tokyo = matches
            .iter()
            .find(|m| m.matched_text == "Tokyo")
            .expect("should detect Tokyo");
        assert_eq!(tokyo.confidence, DetectionConfidence::Medium);
    }

    // ── Word boundaries ──────────────────────────────────────────────

    #[test]
    fn test_no_match_inside_longer_word() {
        // "Paris" must not match inside "ParisHilton" (no boundary)
        let matches = detect_named_locations_in_text("ParisHilton hotel chain");
        assert!(
            matches.is_empty(),
            "should not match across word boundary, got {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_no_match_when_prefixed_by_letters() {
        let matches = detect_named_locations_in_text("Londoner pride");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_match_with_punctuation_boundary() {
        let matches = detect_named_locations_in_text("Cities: Paris, Tokyo, Berlin.");
        assert!(matches.len() >= 3);
    }

    // ── Case insensitivity ───────────────────────────────────────────

    #[test]
    fn test_case_insensitive_uppercase() {
        assert!(is_named_location("flew to TOKYO last week"));
    }

    #[test]
    fn test_case_insensitive_lowercase() {
        assert!(is_named_location("flew to tokyo last week"));
    }

    #[test]
    fn test_case_insensitive_mixed() {
        assert!(is_named_location("flew to TokYo last week"));
    }

    // ── Multi-word cities ────────────────────────────────────────────

    #[test]
    fn test_multi_word_city() {
        let matches = detect_named_locations_in_text("flew to New York City");
        let ny = matches.iter().find(|m| m.matched_text == "New York");
        assert!(ny.is_some(), "should match 'New York' as one token");
    }

    #[test]
    fn test_multi_word_country() {
        let matches = detect_named_locations_in_text("from United States travelers");
        let us = matches.iter().find(|m| m.matched_text == "United States");
        assert!(us.is_some());
    }

    #[test]
    fn test_multi_word_leftmost_longest() {
        // "Cape Town" is in the gazetteer; "Town" is not. Should match
        // "Cape Town" as one match, not just "Cape".
        let matches = detect_named_locations_in_text("Cape Town beaches");
        let names: Vec<&String> = matches.iter().map(|m| &m.matched_text).collect();
        assert!(
            names.contains(&&"Cape Town".to_string()),
            "should match longest, got {names:?}"
        );
    }

    // ── Diacritic variants ───────────────────────────────────────────

    #[test]
    fn test_diacritic_variant_matches() {
        // São Paulo is in the gazetteer with both diacritic and ASCII
        // forms; either should match.
        assert!(is_named_location("flew to São Paulo"));
        assert!(is_named_location("flew to Sao Paulo"));
    }

    // ── Multiple matches ─────────────────────────────────────────────

    #[test]
    fn test_multiple_locations() {
        let text = "Travelled from London to Paris, then to Berlin and back to Tokyo";
        let matches = detect_named_locations_in_text(text);
        assert!(
            matches.len() >= 4,
            "expected at least 4 matches, got {}",
            matches.len()
        );
    }

    // ── Negative cases ───────────────────────────────────────────────

    #[test]
    fn test_no_match_on_unrelated_text() {
        // "Nice" is in the gazetteer (French city) AND in the ambiguous
        // deny-list. Without context, it returns Low confidence — still a
        // match, but consumers can filter on confidence to avoid redacting
        // common-English-word false positives.
        let matches = detect_named_locations_in_text("the weather is nice today");
        for m in &matches {
            assert_eq!(
                m.confidence,
                DetectionConfidence::Low,
                "ambiguous word without location context must be Low, got {m:?}",
            );
        }
    }

    #[test]
    fn test_no_match_on_random_words() {
        let matches = detect_named_locations_in_text("xyzzy plugh foo bar baz");
        assert!(matches.is_empty());
    }

    // ── Edge cases ───────────────────────────────────────────────────

    #[test]
    fn test_empty_input() {
        assert!(detect_named_locations_in_text("").is_empty());
        assert!(!is_named_location(""));
    }

    #[test]
    fn test_redos_protection() {
        let huge = "x".repeat(MAX_INPUT_LENGTH + 1);
        assert!(detect_named_locations_in_text(&huge).is_empty());
    }

    #[test]
    fn test_at_max_length_works() {
        // Slightly under the limit should still be scanned without panic.
        let mut text = String::from("I live in Paris. ");
        text.push_str(&"x".repeat(MAX_INPUT_LENGTH - text.len() - 10));
        let matches = detect_named_locations_in_text(&text);
        assert!(!matches.is_empty());
    }

    // ── Byte spans ───────────────────────────────────────────────────

    #[test]
    fn test_byte_spans_correct() {
        let text = "I live in Paris today";
        let matches = detect_named_locations_in_text(text);
        let paris = matches
            .iter()
            .find(|m| m.matched_text == "Paris")
            .expect("paris match");
        assert_eq!(&text[paris.start..paris.end], "Paris");
    }

    // ── Gazetteer size sanity ────────────────────────────────────────

    #[test]
    fn test_gazetteer_has_sufficient_coverage() {
        assert!(COUNTRIES.len() >= 200, "expected ≥200 countries");
        assert!(CITIES.len() >= 1_000, "expected ≥1000 cities");
    }

    // ── HIPAA scenarios from issue test plan ─────────────────────────

    #[test]
    fn test_hipaa_phoenix_scenario() {
        let matches = detect_named_locations_in_text("Patient lives in Phoenix");
        let phoenix = matches
            .iter()
            .find(|m| m.matched_text == "Phoenix")
            .expect("should detect Phoenix");
        assert_eq!(phoenix.confidence, DetectionConfidence::High);
    }

    #[test]
    fn test_hipaa_visiting_japan_scenario() {
        let matches = detect_named_locations_in_text("I'm visiting Japan");
        let japan = matches
            .iter()
            .find(|m| m.matched_text == "Japan")
            .expect("should detect Japan");
        assert_eq!(japan.confidence, DetectionConfidence::High);
    }
}

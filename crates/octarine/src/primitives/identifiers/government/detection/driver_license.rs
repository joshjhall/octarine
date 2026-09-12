//! Driver's license format detection
//!
//! Supports US state-specific formats for the top 20 states by population,
//! plus a generic `DL#` / `LICENSE:` labeled fallback.
//!
//! # Two confidence tiers
//!
//! State layouts split by how much they identify on their own:
//!
//! - **Alpha-bearing layouts** (`patterns::driver_license::state_patterns`) —
//!   `A1234567`, `AB12345`, `A123456789012`. A letter in a fixed position makes
//!   these specific enough to report at `High` confidence unaided.
//! - **Digits-only layouts** (`patterns::driver_license::weak_state_patterns`)
//!   — TX, PA, GA, TN, NC and the 9-digit NY/VA/MA/MO/AZ form. A bare run of
//!   7-9 digits also describes every order number and invoice in a typical
//!   corpus, so these are reported at `Medium` and upgraded to `High` only when
//!   a driver-license keyword sits nearby.
//!
//! The context upgrade mirrors the one `detection::passport` applies to its own
//! weak generic pattern.

use super::super::super::common::patterns;
use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};
use super::helpers::{MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length, get_full_match};

/// How far either side of a candidate to look for a driver-license keyword.
const CONTEXT_WINDOW: usize = 24;

/// Keywords that make a digits-only candidate likely to be a license number.
const CONTEXT_KEYWORDS: &[&str] = &[
    "driver", "drivers", "driver's", "license", "licence", "dl#", "dl ", "dl:", "lic", "dmv",
];

/// Check if a value matches driver's license format
///
/// Accepts both confidence tiers — a digits-only state layout counts as a
/// format match here even without context, since this answers "could this be a
/// license number" rather than "is this one".
#[must_use]
pub fn is_driver_license(value: &str) -> bool {
    // Check generic labeled pattern
    if patterns::driver_license::GENERIC.is_match(value) {
        return true;
    }

    // Check distinctive state-specific patterns
    if patterns::driver_license::state_patterns()
        .values()
        .any(|p| p.is_match(value))
    {
        return true;
    }

    // Check digits-only state patterns
    patterns::driver_license::weak_state_patterns()
        .values()
        .any(|p| p.is_match(value))
}

/// Find all driver's license patterns in text
///
/// Detects:
/// - Alpha-bearing state layouts: "A1234567" (CA), "AB12345" (OH) — `High`
/// - Digits-only state layouts: "12345678" (TX/PA) — `Medium`, or `High` with
///   a nearby driver-license keyword
/// - Generic labeled: "DL# A1234567", "LICENSE: B9876543" — `High`
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "Driver License: CA A1234567";
/// let matches = detection::find_driver_licenses_in_text(text);
/// assert!(!matches.is_empty());
/// ```
#[must_use]
pub fn find_driver_licenses_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    // Distinctive state-specific patterns — specific enough on their own.
    for pattern in patterns::driver_license::state_patterns().values() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::DriverLicense,
            ));
        }
    }

    // Digits-only state patterns — Medium unless context vouches for them.
    for pattern in patterns::driver_license::weak_state_patterns().values() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            let confidence = DetectionConfidence::Medium
                .with_context_boost(is_likely_license_context(text, full_match.start()));
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::DriverLicense,
                confidence,
            ));
        }
    }

    // Generic labeled pattern — the label is the context.
    for capture in patterns::driver_license::GENERIC.captures_iter(text) {
        let full_match = get_full_match(&capture);
        matches.push(IdentifierMatch::high_confidence(
            full_match.start(),
            full_match.end(),
            full_match.as_str().to_string(),
            IdentifierType::DriverLicense,
        ));
    }

    deduplicate_matches(matches)
}

/// Check whether a driver-license keyword appears within [`CONTEXT_WINDOW`]
/// characters of a candidate.
///
/// Takes the candidate's byte offset rather than its text so repeated values in
/// one document are judged at their own position, not at the first occurrence.
fn is_likely_license_context(text: &str, match_start: usize) -> bool {
    let start = match_start.saturating_sub(CONTEXT_WINDOW);
    let end = match_start.saturating_add(CONTEXT_WINDOW).min(text.len());

    // Snap to char boundaries so slicing never splits a multi-byte character.
    let start = (start..=match_start)
        .find(|i| text.is_char_boundary(*i))
        .unwrap_or(match_start);
    let end = (match_start..=end)
        .rev()
        .find(|i| text.is_char_boundary(*i))
        .unwrap_or(match_start);

    let Some(window) = text.get(start..end) else {
        return false;
    };
    let window = window.to_lowercase();

    CONTEXT_KEYWORDS
        .iter()
        .any(|keyword| window.contains(keyword))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    /// Highest confidence reported for `value` inside `text`.
    fn best_confidence(text: &str, value: &str) -> Option<DetectionConfidence> {
        find_driver_licenses_in_text(text)
            .into_iter()
            .filter(|m| m.matched_text == value)
            .map(|m| m.confidence)
            .max()
    }

    #[test]
    fn test_is_driver_license() {
        assert!(is_driver_license("A1234567")); // CA format
        assert!(is_driver_license("12345678")); // TX/PA format
        assert!(!is_driver_license("invalid"));
    }

    #[test]
    fn test_is_driver_license_covers_added_states() {
        assert!(is_driver_license("A123456789012")); // FL/MD
        assert!(is_driver_license("AB12345")); // OH
        assert!(is_driver_license("A12345678901")); // IL
    }

    #[test]
    fn test_find_driver_licenses_in_text() {
        let text = "Driver License: CA A1234567";
        let matches = find_driver_licenses_in_text(text);
        assert!(!matches.is_empty());
        let first = matches
            .first()
            .expect("Should detect driver license pattern");
        assert_eq!(first.identifier_type, IdentifierType::DriverLicense);
    }

    #[test]
    fn test_alpha_bearing_layout_is_high_without_context() {
        // "A1234567" carries a letter in a fixed position — specific enough
        // that no keyword is needed.
        assert_eq!(
            best_confidence("record A1234567 filed", "A1234567"),
            Some(DetectionConfidence::High)
        );
    }

    #[test]
    fn test_digits_only_layout_is_medium_without_context() {
        // A bare 8-digit run is also every order number in the corpus, so it
        // must NOT be reported at High on its own.
        assert_eq!(
            best_confidence("order 12345678 shipped", "12345678"),
            Some(DetectionConfidence::Medium)
        );
    }

    #[test]
    fn test_digits_only_layout_upgrades_with_context() {
        // The same digits as the Medium case above, now vouched for by a
        // nearby keyword. These phrasings do NOT match the `GENERIC` labeled
        // pattern (which would subsume the digits into one longer high-
        // confidence match), so the upgrade being tested is genuinely the weak
        // tier's context boost.
        assert_eq!(
            best_confidence("DMV record 12345678", "12345678"),
            Some(DetectionConfidence::High)
        );
        assert_eq!(
            best_confidence("driver record 12345678", "12345678"),
            Some(DetectionConfidence::High)
        );
    }

    #[test]
    fn test_labeled_phrase_subsumes_the_digits() {
        // "license 12345678" matches the GENERIC labeled pattern as a single
        // span, so the reported match is the whole labeled phrase at High
        // rather than the bare digits.
        let matches = find_driver_licenses_in_text("driver license 12345678");
        assert!(
            matches.iter().any(|m| m.matched_text.contains("12345678")
                && m.confidence == DetectionConfidence::High),
            "expected a high-confidence match covering the digits: {matches:?}"
        );
    }

    #[test]
    fn test_context_window_is_bounded() {
        // A keyword far from the candidate must not upgrade it, or the window
        // is doing nothing.
        let text = "license mentioned here, and then much later on the very \
                    same page an unrelated 12345678";
        assert_eq!(
            best_confidence(text, "12345678"),
            Some(DetectionConfidence::Medium)
        );
    }

    #[test]
    fn test_multibyte_context_does_not_panic() {
        // Slicing a context window near multi-byte characters must snap to
        // char boundaries.
        let text = "駕駛執照 émigré — 12345678";
        let _ = find_driver_licenses_in_text(text);
        let text = "é12345678é";
        let _ = find_driver_licenses_in_text(text);
    }

    #[test]
    fn test_labeled_generic_is_high() {
        assert_eq!(
            best_confidence("DL# B9876543", "DL# B9876543"),
            Some(DetectionConfidence::High)
        );
    }

    #[test]
    fn test_pattern_maps_are_compiled_once() {
        // These maps are rebuilt on every `find_driver_licenses_in_text`, which
        // sits on the PII redaction hot path. If they ever stop being `Lazy`
        // statics, every call recompiles 19 regexes: measured at ~44ms per
        // call, which took one redaction-heavy integration test from 15s to
        // 97s and timed it out in CI.
        //
        // Two calls returning the SAME address proves the map is a static, not
        // a fresh allocation per call.
        let a = patterns::driver_license::state_patterns();
        let b = patterns::driver_license::state_patterns();
        assert!(
            std::ptr::eq(a, b),
            "state_patterns() rebuilds its map per call — regexes are being \
             recompiled on the redaction hot path"
        );

        let a = patterns::driver_license::weak_state_patterns();
        let b = patterns::driver_license::weak_state_patterns();
        assert!(
            std::ptr::eq(a, b),
            "weak_state_patterns() rebuilds its map per call — regexes are \
             being recompiled on the redaction hot path"
        );
    }

    #[test]
    fn test_empty_input() {
        assert!(!is_driver_license(""));
        assert!(find_driver_licenses_in_text("").is_empty());
    }
}

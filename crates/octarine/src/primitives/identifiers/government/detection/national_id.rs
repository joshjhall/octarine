//! National ID detection
//!
//! Two flavours:
//! - `is_national_id` / `find_national_ids_in_text` — generic catch-all for
//!   country-agnostic national-ID regex patterns (UK NI, Canadian SIN, …).
//!   No country-specific validation; format-only.
//! - `is_uk_ni` / `find_uk_nis_in_text` — strict UK National Insurance
//!   Number detection. Combines a shape check with the full HMRC validator,
//!   so there are no false positives for bare NINOs.

use super::super::super::common::patterns;
use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};
use super::super::validation::validate_uk_ni;
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Check if a value matches national ID format
#[must_use]
pub fn is_national_id(value: &str) -> bool {
    patterns::national_id::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all national ID patterns in text
///
/// Detects international national identification numbers:
/// - UK National Insurance: "AB123456C"
/// - Canadian SIN: "123-456-789"
/// - Generic national IDs
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "UK NI: AB123456C";
/// let matches = detection::find_national_ids_in_text(text);
/// assert!(!matches.is_empty());
/// ```
#[must_use]
pub fn find_national_ids_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::national_id::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::NationalId,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value is a valid UK National Insurance Number (NINO)
///
/// Format: 2 letters + 6 digits + 1 suffix letter (e.g. `AB123456C`).
/// Applies HMRC prefix/suffix rules — invalid prefixes
/// (BG, GB, NK, KN, TN, NT, ZZ), reserved first letters (D, F, I, Q, U, V),
/// and non A-D suffixes are rejected. Test patterns (AA000000A, etc.) are
/// also rejected.
///
/// This detection function combines a regex shape check with the full
/// validator, so it has no false positives for bare NINOs.
#[must_use]
pub fn is_uk_ni(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    if !patterns::uk_ni::STANDARD.is_match(value) {
        return false;
    }
    validate_uk_ni(value).is_ok()
}

/// Find all UK NINO patterns in text with HMRC validation
///
/// Scans for UK National Insurance Number patterns and filters out any
/// regex match whose prefix/suffix rules fail (invalid prefixes, reserved
/// first letters, non A-D suffix, test patterns).
///
/// Labeled patterns (`"NI: AB123456C"`) get High confidence; bare patterns
/// get Medium. The returned match text is the full regex match including
/// the label for labeled patterns — consistent with SSN text scanning.
#[must_use]
pub fn find_uk_nis_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for (pattern_idx, pattern) in patterns::uk_ni::all().iter().enumerate() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);

            // For LABELED (index 0) the NINO is in capture group 2; for
            // STANDARD the full match is the NINO itself.
            let nino_text = if pattern_idx == 0 {
                capture.get(2).map_or(full_match.as_str(), |m| m.as_str())
            } else {
                full_match.as_str()
            };

            if validate_uk_ni(nino_text).is_err() {
                continue;
            }

            let confidence = if pattern_idx == 0 {
                DetectionConfidence::High
            } else {
                DetectionConfidence::Medium
            };

            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::UkNi,
                confidence,
            ));
        }
    }

    deduplicate_matches(matches)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_national_id() {
        assert!(is_national_id("AB123456C")); // UK NI
        assert!(is_national_id("123-456-789")); // Canadian SIN
        assert!(!is_national_id("invalid"));
    }

    #[test]
    fn test_find_national_ids_in_text() {
        let text = "UK NI: AB123456C";
        let matches = find_national_ids_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect national ID pattern");
        assert_eq!(first.identifier_type, IdentifierType::NationalId);
    }

    #[test]
    fn test_empty_input() {
        assert!(!is_national_id(""));
    }

    // ========================================================================
    // UK NINO detection tests
    // ========================================================================

    #[test]
    fn test_is_uk_ni_valid() {
        assert!(is_uk_ni("AB123456C"));
        assert!(is_uk_ni("CE123456A"));
        assert!(is_uk_ni("HJ987654B"));
        assert!(is_uk_ni("LA456789D"));
    }

    #[test]
    fn test_is_uk_ni_rejects_invalid_prefix() {
        // HMRC-prohibited prefix pairs
        assert!(!is_uk_ni("BG123456A"));
        assert!(!is_uk_ni("GB123456A"));
        assert!(!is_uk_ni("NK123456A"));
        assert!(!is_uk_ni("KN123456A"));
        assert!(!is_uk_ni("ZZ999999A")); // ZZ (also a test pattern)
    }

    #[test]
    fn test_is_uk_ni_rejects_reserved_first_letter() {
        // Reserved temporary-prefix first letters
        for first in ['D', 'F', 'I', 'Q', 'U', 'V'] {
            let candidate = format!("{first}A123456C");
            assert!(!is_uk_ni(&candidate), "{candidate} should be rejected");
        }
    }

    #[test]
    fn test_is_uk_ni_rejects_invalid_suffix() {
        assert!(!is_uk_ni("AB123456E"));
        assert!(!is_uk_ni("AB123456Z"));
    }

    #[test]
    fn test_is_uk_ni_rejects_wrong_shape() {
        assert!(!is_uk_ni("not a nino"));
        assert!(!is_uk_ni("A1123456C")); // Only one letter prefix
        assert!(!is_uk_ni("AB1234567")); // All digits after prefix
        assert!(!is_uk_ni(""));
    }

    #[test]
    fn test_find_uk_nis_in_text_labeled_high_confidence() {
        let text = "Employee NI: AB123456C";
        let matches = find_uk_nis_in_text(text);
        assert_eq!(matches.len(), 1);
        let m = matches.first().expect("one match");
        assert_eq!(m.identifier_type, IdentifierType::UkNi);
        assert_eq!(m.confidence, DetectionConfidence::High);
        assert!(m.matched_text.contains("AB123456C"));
    }

    #[test]
    fn test_find_uk_nis_in_text_bare_medium_confidence() {
        let text = "The record is AB123456C overall.";
        let matches = find_uk_nis_in_text(text);
        assert_eq!(matches.len(), 1);
        let m = matches.first().expect("one match");
        assert_eq!(m.identifier_type, IdentifierType::UkNi);
        assert_eq!(m.confidence, DetectionConfidence::Medium);
        assert_eq!(m.matched_text, "AB123456C");
    }

    #[test]
    fn test_find_uk_nis_rejects_invalid_in_text() {
        // Regex shape matches but HMRC rules reject — expect no matches
        let text = "Spurious value BG123456A in the doc";
        assert!(find_uk_nis_in_text(text).is_empty());
    }

    #[test]
    fn test_find_uk_nis_multiple() {
        let text = "First NI: AB123456C, second HJ987654B.";
        let matches = find_uk_nis_in_text(text);
        assert_eq!(matches.len(), 2);
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::UkNi)
        );
    }
}

//! US Medicare Beneficiary Identifier (MBI) detection.
//!
//! - `is_us_mbi` is strict — it delegates to `validation::validate_us_mbi`, so
//!   it enforces the full CMS positional layout and the excluded-letter
//!   alphabet.
//! - `find_us_mbis_in_text` scans for the structural patterns and tags matches
//!   as `IdentifierType::Mbi`. The dashed `XXXX-XXX-XXXX` form is distinctive
//!   enough for `High` confidence; the bare 11-character form gets `Medium`
//!   because it overlaps with arbitrary alphanumeric identifiers.

use super::super::super::common::patterns;
use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};
use super::helpers::{MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length, get_full_match};

/// Check if a value is a valid US Medicare Beneficiary Identifier (MBI).
///
/// Strict: enforces the 11-character CMS layout (`C A AN N A AN N A A N N`)
/// and the letter alphabet `ACDEFGHJKMNPQRTUVWXY` (excluding `S, L, O, I, B,
/// Z`). Accepts both the bare and dashed `XXXX-XXX-XXXX` forms.
#[must_use]
pub fn is_us_mbi(value: &str) -> bool {
    super::super::validation::validate_us_mbi(value).is_ok()
}

/// Find all valid US MBI patterns in text.
///
/// Scans for the dashed form first (`High` confidence — the `XXXX-XXX-XXXX`
/// layout is highly distinctive) and then the bare 11-character form
/// (`Medium`). Every candidate is re-checked through `is_us_mbi` so only
/// structurally valid MBIs are returned. Matches are tagged
/// `IdentifierType::Mbi`.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "Medicare MBI: 1EG4-TE5-MK73";
/// let matches = detection::find_us_mbis_in_text(text);
/// assert_eq!(matches.len(), 1);
/// ```
#[must_use]
pub fn find_us_mbis_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    // Dashed form first (High confidence).
    for capture in patterns::mbi::WITH_DASH.captures_iter(text) {
        let full_match = get_full_match(&capture);
        let matched_text = full_match.as_str();
        if !is_us_mbi(matched_text) {
            continue;
        }
        matches.push(IdentifierMatch::high_confidence(
            full_match.start(),
            full_match.end(),
            matched_text.to_string(),
            IdentifierType::Mbi,
        ));
    }

    // Bare 11-character form (Medium confidence).
    for capture in patterns::mbi::NO_DASH.captures_iter(text) {
        let full_match = get_full_match(&capture);
        let matched_text = full_match.as_str();
        if !is_us_mbi(matched_text) {
            continue;
        }
        matches.push(IdentifierMatch::new(
            full_match.start(),
            full_match.end(),
            matched_text.to_string(),
            IdentifierType::Mbi,
            DetectionConfidence::Medium,
        ));
    }

    deduplicate_matches(matches)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_us_mbi_accepts_valid() {
        assert!(is_us_mbi("1EG4TE5MK73"));
        assert!(is_us_mbi("1EG4-TE5-MK73"));
    }

    #[test]
    fn test_is_us_mbi_rejects_invalid() {
        // Excluded letter 'B' at position 3 (the issue's bad fixture).
        assert!(!is_us_mbi("1AB2C3D4EF5"));
        // Starts with a letter.
        assert!(!is_us_mbi("AEG4TE5MK73"));
        assert!(!is_us_mbi(""));
    }

    #[test]
    fn test_find_us_mbis_in_text_dashed_high() {
        let text = "Medicare MBI: 1EG4-TE5-MK73 on the card";
        let matches = find_us_mbis_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("should detect dashed MBI");
        assert_eq!(first.identifier_type, IdentifierType::Mbi);
        assert_eq!(first.confidence, DetectionConfidence::High);
    }

    #[test]
    fn test_find_us_mbis_in_text_bare_medium() {
        let text = "Beneficiary 1EG4TE5MK73 enrolled";
        let matches = find_us_mbis_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("should detect bare MBI");
        assert_eq!(first.identifier_type, IdentifierType::Mbi);
        assert_eq!(first.confidence, DetectionConfidence::Medium);
    }

    #[test]
    fn test_find_us_mbis_in_text_skips_invalid() {
        // Structurally invalid strings must not surface as MBI matches.
        let text = "Reference 1AB2C3D4EF5 is not an MBI";
        let matches = find_us_mbis_in_text(text);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_find_us_mbis_in_text_multiple() {
        let text = "First 1EG4TE5MK73 then 9YK8MQ3PW21";
        let matches = find_us_mbis_in_text(text);
        assert_eq!(matches.len(), 2);
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::Mbi)
        );
    }

    #[test]
    fn test_find_us_mbis_in_text_empty() {
        assert!(find_us_mbis_in_text("").is_empty());
    }
}

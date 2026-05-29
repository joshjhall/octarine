//! US Individual Taxpayer Identification Number (ITIN) detection.
//!
//! - `is_itin` is strict — requires `XXX-XX-XXXX` shape **and** valid IRS
//!   middle group (delegates to `validation::validate_itin`).
//! - `find_itins_in_text` scans for strict-shaped candidates and tags
//!   matches as `IdentifierType::Itin`. The same value may also appear in
//!   `find_tax_ids_in_text` results — ITINs are a subset of tax IDs.

use super::super::super::common::patterns;
use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};
use super::helpers::{MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length, get_full_match};

/// Check if a value is a valid ITIN (Individual Taxpayer Identification Number)
///
/// Strict: requires `XXX-XX-XXXX` or `XXXXXXXXX` layout, area `9XX`, and a
/// middle group in `{50-65, 70-88, 90-92, 94-99}` per IRS Publication 1915.
#[must_use]
pub fn is_itin(value: &str) -> bool {
    super::super::validation::validate_itin(value).is_ok()
}

/// Find all valid ITIN patterns in text
///
/// Scans for the strict ITIN regex (`ITIN_FORMAT_STRICT` and `ITIN_LABELED`)
/// and then runs each candidate through `is_itin` to enforce the full IRS
/// rule. Matches are tagged `IdentifierType::Itin`.
///
/// Labeled matches get `High` confidence; bare strict-shape matches get
/// `Medium` because raw `9XX-XX-XXXX` strings overlap with arbitrary
/// numeric identifiers.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "ITIN: 900-70-0001";
/// let matches = detection::find_itins_in_text(text);
/// assert_eq!(matches.len(), 1);
/// ```
#[must_use]
pub fn find_itins_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    // Labeled first (High confidence)
    for capture in patterns::tax_id::ITIN_LABELED.captures_iter(text) {
        let full_match = get_full_match(&capture);
        let matched_text = full_match.as_str();
        // The capture's group 2 is the ITIN body without the label
        let number = capture.get(2).map_or("", |m| m.as_str());
        if !is_itin(number) {
            continue;
        }
        matches.push(IdentifierMatch::high_confidence(
            full_match.start(),
            full_match.end(),
            matched_text.to_string(),
            IdentifierType::Itin,
        ));
    }

    // Bare strict-shape candidates (Medium confidence)
    for capture in patterns::tax_id::ITIN_FORMAT_STRICT.captures_iter(text) {
        let full_match = get_full_match(&capture);
        let matched_text = full_match.as_str();
        if !is_itin(matched_text) {
            continue;
        }
        matches.push(IdentifierMatch::new(
            full_match.start(),
            full_match.end(),
            matched_text.to_string(),
            IdentifierType::Itin,
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
    fn test_is_itin_accepts_valid() {
        assert!(is_itin("900-70-0001"));
        assert!(is_itin("999-88-1234"));
        assert!(is_itin("900-50-0001"));
        // Bare digits accepted
        assert!(is_itin("900700001"));
    }

    #[test]
    fn test_is_itin_rejects_gap_groups() {
        assert!(!is_itin("912-34-5678")); // group 34 invalid
        assert!(!is_itin("987-12-3456")); // group 12 invalid
        assert!(!is_itin("900-01-0001")); // group 01 invalid
        assert!(!is_itin("900-66-0001")); // gap between 65/70
        assert!(!is_itin("900-89-0001")); // gap between 88/90
        assert!(!is_itin("900-93-0001")); // gap between 92/94
    }

    #[test]
    fn test_is_itin_rejects_non_itin_area() {
        assert!(!is_itin("123-70-0001")); // SSN area
        assert!(!is_itin("517-70-0001")); // SSN area
        assert!(!is_itin("899-70-0001")); // just below ITIN
    }

    #[test]
    fn test_find_itins_in_text_labeled() {
        let text = "ITIN: 900-70-0001 on the form";
        let matches = find_itins_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect labeled ITIN");
        assert_eq!(first.identifier_type, IdentifierType::Itin);
        assert_eq!(first.confidence, DetectionConfidence::High);
    }

    #[test]
    fn test_find_itins_in_text_bare() {
        let text = "Tax record 900-70-0001 attached";
        let matches = find_itins_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect bare ITIN");
        assert_eq!(first.identifier_type, IdentifierType::Itin);
        assert_eq!(first.confidence, DetectionConfidence::Medium);
    }

    #[test]
    fn test_find_itins_in_text_skips_invalid_middle_group() {
        // 912-34-5678 matches the loose ITIN_FORMAT but not ITIN_FORMAT_STRICT
        let text = "Possibly an ITIN: 912-34-5678 in this text";
        let matches = find_itins_in_text(text);
        assert!(
            matches.is_empty(),
            "Invalid IRS middle group must not produce ITIN matches"
        );
    }

    #[test]
    fn test_find_itins_in_text_skips_ssn_area() {
        // SSN-area values must never appear as ITIN matches even if the
        // middle group happens to be in the ITIN range.
        let text = "SSN: 123-70-0001 on file";
        let matches = find_itins_in_text(text);
        assert!(matches.is_empty(), "SSN-area values must not be ITIN");
    }

    #[test]
    fn test_find_itins_in_text_multiple() {
        let text = "Taxpayer 900-70-0001 also files as 999-88-1234";
        let matches = find_itins_in_text(text);
        assert_eq!(matches.len(), 2);
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::Itin)
        );
    }

    #[test]
    fn test_find_itins_in_text_empty() {
        assert!(find_itins_in_text("").is_empty());
    }
}

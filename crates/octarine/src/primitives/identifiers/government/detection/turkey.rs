//! Turkey identifier detection — TCKN (T.C. Kimlik Numarası) and license plate.
//!
//! Detection functions are pattern-based (shape-only). For checksum
//! verification of TCKN, use
//! [`super::super::validation::validate_turkey_tckn_with_checksum`].

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Check if a value matches Turkey TCKN format (bare or labeled)
///
/// Format-only check (11 digits, leading non-zero). Use
/// [`super::super::validation::validate_turkey_tckn_with_checksum`] for
/// NVI mod-10 verification.
#[must_use]
pub fn is_turkey_tckn(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::turkey_tckn::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Turkey TCKN patterns in text
///
/// Label-anchored only — a bare 11-digit run collides with phone numbers
/// (Turkish mobile/landline are also 11 digits with international code),
/// so text scanning requires context.
#[must_use]
pub fn find_turkey_tckns_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::turkey_tckn::labeled_only() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::TurkeyTckn,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Turkey license plate format
///
/// Format: `<province 01-81>[\s\-]?<1-3 letters from A-PR-VY-Z>[\s\-]?<2-4 digits>`.
#[must_use]
pub fn is_turkey_license_plate(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::turkey_license_plate::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Turkey license plate patterns in text
#[must_use]
pub fn find_turkey_license_plates_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::turkey_license_plate::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::TurkeyLicensePlate,
            ));
        }
    }

    deduplicate_matches(matches)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_is_turkey_tckn_bare_eleven_digits_accepted() {
        assert!(is_turkey_tckn("12345678901"));
    }

    #[test]
    fn test_is_turkey_tckn_leading_zero_rejected_by_pattern() {
        assert!(!is_turkey_tckn("01234567890"));
    }

    #[test]
    fn test_is_turkey_tckn_wrong_length_rejected() {
        assert!(!is_turkey_tckn("1234567890")); // 10
        assert!(!is_turkey_tckn("123456789012")); // 12
    }

    #[test]
    fn test_is_turkey_tckn_labeled_form() {
        assert!(is_turkey_tckn("TCKN: 12345678901"));
        assert!(is_turkey_tckn("TC Kimlik No 12345678901"));
    }

    #[test]
    fn test_find_turkey_tckns_label_required() {
        let bare = find_turkey_tckns_in_text("Some random text 12345678901 in the middle.");
        assert!(
            bare.is_empty(),
            "bare 11-digit string must not match without a label"
        );

        let labeled = find_turkey_tckns_in_text("Customer TCKN: 12345678901.");
        assert_eq!(labeled.len(), 1);
    }

    #[test]
    fn test_find_turkey_tckns_multiple() {
        let text = "Two records: TCKN 12345678901 and Türk Kimlik 98765432109.";
        let found = find_turkey_tckns_in_text(text);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_is_turkey_license_plate_valid_forms() {
        assert!(is_turkey_license_plate("34 ABC 123"));
        assert!(is_turkey_license_plate("34ABC123"));
        assert!(is_turkey_license_plate("06 A 12"));
        assert!(is_turkey_license_plate("81 ZZ 99"));
    }

    #[test]
    fn test_is_turkey_license_plate_rejects_invalid() {
        // Province out of range
        assert!(!is_turkey_license_plate("82 ABC 123"));
        // Reserved letter Q
        assert!(!is_turkey_license_plate("34 QBC 123"));
    }

    #[test]
    fn test_find_turkey_license_plates_in_text() {
        let labeled = find_turkey_license_plates_in_text("Plaka: 34 ABC 123 — Istanbul.");
        assert!(!labeled.is_empty());

        let bare = find_turkey_license_plates_in_text("Vehicle 34 ABC 123 stopped at the light.");
        assert!(
            !bare.is_empty(),
            "STANDARD pattern matches province-bounded shape"
        );
    }
}

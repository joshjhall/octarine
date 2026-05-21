//! Nigeria identifier detection — NIN, BVN, and vehicle registration.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Check if a value matches Nigeria NIN format (11 digits)
#[must_use]
pub fn is_nigeria_nin(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    // Direct value check: 11 digits with optional separators
    if value.chars().filter(|c| c.is_ascii_digit()).count() == 11
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '-' | ' '))
    {
        return true;
    }
    patterns::nigeria_nin::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Nigeria NIN patterns in text (LABELED only — see pattern docs)
#[must_use]
pub fn find_nigeria_nins_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::nigeria_nin::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::NigeriaNin,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Nigeria BVN format (11 digits)
///
/// BVN shares its shape with NIN (`\d{11}`); the dispatcher cannot tell them
/// apart without surrounding context. Callers that need precision should use
/// the labeled finders (`find_nigeria_bvns_in_text` / `find_nigeria_nins_in_text`).
#[must_use]
pub fn is_nigeria_bvn(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    if value.chars().filter(|c| c.is_ascii_digit()).count() == 11
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '-' | ' '))
    {
        return true;
    }
    patterns::nigeria_bvn::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Nigeria BVN patterns in text (LABELED only — see pattern docs)
#[must_use]
pub fn find_nigeria_bvns_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::nigeria_bvn::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::NigeriaBvn,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches a Nigerian vehicle registration plate
///
/// Accepts the current post-2020 format (`XXX-NNN-XX` with optional separators)
/// and the pre-2020 legacy format (`AA999-AAA`).
#[must_use]
pub fn is_nigeria_vehicle_registration(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::nigeria_vehicle_reg::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Nigeria vehicle registration plates in text
#[must_use]
pub fn find_nigeria_vehicle_registrations_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::nigeria_vehicle_reg::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::NigeriaVehicleReg,
            ));
        }
    }

    deduplicate_matches(matches)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // ---------------- BVN ----------------

    #[test]
    fn test_is_nigeria_bvn_accepts_11_digits() {
        assert!(is_nigeria_bvn("12345678901"));
    }

    #[test]
    fn test_is_nigeria_bvn_with_separators() {
        assert!(is_nigeria_bvn("123-456-789-01"));
        assert!(is_nigeria_bvn("123 456 789 01"));
    }

    #[test]
    fn test_is_nigeria_bvn_rejects_wrong_length() {
        assert!(!is_nigeria_bvn("1234567890"));
        assert!(!is_nigeria_bvn("123456789012"));
    }

    #[test]
    fn test_is_nigeria_bvn_accepts_labeled_form() {
        assert!(is_nigeria_bvn("BVN: 12345678901"));
        assert!(is_nigeria_bvn("Bank Verification Number: 12345678901"));
    }

    #[test]
    fn test_find_bvns_labeled_form() {
        let text = "BVN: 12345678901";
        assert_eq!(find_nigeria_bvns_in_text(text).len(), 1);
    }

    #[test]
    fn test_find_bvns_bank_verification_label() {
        let text = "bank verification number: 12345678901";
        assert_eq!(find_nigeria_bvns_in_text(text).len(), 1);
    }

    #[test]
    fn test_find_bvns_unlabeled_returns_empty() {
        let text = "12345678901";
        assert!(find_nigeria_bvns_in_text(text).is_empty());
    }

    #[test]
    fn test_find_bvns_does_not_match_nin_label() {
        // BVN scanner must not pick up a NIN-labeled value
        let text = "NIN: 12345678901";
        assert!(find_nigeria_bvns_in_text(text).is_empty());
    }

    #[test]
    fn test_find_nins_does_not_match_bvn_label() {
        // Symmetric check — NIN scanner must not pick up a BVN-labeled value
        let text = "BVN: 12345678901";
        assert!(find_nigeria_nins_in_text(text).is_empty());
    }

    // ---------------- Vehicle Registration ----------------

    #[test]
    fn test_is_vehicle_registration_current_format() {
        assert!(is_nigeria_vehicle_registration("LAG123AB"));
    }

    #[test]
    fn test_is_vehicle_registration_with_separators() {
        assert!(is_nigeria_vehicle_registration("LAG-123-AB"));
        assert!(is_nigeria_vehicle_registration("LAG 123 AB"));
    }

    #[test]
    fn test_is_vehicle_registration_legacy_format() {
        assert!(is_nigeria_vehicle_registration("LA123-ABC"));
    }

    #[test]
    fn test_is_vehicle_registration_rejects_junk() {
        assert!(!is_nigeria_vehicle_registration("12345"));
        assert!(!is_nigeria_vehicle_registration("LA-123-AB")); // 2-letter LGA on current format
    }

    #[test]
    fn test_find_vehicle_registration_labeled() {
        let text = "plate: LAG-123-AB";
        assert_eq!(find_nigeria_vehicle_registrations_in_text(text).len(), 1);
    }

    #[test]
    fn test_find_vehicle_registration_standalone() {
        // STANDARD pattern (no separators) is distinctive enough to scan
        let text = "Spotted LAG123AB in the lot.";
        assert_eq!(find_nigeria_vehicle_registrations_in_text(text).len(), 1);
    }
}

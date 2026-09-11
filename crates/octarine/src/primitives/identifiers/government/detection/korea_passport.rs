//! South Korea Passport detection
//!
//! Format: `[MRSOD][A-Z]?[0-9]{7,8}` — M=multiple, R=resident, S=single,
//! O=official, D=diplomatic, with an optional second uppercase letter for the
//! newer (post-2008) format.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Check if a value matches South Korea Passport format
#[must_use]
pub fn is_korea_passport(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::korea_passport::STANDARD.is_match(value)
}

/// Find all South Korea passport patterns in text
#[must_use]
pub fn find_korea_passports_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::korea_passport::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::KoreaPassport,
            ));
        }
    }

    deduplicate_matches(matches)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_korea_passport_mofa_prefixes_detected() {
        // O (official) and D (diplomatic) validate as of #427, so detection
        // must find them too — otherwise scans stay blind to valid passports.
        assert!(is_korea_passport("O12345678"));
        assert!(is_korea_passport("D12345678"));
    }

    #[test]
    fn test_is_korea_passport_legacy_prefixes_still_detected() {
        // Control: widening the class must not drop the original prefixes.
        assert!(is_korea_passport("M12345678"));
        assert!(is_korea_passport("R12345678"));
        assert!(is_korea_passport("S12345678"));
        // A prefix outside the valid set is still not a passport.
        assert!(!is_korea_passport("X12345678"));
    }

    #[test]
    fn test_find_korea_passports_in_text_mofa_prefix() {
        let matches = find_korea_passports_in_text("Korean passport: D12345678");
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches.first().expect("one match").identifier_type,
            IdentifierType::KoreaPassport
        );
    }
}

//! South Korea Passport detection
//!
//! Format: `[MRS][A-Z]?[0-9]{7,8}` — M=multiple, R=resident, S=single, with an
//! optional second uppercase letter for the newer (post-2008) format.

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

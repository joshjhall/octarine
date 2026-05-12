//! Australia TFN (Tax File Number) and ABN (Australian Business Number) detection

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Check if a value matches Australian TFN format (8-9 digits)
#[must_use]
pub fn is_australia_tfn(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::australia_tfn::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Check if a value matches Australian ABN format (11 digits)
#[must_use]
pub fn is_australia_abn(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::australia_abn::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Australian TFN patterns in text
#[must_use]
pub fn find_australia_tfns_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::australia_tfn::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::AustraliaTfn,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all Australian ABN patterns in text
#[must_use]
pub fn find_australia_abns_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::australia_abn::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::AustraliaAbn,
            ));
        }
    }

    deduplicate_matches(matches)
}

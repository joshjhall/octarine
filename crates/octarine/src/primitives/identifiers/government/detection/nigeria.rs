//! Nigeria NIN (National Identification Number) detection

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

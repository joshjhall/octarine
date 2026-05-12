//! Thailand TNIN (Thai National ID Number) detection

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Check if a value matches Thailand TNIN format
#[must_use]
pub fn is_thailand_tnin(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    if value.chars().filter(|c| c.is_ascii_digit()).count() == 13
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '-' | ' '))
    {
        return true;
    }
    patterns::thailand_tnin::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Thailand TNIN patterns in text
#[must_use]
pub fn find_thailand_tnins_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::thailand_tnin::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::ThailandTnin,
            ));
        }
    }

    deduplicate_matches(matches)
}

//! South Korea Business Registration Number (BRN) detection
//!
//! Format: `NNN-NN-NNNNN` (10 digits total). Validated by a weighted mod-10
//! checksum — see `validation/korea_brn.rs`.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Check if a value matches South Korea BRN format
#[must_use]
pub fn is_korea_brn(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::korea_brn::WITH_DASH.is_match(value)
}

/// Find all South Korea BRN patterns in text
#[must_use]
pub fn find_korea_brns_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::korea_brn::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::KoreaBrn,
            ));
        }
    }

    deduplicate_matches(matches)
}

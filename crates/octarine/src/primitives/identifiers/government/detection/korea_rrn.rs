//! South Korea RRN (Resident Registration Number) detection

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Check if a value matches South Korea RRN format
///
/// Validates the YYMMDD-GNNNNNN format where G is a gender/century digit (1-8).
/// Does NOT validate the checksum — use `validate_korea_rrn_with_checksum` for that.
#[must_use]
pub fn is_korea_rrn(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::korea_rrn::WITH_DASH.is_match(value)
}

/// Find all South Korea RRN patterns in text
///
/// Detects Korean Resident Registration Numbers in YYMMDD-GNNNNNN format.
///
/// # Returns
///
/// Vector of matches with position, text, and confidence level.
#[must_use]
pub fn find_korea_rrns_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::korea_rrn::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::KoreaRrn,
            ));
        }
    }

    deduplicate_matches(matches)
}

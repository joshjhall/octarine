//! South Korea Foreign Registration Number (FRN) detection
//!
//! Same shape as RRN (`YYMMDD-GNNNNNN`) but the gender/century digit is 5-8
//! (foreigners). RRN (citizens) uses 1-4 — see `korea_rrn.rs`.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Check if a value matches South Korea FRN format
///
/// Validates the YYMMDD-GNNNNNN format where G is a gender/century digit (5-8).
/// Does NOT validate the checksum — use `validate_korea_frn_with_checksum`.
#[must_use]
pub fn is_korea_frn(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::korea_frn::WITH_DASH.is_match(value)
}

/// Find all South Korea FRN patterns in text
#[must_use]
pub fn find_korea_frns_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::korea_frn::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::KoreaFrn,
            ));
        }
    }

    deduplicate_matches(matches)
}

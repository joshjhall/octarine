//! South Korea Driver License detection
//!
//! Format: `NN-NN-NNNNNN-NN` — region (2) + year (2) + serial (6) + check (2).
//! Region codes 11-28 (Seoul=11, Busan=21, etc.) are enforced by the regex.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Check if a value matches South Korea Driver License format
///
/// Validates the `NN-NN-NNNNNN-NN` shape with the leading region code in
/// `11..=28`. Does NOT validate any checksum — the issue spec does not define
/// one for this identifier.
#[must_use]
pub fn is_korea_driver_license(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::korea_driver_license::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all South Korea Driver License patterns in text
#[must_use]
pub fn find_korea_driver_licenses_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::korea_driver_license::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::KoreaDriverLicense,
            ));
        }
    }

    deduplicate_matches(matches)
}

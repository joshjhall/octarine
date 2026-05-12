//! Driver's license format detection
//!
//! Supports US state-specific formats (CA, TX, etc.) plus a generic
//! `DL#` / `LICENSE:` labeled fallback.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length, get_full_match};

/// Check if a value matches driver's license format
///
/// Supports state-specific formats and generic patterns.
#[must_use]
pub fn is_driver_license(value: &str) -> bool {
    // Check generic pattern
    if patterns::driver_license::GENERIC.is_match(value) {
        return true;
    }

    // Check state-specific patterns
    patterns::driver_license::state_patterns()
        .values()
        .any(|p| p.is_match(value))
}

/// Find all driver's license patterns in text
///
/// Detects both state-specific and generic patterns:
/// - California: "A1234567"
/// - Texas: "12345678"
/// - Generic: "DL# A1234567", "LICENSE: B9876543"
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "Driver License: CA A1234567";
/// let matches = detection::find_driver_licenses_in_text(text);
/// assert!(!matches.is_empty());
/// ```
#[must_use]
pub fn find_driver_licenses_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    // Check state-specific patterns
    for (_state, pattern) in patterns::driver_license::state_patterns() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::DriverLicense,
            ));
        }
    }

    // Check generic pattern
    for capture in patterns::driver_license::GENERIC.captures_iter(text) {
        let full_match = get_full_match(&capture);
        matches.push(IdentifierMatch::high_confidence(
            full_match.start(),
            full_match.end(),
            full_match.as_str().to_string(),
            IdentifierType::DriverLicense,
        ));
    }

    deduplicate_matches(matches)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_driver_license() {
        assert!(is_driver_license("A1234567")); // CA format
        assert!(is_driver_license("12345678")); // TX format
        assert!(!is_driver_license("invalid"));
    }

    #[test]
    fn test_find_driver_licenses_in_text() {
        let text = "Driver License: CA A1234567";
        let matches = find_driver_licenses_in_text(text);
        assert!(!matches.is_empty());
        let first = matches
            .first()
            .expect("Should detect driver license pattern");
        assert_eq!(first.identifier_type, IdentifierType::DriverLicense);
    }

    #[test]
    fn test_empty_input() {
        assert!(!is_driver_license(""));
    }
}

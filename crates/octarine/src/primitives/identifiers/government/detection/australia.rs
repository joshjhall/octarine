//! Australia TFN, ABN, Medicare, and ACN detection

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

/// Check if a value matches Australian Medicare format
///
/// 10 digits with optional 11th individual reference number; first digit 2-6.
#[must_use]
pub fn is_australia_medicare(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::australia_medicare::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Australian Medicare patterns in text
#[must_use]
pub fn find_australia_medicares_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::australia_medicare::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::AustraliaMedicare,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Australian ACN format (9 digits)
#[must_use]
pub fn is_australia_acn(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::australia_acn::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Australian ACN patterns in text
#[must_use]
pub fn find_australia_acns_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::australia_acn::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::AustraliaAcn,
            ));
        }
    }

    deduplicate_matches(matches)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_is_australia_medicare_labeled() {
        assert!(is_australia_medicare("Medicare: 2123 45670 1"));
    }

    #[test]
    fn test_is_australia_medicare_with_spaces() {
        assert!(is_australia_medicare("2123 45670 1"));
    }

    #[test]
    fn test_is_australia_medicare_rejects_first_digit() {
        // First digit must be 2-6
        assert!(!is_australia_medicare("1123 45670 1"));
        assert!(!is_australia_medicare("7123 45670 1"));
    }

    #[test]
    fn test_find_australia_medicares_labeled() {
        let matches = find_australia_medicares_in_text("Patient Medicare 2123 45670 1 attended.");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_find_australia_medicares_clean_text() {
        assert!(find_australia_medicares_in_text("nothing to find").is_empty());
    }

    #[test]
    fn test_is_australia_acn_with_spaces() {
        assert!(is_australia_acn("004 085 616"));
    }

    #[test]
    fn test_is_australia_acn_labeled() {
        assert!(is_australia_acn("ACN: 004085616"));
    }

    #[test]
    fn test_is_australia_acn_rejects_short() {
        assert!(!is_australia_acn("12345678")); // 8 digits
    }

    #[test]
    fn test_find_australia_acns_labeled() {
        let matches = find_australia_acns_in_text("Company ACN 004 085 616 is active.");
        assert!(!matches.is_empty());
        assert!(
            matches
                .iter()
                .any(|m| m.identifier_type == IdentifierType::AustraliaAcn)
        );
    }
}

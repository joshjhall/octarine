//! Singapore NRIC/FIN and UEN detection

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Check if a value matches Singapore NRIC/FIN format
#[must_use]
pub fn is_singapore_nric(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::singapore_nric::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Singapore NRIC/FIN patterns in text
#[must_use]
pub fn find_singapore_nrics_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::singapore_nric::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::SingaporeNric,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches a Singapore UEN layout
///
/// Accepts the three published layouts (business / local company / other entity).
/// Check letter is not validated — Singapore does not publish the algorithm.
#[must_use]
pub fn is_singapore_uen(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::singapore_uen::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Singapore UEN patterns in text
#[must_use]
pub fn find_singapore_uens_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::singapore_uen::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::SingaporeUen,
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
    fn test_is_singapore_uen_business_layout() {
        assert!(is_singapore_uen("12345678K"));
    }

    #[test]
    fn test_is_singapore_uen_local_company_layout() {
        assert!(is_singapore_uen("201912345K"));
    }

    #[test]
    fn test_is_singapore_uen_other_entity_layout() {
        assert!(is_singapore_uen("T12LL1234A"));
    }

    #[test]
    fn test_is_singapore_uen_rejects_bad_shapes() {
        // Wrong digit count
        assert!(!is_singapore_uen("1234567K"));
        // No trailing check letter
        assert!(!is_singapore_uen("123456789"));
        // Lowercase check letter
        assert!(!is_singapore_uen("12345678k"));
        // Other layout with too few digits at end
        assert!(!is_singapore_uen("T12LL123A"));
    }

    #[test]
    fn test_find_singapore_uens_labeled() {
        let matches = find_singapore_uens_in_text("UEN: 201912345K is registered.");
        assert!(!matches.is_empty());
        assert!(
            matches
                .iter()
                .any(|m| m.identifier_type == IdentifierType::SingaporeUen)
        );
    }

    #[test]
    fn test_find_singapore_uens_other_layout_standalone() {
        let matches = find_singapore_uens_in_text("Issued to T12LL1234A today.");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_find_singapore_uens_in_clean_text() {
        assert!(find_singapore_uens_in_text("nothing to see here").is_empty());
    }

    #[test]
    fn test_find_singapore_uens_dedupes_overlapping() {
        // Same UEN reachable via LABELED + BUSINESS pattern; deduplication should collapse.
        let matches = find_singapore_uens_in_text("UEN 12345678K");
        let starts: Vec<usize> = matches.iter().map(|m| m.start).collect();
        // Ensure no two matches start at the same position.
        for (i, &start) in starts.iter().enumerate() {
            for &other in starts.iter().skip(i.saturating_add(1)) {
                assert_ne!(start, other, "duplicate match at position {}", start);
            }
        }
    }
}

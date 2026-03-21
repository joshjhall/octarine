//! Personal name detection
//!
//! Pure detection functions for personal names in various formats.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};

/// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 10_000;

// ============================================================================
// Public API
// ============================================================================

/// Find all personal names in text
///
/// Scans text for name patterns and returns all matches with positions.
/// Includes ReDoS protection for large inputs.
///
/// # Security Considerations
///
/// - **High false positive rate**: Name patterns are heuristic-based
/// - Common words may be detected as names (e.g., "May June" could be months)
/// - Use context validation for production systems
/// - Consider checking against common word lists to reduce false positives
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection::detect_names_in_text;
///
/// let text = "Contact John Smith or Jane Doe, PhD";
/// let matches = detect_names_in_text(text);
/// assert!(matches.len() >= 2);
/// ```
#[allow(clippy::expect_used)]
#[must_use]
pub fn detect_names_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::personal_name::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = capture.get(0).expect("BUG: capture group 0 always exists");
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::PersonalName,
            ));
        }
    }

    super::common::deduplicate_matches(matches)
}

/// Check if value is a personal name
///
/// Uses heuristic pattern matching. High false positive rate.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection::is_name;
///
/// assert!(is_name("John Smith"));
/// assert!(!is_name("hello world"));
/// ```
#[must_use]
pub fn is_name(value: &str) -> bool {
    !detect_names_in_text(value).is_empty()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_detect_names_in_text_first_last() {
        let text = "Contact John Smith for more information";
        let matches = detect_names_in_text(text);
        assert!(!matches.is_empty());
        let first = matches
            .first()
            .expect("Should detect personal name pattern");
        assert_eq!(first.identifier_type, IdentifierType::PersonalName);
        assert!(
            first.matched_text == "John Smith"
                || first.matched_text.contains("John")
                || first.matched_text.contains("Smith")
        );
    }

    #[test]
    fn test_detect_names_in_text_last_first() {
        let text = "Employee: Smith, John";
        let matches = detect_names_in_text(text);
        assert!(!matches.is_empty());
        let first = matches
            .first()
            .expect("Should detect name in last, first format");
        assert_eq!(first.identifier_type, IdentifierType::PersonalName);
    }

    #[test]
    fn test_detect_names_in_text_multiple() {
        let text = "Meeting with John Smith and Jane Doe";
        let matches = detect_names_in_text(text);
        assert!(matches.len() >= 2);
    }

    #[test]
    fn test_find_names_no_matches() {
        let text = "no names just lowercase words";
        let matches = detect_names_in_text(text);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_is_name() {
        assert!(is_name("John Smith"));
        assert!(is_name("Jane Doe"));
        assert!(!is_name("hello world")); // All lowercase
        assert!(!is_name("12345"));
    }

    #[test]
    fn test_find_names_edge_cases() {
        // Multiple names
        let text = "John Smith and Jane Doe";
        let matches = detect_names_in_text(text);
        assert!(matches.len() >= 2);

        // Names with titles
        let text = "Dr. John Smith";
        let matches = detect_names_in_text(text);
        assert!(!matches.is_empty());

        // Hyphenated names
        let text = "Mary Jane Watson-Parker";
        let matches = detect_names_in_text(text);
        assert!(!matches.is_empty());

        // All lowercase (should not match)
        let text = "john smith";
        let matches = detect_names_in_text(text);
        assert_eq!(matches.len(), 0);
    }
}

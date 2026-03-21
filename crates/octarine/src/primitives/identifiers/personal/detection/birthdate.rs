//! Birthdate detection
//!
//! Pure detection functions for dates of birth in various formats.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};

/// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 10_000;

// ============================================================================
// Public API
// ============================================================================

/// Find all birthdates in text
///
/// Scans text for date patterns that may represent dates of birth.
/// Detects ISO format (YYYY-MM-DD), US format (MM/DD/YYYY),
/// European format (DD/MM/YYYY), and month name formats.
/// Includes ReDoS protection for large inputs.
///
/// # Security Considerations
///
/// - **GDPR Article 9**: Date of birth is sensitive personal data
/// - **CCPA**: Considered personal information requiring disclosure
/// - **HIPAA**: Protected Health Information (PHI) when linked to individuals
/// - May require special handling under data protection regulations
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection::detect_birthdates_in_text;
///
/// let text = "Born on 1990-05-15 or DOB: 03/22/1985";
/// let matches = detect_birthdates_in_text(text);
/// assert!(matches.len() >= 2);
/// ```
#[allow(clippy::expect_used)]
#[must_use]
pub fn detect_birthdates_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::birthdate::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = capture.get(0).expect("BUG: capture group 0 always exists");
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::Birthdate,
            ));
        }
    }

    super::common::deduplicate_matches(matches)
}

/// Check if value is a birthdate
///
/// Detects ISO, US, EU, and month name date formats.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection::is_birthdate;
///
/// assert!(is_birthdate("1990-05-15"));
/// assert!(is_birthdate("05/15/1990"));
/// assert!(!is_birthdate("not a date"));
/// ```
#[must_use]
pub fn is_birthdate(value: &str) -> bool {
    !detect_birthdates_in_text(value).is_empty()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_find_birthdates_iso_format() {
        let text = "Born on 1990-05-15";
        let matches = detect_birthdates_in_text(text);
        assert!(!matches.is_empty());
        let first = matches.first().expect("Should detect ISO format birthdate");
        assert_eq!(first.identifier_type, IdentifierType::Birthdate);
        assert_eq!(first.matched_text, "1990-05-15");
    }

    #[test]
    fn test_find_birthdates_us_format() {
        let text = "DOB: 03/22/1985";
        let matches = detect_birthdates_in_text(text);
        assert!(!matches.is_empty());
        let first = matches.first().expect("Should detect US format birthdate");
        assert_eq!(first.identifier_type, IdentifierType::Birthdate);
    }

    #[test]
    fn test_find_birthdates_month_name() {
        let text = "Birthday: May 15, 1990";
        let matches = detect_birthdates_in_text(text);
        assert!(!matches.is_empty());
        let first = matches
            .first()
            .expect("Should detect month name format birthdate");
        assert_eq!(first.identifier_type, IdentifierType::Birthdate);
    }

    #[test]
    fn test_find_birthdates_multiple_formats() {
        let text = "Dates: 1990-05-15 and 03/22/1985 and May 10, 1988";
        let matches = detect_birthdates_in_text(text);
        assert!(matches.len() >= 3);
    }

    #[test]
    fn test_find_birthdates_no_matches() {
        let text = "No dates in this text";
        let matches = detect_birthdates_in_text(text);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_is_birthdate() {
        // ISO format
        assert!(is_birthdate("1990-05-15"));
        // US format
        assert!(is_birthdate("05/15/1990"));
        // Month name
        assert!(is_birthdate("May 15, 1990"));
        // Not dates
        assert!(!is_birthdate("not a date"));
        assert!(!is_birthdate("12345"));
    }

    #[test]
    fn test_find_birthdates_edge_cases() {
        // ISO format
        let text = "Born on 1990-05-15";
        let matches = detect_birthdates_in_text(text);
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().map(|m| m.matched_text.as_str()),
            Some("1990-05-15")
        );

        // US format
        let text = "DOB: 05/15/1990";
        let matches = detect_birthdates_in_text(text);
        assert!(!matches.is_empty());

        // European format (day > 12)
        let text = "Born 31/12/1990";
        let matches = detect_birthdates_in_text(text);
        assert!(!matches.is_empty());

        // Month name formats
        let text = "May 15, 1990 and 15 May 1990";
        let matches = detect_birthdates_in_text(text);
        assert!(!matches.is_empty());
    }
}

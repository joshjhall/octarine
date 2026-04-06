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

/// PII context keywords that indicate a date is personally identifiable
const PII_CONTEXT_KEYWORDS: &[&str] = &[
    "dob",
    "date of birth",
    "born",
    "birthday",
    "birthdate",
    "birth date",
    "d.o.b.",
    "date_of_birth",
    "admission",
    "discharge",
    "procedure",
    "appointment",
];

/// Check if a date found in text appears in a PII-relevant context
///
/// Examines the 50 characters preceding the match for PII-related keywords
/// like "DOB", "born", "birthday", medical terms, etc.
///
/// # Examples
///
/// ```ignore
/// assert!(is_date_in_pii_context("DOB: 1990-01-15", 5));
/// assert!(!is_date_in_pii_context("version 1990-01-15", 8));
/// ```
#[must_use]
pub fn is_date_in_pii_context(text: &str, match_start: usize) -> bool {
    let prefix_len = 50.min(match_start);
    if let Some(prefix) = text.get(match_start.saturating_sub(prefix_len)..match_start) {
        let prefix_lower = prefix.to_lowercase();
        return PII_CONTEXT_KEYWORDS
            .iter()
            .any(|kw| prefix_lower.contains(kw));
    }
    false
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

    // ── New format tests ────────────────────────────────────────────

    #[test]
    fn test_day_month_abbreviated() {
        assert!(is_birthdate("15-Jan-1990"));
        assert!(is_birthdate("1 Feb 2000"));
        assert!(is_birthdate("31-Dec-1999"));
        assert!(is_birthdate("01.Mar.1985"));
    }

    #[test]
    fn test_year_first_slashes() {
        assert!(is_birthdate("1990/01/15"));
        assert!(is_birthdate("2000/12/31"));
        assert!(!is_birthdate("1990/13/15")); // Invalid month
    }

    #[test]
    fn test_two_digit_year() {
        assert!(is_birthdate("01/15/90"));
        assert!(is_birthdate("12-31-00"));
        assert!(!is_birthdate("13/15/90")); // Invalid month
    }

    #[test]
    fn test_iso_with_time() {
        let text = "Timestamp: 1990-01-15T10:30:00";
        let matches = detect_birthdates_in_text(text);
        assert!(!matches.is_empty(), "ISO with time should be detected");
    }

    #[test]
    fn test_detect_new_formats_in_text() {
        let text = "Born 15-Jan-1990, record 1990/01/15, short 01/15/90";
        let matches = detect_birthdates_in_text(text);
        assert!(
            matches.len() >= 3,
            "expected at least 3 matches, got {}",
            matches.len()
        );
    }

    // ── PII context tests ──────────────────────────────────────────

    #[test]
    fn test_pii_context_detection() {
        assert!(is_date_in_pii_context("DOB: 1990-01-15", 5));
        assert!(is_date_in_pii_context("Date of birth: 1990-01-15", 16));
        assert!(is_date_in_pii_context("Patient born 1990-01-15", 14));
        assert!(is_date_in_pii_context("Birthday: 1990-01-15", 10));
        assert!(is_date_in_pii_context("Admission date 1990-01-15", 16));
    }

    #[test]
    fn test_pii_context_not_detected() {
        assert!(!is_date_in_pii_context("Version 1990-01-15", 8));
        assert!(!is_date_in_pii_context("Released 1990-01-15", 9));
        assert!(!is_date_in_pii_context("1990-01-15", 0)); // No prefix
    }

    // ── False positive tests ───────────────────────────────────────

    #[test]
    fn test_version_numbers_not_detected() {
        let text = "Use version 1.2.3 for this build";
        let matches = detect_birthdates_in_text(text);
        assert!(
            matches.is_empty(),
            "version numbers should not match: {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
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

//! Common detection utilities and aggregate functions
//!
//! Provides aggregate detection functions that span multiple personal identifier types.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};

use super::birthdate::detect_birthdates_in_text;
use super::email::{detect_emails_in_text, is_email};
use super::name::detect_names_in_text;
use super::phone::{detect_phones_in_text, is_phone_number};

// ============================================================================
// Aggregate Detection Functions
// ============================================================================

/// Find personal identifier type from input string
///
/// Automatically finds the type of personal identifier (PII) from the input.
/// Checks for emails, phone numbers, and usernames in order of specificity.
///
/// **Note**: SSN detection is in `government` module since it's a government-issued ID
///
/// # Arguments
///
/// * `value` - The string to analyze for personal identifier patterns
///
/// # Returns
///
/// * `Some(IdentifierType::Email)` - If the value matches email format
/// * `Some(IdentifierType::PhoneNumber)` - If the value matches phone formats
/// * `Some(IdentifierType::Username)` - If the value looks like a username
/// * `None` - If no personal identifier pattern is detected
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection::find_personal_identifier;
/// use crate::primitives::identifiers::types::IdentifierType;
///
/// // Email detection
/// let result = find_personal_identifier("john.doe@example.com");
/// assert_eq!(result, Some(IdentifierType::Email));
///
/// // Phone detection
/// let result = find_personal_identifier("+1-555-123-4567");
/// assert_eq!(result, Some(IdentifierType::PhoneNumber));
/// ```
///
/// # Security Considerations
///
/// - Username detection is heuristic and may have false positives
/// - All detected identifiers should be treated as PII under privacy regulations
///
/// # Implementation Notes
///
/// Detection is performed in this order for accuracy:
/// 1. Email (most specific pattern)
/// 2. Phone Number (E.164 and US formats)
/// 3. Username (least specific, heuristic-based)
pub fn find_personal_identifier(value: &str) -> Option<IdentifierType> {
    let trimmed = value.trim();

    // Check for email first (very specific pattern)
    if patterns::email::EXACT.is_match(trimmed) {
        return Some(IdentifierType::Email);
    }

    // Check for phone numbers
    if patterns::phone::E164_EXACT.is_match(trimmed) || patterns::phone::US_EXACT.is_match(trimmed)
    {
        return Some(IdentifierType::PhoneNumber);
    }

    // Check for username (but only if it doesn't look like something else)
    // This is a heuristic check - usernames are hard to detect definitively
    if patterns::username::STANDARD.is_match(trimmed)
        && !trimmed.contains('@')
        && !trimmed.contains('.')
        && trimmed.len() >= 3
        && trimmed.len() <= 32
    {
        // Don't classify as username if it looks like other identifier types
        if !trimmed.chars().all(|c| c.is_ascii_digit()) {
            return Some(IdentifierType::Username);
        }
    }

    None
}

/// Check if value is a personal identifier
#[must_use]
pub fn is_personal_identifier(value: &str) -> bool {
    find_personal_identifier(value).is_some()
}

/// Detect personal identifier type (dual-API contract alias).
///
/// Every identifier domain exposes the pair `detect_{domain}_identifier` /
/// `is_{domain}_identifier`. This is the aggregate entry point that returns
/// which specific `IdentifierType` matched — the bool counterpart is
/// [`is_personal_identifier`].
///
/// Semantically identical to [`find_personal_identifier`]; kept as an alias
/// for contract consistency across domains.
#[must_use]
pub fn detect_personal_identifier(value: &str) -> Option<IdentifierType> {
    find_personal_identifier(value)
}

/// Check if value is PII (any personal identifier)
///
/// Alias for `is_personal_identifier` - checks if a single value matches
/// a personal identifier pattern (email, phone, username).
#[must_use]
pub fn is_pii(value: &str) -> bool {
    is_personal_identifier(value)
}

/// Detect all personal identifiers in text
///
/// Comprehensive scanner that detects all PII types in a single pass:
/// emails, phones, names, and birthdates.
///
/// # Returns
///
/// Vector of `IdentifierMatch` sorted by position, deduplicated.
///
/// # Performance
///
/// O(n * p) where n is text length and p is number of patterns.
/// For very large documents, consider async batch processing.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection::detect_all_pii_in_text;
///
/// let text = "Contact John Smith at user@example.com or +1-555-123-4567. Born: 1990-05-15";
/// let matches = detect_all_pii_in_text(text);
///
/// // Should find: name, email, phone, birthdate
/// assert!(matches.len() >= 4);
/// ```
#[must_use]
pub fn detect_all_pii_in_text(text: &str) -> Vec<IdentifierMatch> {
    let mut all_matches = Vec::new();

    // Collect all PII types
    all_matches.extend(detect_emails_in_text(text));
    all_matches.extend(detect_phones_in_text(text));
    all_matches.extend(detect_names_in_text(text));
    all_matches.extend(detect_birthdates_in_text(text));

    // Deduplicate overlapping matches across types
    deduplicate_matches(all_matches)
}

/// Check if personal identifiers are present in text
///
/// Returns true if text contains any email, phone, name, or birthdate.
/// More thorough than `is_pii()` which only checks exact value match.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection::is_pii_present;
///
/// assert!(is_pii_present("Email me at user@example.com"));
/// assert!(!is_pii_present("No PII here"));
/// ```
#[must_use]
pub fn is_pii_present(text: &str) -> bool {
    !detect_all_pii_in_text(text).is_empty()
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Deduplicate overlapping matches (keep longest/highest confidence)
///
/// When multiple patterns match the same text position, keeps only the
/// longest and highest confidence match.
pub fn deduplicate_matches(mut matches: Vec<IdentifierMatch>) -> Vec<IdentifierMatch> {
    if matches.is_empty() {
        return matches;
    }

    // Sort by position, then length (descending), then confidence
    matches.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| b.len().cmp(&a.len()))
            .then_with(|| b.confidence.cmp(&a.confidence))
    });

    let mut deduped = Vec::new();
    let mut last_end = 0;

    for m in matches {
        if m.start >= last_end {
            last_end = m.end;
            deduped.push(m);
        }
    }

    deduped
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_find_email() {
        assert_eq!(
            find_personal_identifier("user@example.com"),
            Some(IdentifierType::Email)
        );
    }

    #[test]
    fn test_find_phone() {
        assert_eq!(
            find_personal_identifier("+15551234567"),
            Some(IdentifierType::PhoneNumber)
        );
        assert_eq!(
            find_personal_identifier("(555) 123-4567"),
            Some(IdentifierType::PhoneNumber)
        );
    }

    #[test]
    fn test_find_username() {
        assert_eq!(
            find_personal_identifier("john_doe"),
            Some(IdentifierType::Username)
        );
        // Should not detect email as username
        assert_ne!(
            find_personal_identifier("user@example.com"),
            Some(IdentifierType::Username)
        );
    }

    #[test]
    fn test_is_pii() {
        assert!(is_pii("user@example.com"));
        assert!(is_pii("+15551234567"));
        assert!(!is_pii("550e8400-e29b-41d4-a716-446655440000")); // UUID is not PII
    }

    #[test]
    fn test_detect_personal_identifier() {
        assert_eq!(
            detect_personal_identifier("user@example.com"),
            Some(IdentifierType::Email)
        );
        assert_eq!(
            detect_personal_identifier("+15551234567"),
            Some(IdentifierType::PhoneNumber)
        );
        assert_eq!(
            detect_personal_identifier("john_doe"),
            Some(IdentifierType::Username)
        );
        assert_eq!(detect_personal_identifier(""), None);
        // UUID is not PII
        assert_eq!(
            detect_personal_identifier("550e8400-e29b-41d4-a716-446655440000"),
            None
        );
    }

    #[test]
    fn test_detect_all_pii_in_text() {
        let text = "Contact John Smith at user@example.com or +1-555-123-4567. Born: 1990-05-15";
        let matches = detect_all_pii_in_text(text);

        // Should find multiple PII types
        assert!(matches.len() >= 3); // At minimum: email, phone, date

        // Check that different types are found
        let types: Vec<_> = matches.iter().map(|m| &m.identifier_type).collect();
        assert!(types.contains(&&IdentifierType::Email));
        assert!(types.contains(&&IdentifierType::PhoneNumber));
        assert!(types.contains(&&IdentifierType::Birthdate));
    }

    #[test]
    fn test_detect_all_pii_empty_text() {
        let matches = detect_all_pii_in_text("");
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_detect_all_pii_no_matches() {
        let text = "This text has no personal identifiers at all";
        let matches = detect_all_pii_in_text(text);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_is_pii_present() {
        assert!(is_pii_present("Email: user@example.com"));
        assert!(is_pii_present("Call +1-555-123-4567"));
        assert!(is_pii_present("Born on 1990-05-15"));
        assert!(!is_pii_present("No PII here"));
    }

    #[test]
    fn test_deduplicate_matches() {
        // Create overlapping matches
        let matches = vec![
            IdentifierMatch::high_confidence(0, 10, "test1".into(), IdentifierType::Email),
            IdentifierMatch::high_confidence(0, 15, "test1long".into(), IdentifierType::Email),
            IdentifierMatch::high_confidence(20, 30, "test2".into(), IdentifierType::Email),
        ];

        let deduped = deduplicate_matches(matches);
        // Should keep the longer match at position 0 and the match at position 20
        assert_eq!(deduped.len(), 2);
        let first = deduped.first().expect("Should have first match");
        let second = deduped.get(1).expect("Should have second match");
        assert_eq!(first.matched_text, "test1long");
        assert_eq!(second.matched_text, "test2");
    }

    #[test]
    fn test_overlapping_matches() {
        let matches = vec![
            IdentifierMatch::high_confidence(
                0,
                20,
                "user@example.com".to_string(),
                IdentifierType::Email,
            ),
            IdentifierMatch::high_confidence(
                0,
                16,
                "user@example".to_string(),
                IdentifierType::Email,
            ),
        ];
        let deduped = deduplicate_matches(matches);
        assert_eq!(deduped.len(), 1);
        assert_eq!(
            deduped.first().map(|m| m.matched_text.as_str()),
            Some("user@example.com")
        );
    }

    #[test]
    fn test_adjacent_matches() {
        // Adjacent (non-overlapping) matches should all be kept
        let matches = vec![
            IdentifierMatch::high_confidence(0, 10, "first".into(), IdentifierType::Email),
            IdentifierMatch::high_confidence(10, 20, "second".into(), IdentifierType::Email),
            IdentifierMatch::high_confidence(20, 30, "third".into(), IdentifierType::Email),
        ];
        let deduped = deduplicate_matches(matches);
        assert_eq!(deduped.len(), 3);
    }

    #[test]
    fn test_username_detection_edge_cases() {
        // Valid usernames
        assert_eq!(
            find_personal_identifier("john_doe"),
            Some(IdentifierType::Username)
        );
        assert_eq!(
            find_personal_identifier("user123"),
            Some(IdentifierType::Username)
        );

        // At length boundaries
        assert_eq!(
            find_personal_identifier("abc"), // Minimum 3 chars
            Some(IdentifierType::Username)
        );

        // Should NOT be username
        assert_ne!(
            find_personal_identifier("ab"), // Too short
            Some(IdentifierType::Username)
        );
        assert_ne!(
            find_personal_identifier("12345"), // All digits
            Some(IdentifierType::Username)
        );
        assert_ne!(
            find_personal_identifier("user.name"), // Contains dot
            Some(IdentifierType::Username)
        );
    }

    #[test]
    fn test_empty_input_all_functions() {
        assert!(!is_email(""));
        assert!(!is_phone_number(""));
        assert!(!is_personal_identifier(""));
        assert!(!is_pii(""));
        assert!(!is_pii_present(""));
        assert_eq!(detect_all_pii_in_text("").len(), 0);
    }
}

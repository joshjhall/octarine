//! US Social Security Number detection
//!
//! - Format match: regex against SSA patterns (`XXX-XX-XXXX` and variants).
//! - SSA structural rules: reject area 000/666, group 00, serial 0000.
//! - ITIN reclassification: area 900-999 is NOT an SSN (callers reclassify
//!   text-scan matches to `IdentifierType::TaxId`).
//! - Test/advertising pattern filtering via `common::is_test_ssn`.

use super::super::super::common::patterns;
use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};
use super::super::common::{is_itin_area, is_test_ssn};
use super::helpers::{MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length, get_full_match};

/// Extract only ASCII digits from a string
fn extract_digits(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Check if an SSN candidate passes SSA structural rules
///
/// Rejects known-invalid patterns per Social Security Administration rules:
/// - Area 000 (never assigned)
/// - Area 666 (never assigned)
/// - Group 00 (never assigned)
/// - Serial 0000 (never assigned)
/// - Known test/advertising SSNs and sequential/repeating patterns
///
/// Does NOT reject area 900-999 (ITINs) — caller handles reclassification.
fn is_valid_ssn_candidate(matched_text: &str) -> bool {
    let digits = extract_digits(matched_text);
    if digits.len() != 9 {
        return false;
    }

    let area = &digits[0..3];
    let group = &digits[3..5];
    let serial = &digits[5..9];

    // SSA Rule: Area 000 is never valid
    if area == "000" {
        return false;
    }

    // SSA Rule: Area 666 is reserved/never issued
    if area == "666" {
        return false;
    }

    // SSA Rule: Group 00 is invalid
    if group == "00" {
        return false;
    }

    // SSA Rule: Serial 0000 is invalid
    if serial == "0000" {
        return false;
    }

    // Reject test/advertising/sequential/repeating patterns
    if is_test_ssn(matched_text) {
        return false;
    }

    true
}

/// Check if a value matches SSN format and passes SSA structural rules
///
/// Validates format (XXX-XX-XXXX or variants) and rejects known-invalid
/// patterns: area 000/666, group 00, serial 0000, test SSNs, and ITINs (900-999).
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// assert!(detection::is_ssn("517-29-8346"));
/// assert!(detection::is_ssn("628 41 9053"));
/// assert!(!detection::is_ssn("000-12-3456")); // Invalid area
/// assert!(!detection::is_ssn("900-70-1234")); // ITIN, not SSN
/// ```
#[must_use]
pub fn is_ssn(value: &str) -> bool {
    if !patterns::ssn::all().iter().any(|p| p.is_match(value)) {
        return false;
    }

    let digits = extract_digits(value);
    if digits.len() != 9 {
        return false;
    }

    // Reclassify ITINs (area 900-999) — not SSNs
    if is_itin_area(value) {
        return false;
    }

    is_valid_ssn_candidate(value)
}

/// Find all SSN patterns in text with false positive filtering
///
/// Scans text for Social Security Number patterns and filters out:
/// - Invalid SSA patterns (area 000/666, group 00, serial 0000)
/// - Known test/advertising SSNs (078-05-1120, 123-45-6789, etc.)
/// - Sequential and repeating digit patterns
/// - ITINs (area 900-999) — reclassified as `IdentifierType::TaxId`
///
/// Labeled patterns ("SSN: ...") get High confidence; bare patterns get Medium.
///
/// # Returns
///
/// Vector of matches with position, text, and confidence level.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "Employee SSN: 517-29-8346";
/// let matches = detection::find_ssns_in_text(text);
/// assert_eq!(matches.len(), 1);
/// ```
#[must_use]
pub fn find_ssns_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for (pattern_idx, pattern) in patterns::ssn::all().iter().enumerate() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            let matched_text = full_match.as_str();

            // Reclassify ITINs (area 900-999) as TaxId
            if is_itin_area(matched_text) {
                matches.push(IdentifierMatch::high_confidence(
                    full_match.start(),
                    full_match.end(),
                    matched_text.to_string(),
                    IdentifierType::TaxId,
                ));
                continue;
            }

            // Filter out false positives using SSA structural rules
            if !is_valid_ssn_candidate(matched_text) {
                continue;
            }

            // Labeled patterns (index 0) get High confidence; bare patterns get Medium
            let confidence = if pattern_idx == 0 {
                DetectionConfidence::High
            } else {
                DetectionConfidence::Medium
            };

            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                matched_text.to_string(),
                IdentifierType::Ssn,
                confidence,
            ));
        }
    }

    deduplicate_matches(matches)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_ssn() {
        // Valid SSNs
        assert!(is_ssn("517-29-8346"));
        assert!(is_ssn("628 41 9053"));

        // Invalid: no separators
        assert!(!is_ssn("234567890"));
        assert!(!is_ssn("invalid"));
    }

    #[test]
    fn test_is_ssn_rejects_invalid_area() {
        assert!(!is_ssn("000-12-3456")); // Area 000 never assigned
        assert!(!is_ssn("666-12-3456")); // Area 666 never assigned
    }

    #[test]
    fn test_is_ssn_rejects_invalid_group_serial() {
        assert!(!is_ssn("234-00-5678")); // Group 00 never assigned
        assert!(!is_ssn("234-56-0000")); // Serial 0000 never assigned
    }

    #[test]
    fn test_is_ssn_rejects_test_patterns() {
        assert!(!is_ssn("123-45-6789")); // Sequential
        assert!(!is_ssn("078-05-1120")); // Woolworth's advertising SSN
        assert!(!is_ssn("219-09-9999")); // SSA example
        assert!(!is_ssn("457-55-5462")); // IRS example
        assert!(!is_ssn("111-11-1111")); // Repeating digits
        assert!(!is_ssn("555-55-5555")); // Repeating digits
    }

    #[test]
    fn test_is_ssn_rejects_itin_range() {
        // 900-999 area codes are ITINs, not SSNs
        assert!(!is_ssn("900-70-1234"));
        assert!(!is_ssn("912-34-5678"));
        assert!(!is_ssn("999-88-7654"));
    }

    #[test]
    fn test_empty_input() {
        assert!(!is_ssn(""));
        assert_eq!(find_ssns_in_text("").len(), 0);
    }

    #[test]
    fn test_find_ssns_in_text() {
        let text = "Employee SSN: 517-29-8346 and contractor SSN: 142-58-3697";
        let matches = find_ssns_in_text(text);
        assert_eq!(matches.len(), 2);
        let first = matches.first().expect("Should detect SSN patterns");
        assert_eq!(first.identifier_type, IdentifierType::Ssn);
        // Labeled matches get High confidence
        assert_eq!(first.confidence, DetectionConfidence::High);
    }

    #[test]
    fn test_find_ssns_bare_pattern_medium_confidence() {
        let text = "The number is 517-29-8346 in the file";
        let matches = find_ssns_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect bare SSN");
        assert_eq!(first.confidence, DetectionConfidence::Medium);
    }

    #[test]
    fn test_find_ssns_rejects_false_positives() {
        // These should all be filtered out
        let text = "area 000-12-3456 and 666-12-3456 and 234-00-5678 and 234-56-0000";
        let matches = find_ssns_in_text(text);
        assert_eq!(matches.len(), 0, "Should reject all invalid SSN patterns");
    }

    #[test]
    fn test_find_ssns_rejects_test_patterns() {
        let text = "test 123-45-6789 and 078-05-1120 and 111-11-1111";
        let matches = find_ssns_in_text(text);
        assert_eq!(matches.len(), 0, "Should reject test/advertising SSNs");
    }

    #[test]
    fn test_find_ssns_reclassifies_itin() {
        let text = "ITIN holder SSN: 900-70-1234 and 912-34-5678";
        let matches = find_ssns_in_text(text);
        // Both should be reclassified as TaxId
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::TaxId),
            "900-999 area codes should be classified as TaxId, not Ssn"
        );
        assert!(
            !matches.is_empty(),
            "ITINs should still be detected as TaxId"
        );
    }
}

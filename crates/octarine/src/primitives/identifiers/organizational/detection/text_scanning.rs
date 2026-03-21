// SAFETY: All expect() calls in this module are on capture.get(0), which always exists
// per the regex spec (group 0 is the full match and is guaranteed to exist).
#![allow(clippy::expect_used)]

//! Text scanning for organizational IDs
//!
//! Functions for finding all organizational identifiers in text documents:
//! - Employee IDs
//! - Student IDs
//! - Badge numbers

use super::super::super::common::patterns::organizational;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::constants::{MAX_INPUT_LENGTH, exceeds_safe_length};

// ============================================================================
// Text Scanning (Find All Matches in Documents)
// ============================================================================

/// Find all employee ID patterns in text
///
/// Scans text for employee identification numbers with various formats:
/// - E-numbers: "E123456"
/// - Labeled: "Employee: EMP00123"
/// - Badge: "BADGE# 98765"
///
/// # Returns
///
/// Vector of matches with position, text, and confidence level.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::organizational::find_employee_ids_in_text;
///
/// let text = "Employee ID: E123456";
/// let matches = find_employee_ids_in_text(text);
/// assert_eq!(matches.len(), 1);
/// ```
pub fn find_employee_ids_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in organizational::employee_id::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = capture.get(0).expect("BUG: capture group 0 always exists");
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::EmployeeId,
            ));
        }
    }

    matches
}

/// Find all student ID patterns in text
///
/// Scans for educational institution identification:
/// - S-numbers: "S12345678"
/// - Labeled: "Student: STU123456"
/// - Formatted: "900-00-0001" (needs context checking)
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::organizational::find_student_ids_in_text;
///
/// let text = "Student ID: S12345678";
/// let matches = find_student_ids_in_text(text);
/// assert_eq!(matches.len(), 1);
/// ```
pub fn find_student_ids_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in organizational::student_id::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = capture.get(0).expect("BUG: capture group 0 always exists");

            // Only include if it looks like a student ID context
            // (to avoid false positives with SSN format)
            if is_likely_student_id_context(text, full_match.as_str()) {
                matches.push(IdentifierMatch::high_confidence(
                    full_match.start(),
                    full_match.end(),
                    full_match.as_str().to_string(),
                    IdentifierType::StudentId,
                ));
            }
        }
    }

    matches
}

/// Check if a match is likely a student ID based on surrounding context
fn is_likely_student_id_context(text: &str, potential_id: &str) -> bool {
    // S-number format is unambiguous
    if potential_id.starts_with('S') || potential_id.starts_with('s') {
        return true;
    }

    // For XXX-XX-XXXX format, check for student-related keywords
    let context_keywords = [
        "student",
        "stu",
        "enrollment",
        "university",
        "college",
        "school",
    ];

    let id_pos = text.find(potential_id).unwrap_or(0);
    let start = id_pos.saturating_sub(30);
    let end = id_pos
        .saturating_add(potential_id.len())
        .saturating_add(30)
        .min(text.len());
    let context = &text[start..end].to_lowercase();

    context_keywords
        .iter()
        .any(|&keyword| context.contains(keyword))
}

/// Find all badge number patterns in text
///
/// Scans for physical security badges and facility access IDs:
/// - Labeled: "BADGE# 98765", "BADGE-12345"
/// - ID format: "ID 12345", "ID#98765"
///
/// Badge numbers grant facility access and should be protected in logs.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::organizational::find_badge_numbers_in_text;
///
/// let text = "Badge: BADGE# 98765";
/// let matches = find_badge_numbers_in_text(text);
/// assert_eq!(matches.len(), 1);
/// ```
pub fn find_badge_numbers_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in organizational::badge_number::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = capture.get(0).expect("BUG: capture group 0 always exists");
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::BadgeNumber,
            ));
        }
    }

    matches
}

/// Find all organizational ID patterns in text
///
/// Comprehensive scan for all organization-issued identifiers:
/// - Employee IDs, student IDs, badge numbers
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::organizational::find_all_organizational_ids_in_text;
///
/// let text = "Employee: E123456, Student: S98765432, Badge: BADGE# 98765";
/// let matches = find_all_organizational_ids_in_text(text);
/// assert!(matches.len() >= 3);
/// ```
pub fn find_all_organizational_ids_in_text(text: &str) -> Vec<IdentifierMatch> {
    let mut all_matches = Vec::new();

    all_matches.extend(find_employee_ids_in_text(text));
    all_matches.extend(find_student_ids_in_text(text));
    all_matches.extend(find_badge_numbers_in_text(text));

    // Sort by position in text
    all_matches.sort_by_key(|m| m.start);

    all_matches
}

/// Check if text contains any organizational identifiers
///
/// Convenience function for quick boolean check without collecting matches.
/// Returns `true` if text contains any employee IDs, student IDs, or badge numbers.
///
/// # Performance
///
/// This function is optimized for early exit - returns as soon as any identifier
/// is found without scanning the entire text.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::organizational::is_organizational_present;
///
/// assert!(is_organizational_present("Employee ID: E123456"));
/// assert!(is_organizational_present("Student: S12345678"));
/// assert!(is_organizational_present("Badge: BADGE# 98765"));
/// assert!(!is_organizational_present("Clean text with no IDs"));
/// ```
#[must_use]
pub fn is_organizational_present(text: &str) -> bool {
    // Early exit for very large inputs
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return false;
    }

    // Check each pattern type - return immediately on first match
    for pattern in organizational::employee_id::all() {
        if pattern.is_match(text) {
            return true;
        }
    }

    for pattern in organizational::student_id::all() {
        if pattern.is_match(text) {
            // Check context for XXX-XX-XXXX format
            for capture in pattern.captures_iter(text) {
                let full_match = capture.get(0).expect("BUG: capture group 0 always exists");
                if is_likely_student_id_context(text, full_match.as_str()) {
                    return true;
                }
            }
        }
    }

    for pattern in organizational::badge_number::all() {
        if pattern.is_match(text) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== Text Scanning Tests =====

    #[test]
    fn test_find_employee_ids_in_text() {
        let text = "Employee: E123456 and contractor: E987654";
        let matches = find_employee_ids_in_text(text);
        assert_eq!(matches.len(), 2);
        let first = matches.first().expect("Should detect employee ID patterns");
        assert_eq!(first.identifier_type, IdentifierType::EmployeeId);
    }

    #[test]
    fn test_find_student_ids_in_text() {
        let text = "Student ID: S12345678";
        let matches = find_student_ids_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect student ID pattern");
        assert_eq!(first.identifier_type, IdentifierType::StudentId);
    }

    #[test]
    fn test_student_id_requires_context() {
        // XXX-XX-XXXX format without student context should not match
        let text = "Reference number: 900-00-0001";
        let matches = find_student_ids_in_text(text);
        assert_eq!(matches.len(), 0);

        // Same format with student context should match
        let text = "Student enrollment: 900-00-0001";
        let matches = find_student_ids_in_text(text);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_find_badge_numbers_in_text() {
        let text = "Badge: BADGE# 98765";
        let matches = find_badge_numbers_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect badge number pattern");
        assert_eq!(first.identifier_type, IdentifierType::BadgeNumber);
    }

    #[test]
    fn test_find_badge_id_format() {
        let text = "ID 12345 and ID#67890";
        let matches = find_badge_numbers_in_text(text);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_find_multiple_badge_numbers() {
        let text = "Badges: BADGE# 98765, BADGE-12345, ID 11111";
        let matches = find_badge_numbers_in_text(text);
        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn test_find_all_organizational_ids() {
        let text = "Employee: E123456, Student: S98765432, Badge: 12345";
        let matches = find_all_organizational_ids_in_text(text);
        assert!(matches.len() >= 2); // Employee and Student

        // Verify sorted by position
        for window in matches.windows(2) {
            let [prev, curr] = window else { continue };
            assert!(curr.start >= prev.start);
        }
    }

    #[test]
    fn test_no_matches_in_clean_text() {
        let text = "This text contains no organizational IDs";
        let matches = find_all_organizational_ids_in_text(text);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_multiple_employee_ids_same_text() {
        let text = "Team: E123456, E234567, E345678";
        let matches = find_employee_ids_in_text(text);
        assert_eq!(matches.len(), 3);
    }

    #[test]
    fn test_is_organizational_present() {
        // Employee ID
        assert!(is_organizational_present("Employee: E123456"));
        assert!(is_organizational_present("Staff member EMP00123"));

        // Student ID
        assert!(is_organizational_present("Student ID: S12345678"));
        assert!(is_organizational_present("Student enrollment: 900-00-0001"));

        // Badge number
        assert!(is_organizational_present("Badge: BADGE# 98765"));
        assert!(is_organizational_present("Access ID 12345"));

        // Clean text
        assert!(!is_organizational_present("No identifiers here"));
        assert!(!is_organizational_present("Just some text"));

        // False positive prevention - XXX-XX-XXXX without context
        assert!(!is_organizational_present("Reference: 900-00-0001"));
    }

    #[test]
    fn test_unicode_in_text() {
        // Text scanning should handle unicode safely
        let text = "Employee 👋: E123456 and 学生: S12345678";
        let matches = find_all_organizational_ids_in_text(text);
        assert_eq!(matches.len(), 2); // Should find both IDs despite unicode
    }

    #[test]
    fn test_redos_protection_text_scanning() {
        // Text scanning with very long input
        let long_text = "x".repeat(20_000);
        let matches = find_all_organizational_ids_in_text(&long_text);
        assert_eq!(matches.len(), 0); // Should return empty, not hang
    }

    #[test]
    fn test_boundary_edge_cases() {
        // Exactly at boundaries
        let text = "IDs: E12345 E12345678 S1234567 S123456789";
        let matches = find_all_organizational_ids_in_text(text);
        assert_eq!(matches.len(), 4); // All at min/max boundaries

        // Mixed valid and invalid lengths
        let text = "Short: E123 E12345 E123456789";
        let matches = find_employee_ids_in_text(text);
        assert_eq!(matches.len(), 1); // Only E12345 is valid
    }

    #[test]
    fn test_overlapping_patterns_no_duplicates() {
        // Ensure no duplicate detections from overlapping patterns
        let text = "BADGE# 123 and ID 456 and E123456";
        let all = find_all_organizational_ids_in_text(text);

        // Check for unique positions
        let mut seen = std::collections::HashSet::new();
        for m in &all {
            let key = (m.start, m.end);
            assert!(
                !seen.contains(&key),
                "Duplicate match at position {:?}",
                key
            );
            seen.insert(key);
        }
    }
}

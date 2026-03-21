// SAFETY: All expect() calls in this module are on capture.get(0), which always exists
// per the regex spec (group 0 is the full match and is guaranteed to exist).
#![allow(clippy::expect_used)]

//! Single-value organizational ID detection
//!
//! Functions for validating individual organizational identifiers:
//! - Employee IDs
//! - Student IDs
//! - Badge numbers

use super::super::super::common::patterns::organizational;
use super::super::super::types::IdentifierType;

// ============================================================================
// Single-Value Detection (Format Validation)
// ============================================================================

/// Detect organizational identifier type
///
/// Returns the specific type of organizational identifier if detected.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::organizational::detect_organizational_id;
/// use crate::primitives::identifiers::types::IdentifierType;
///
/// assert_eq!(detect_organizational_id("E123456"), Some(IdentifierType::EmployeeId));
/// assert_eq!(detect_organizational_id("S12345678"), Some(IdentifierType::StudentId));
/// assert_eq!(detect_organizational_id("invalid"), None);
/// ```
pub fn detect_organizational_id(value: &str) -> Option<IdentifierType> {
    if is_employee_id(value) {
        Some(IdentifierType::EmployeeId)
    } else if is_student_id(value) {
        Some(IdentifierType::StudentId)
    } else if is_badge_number(value) {
        Some(IdentifierType::BadgeNumber)
    } else {
        None
    }
}

/// Check if any organizational identifier is present
///
/// Lenient boolean wrapper for quick checks.
pub fn is_organizational_id(value: &str) -> bool {
    detect_organizational_id(value).is_some()
}

/// Check if a value matches employee ID format
///
/// Detects common corporate employee ID patterns:
/// - E-numbers: "E123456"
/// - Prefixed: "EMP00123", "EMPLOYEE-456"
/// - Badge numbers: "BADGE# 98765"
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::organizational::is_employee_id;
///
/// assert!(is_employee_id("E123456"));
/// assert!(is_employee_id("EMP00123"));
/// assert!(!is_employee_id("invalid"));
/// ```
pub fn is_employee_id(value: &str) -> bool {
    organizational::employee_id::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Check if a value matches student ID format
///
/// Detects common educational institution ID patterns:
/// - S-numbers: "S12345678"
/// - Prefixed: "STUDENT# 123456"
/// - Formatted: "900-00-0001"
///
/// Note: The formatted pattern overlaps with SSN format and needs context.
pub fn is_student_id(value: &str) -> bool {
    organizational::student_id::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Check if a value matches badge number format
///
/// Detects common badge/security ID patterns:
/// - Labeled: "BADGE# 98765", "BADGE-12345"
/// - ID format: "ID 12345", "ID#98765"
///
/// Physical security badges grant facility access and should be protected.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::organizational::is_badge_number;
///
/// assert!(is_badge_number("BADGE# 98765"));
/// assert!(is_badge_number("ID 12345"));
/// assert!(!is_badge_number("invalid"));
/// ```
pub fn is_badge_number(value: &str) -> bool {
    organizational::badge_number::all()
        .iter()
        .any(|p| p.is_match(value))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== Detection Tests =====

    #[test]
    fn test_detect_organizational_id() {
        assert_eq!(
            detect_organizational_id("E123456"),
            Some(IdentifierType::EmployeeId)
        );
        assert_eq!(
            detect_organizational_id("S12345678"),
            Some(IdentifierType::StudentId)
        );
        assert_eq!(detect_organizational_id("invalid"), None);
    }

    #[test]
    fn test_is_organizational_id() {
        assert!(is_organizational_id("E123456"));
        assert!(is_organizational_id("S12345678"));
        assert!(!is_organizational_id("invalid"));
    }

    // ===== Single-Value Detection Tests =====

    #[test]
    fn test_is_employee_id() {
        assert!(is_employee_id("E123456"));
        assert!(is_employee_id("E12345")); // Minimum length
        assert!(is_employee_id("EMP00123"));
        assert!(!is_employee_id("invalid"));
        assert!(!is_employee_id("E123")); // Too short
    }

    #[test]
    fn test_is_student_id() {
        assert!(is_student_id("S12345678"));
        assert!(is_student_id("s12345678")); // Lowercase
        assert!(!is_student_id("invalid"));
    }

    #[test]
    fn test_is_badge_number() {
        assert!(is_badge_number("BADGE# 98765"));
        assert!(is_badge_number("BADGE-12345"));
        assert!(is_badge_number("ID 12345"));
        assert!(!is_badge_number("invalid"));
        assert!(!is_badge_number("BADGE# AB")); // Too short
    }

    // ===== Edge Case Tests =====

    #[test]
    fn test_unicode_handling() {
        // Unicode in middle of ID breaks the match
        assert!(!is_employee_id("E123👍456"));
        assert!(!is_employee_id("EMP😀123"));
        assert!(!is_student_id("S123😀456"));
        assert!(!is_student_id("S12€345678"));

        // Unicode at end doesn't prevent detection (word boundary handles it)
        // The pattern will match the valid part before the unicode
        assert!(is_badge_number("BADGE# 123€")); // Matches "BADGE# 123"
    }

    #[test]
    fn test_whitespace_handling() {
        // Leading/trailing whitespace doesn't prevent detection
        // (word boundaries handle this correctly - we detect the ID part)
        assert!(is_employee_id("  E123456")); // Matches "E123456"
        assert!(is_employee_id("E123456  ")); // Matches "E123456"
        assert!(is_employee_id("  E123456  ")); // Matches "E123456"

        // Embedded whitespace breaks the match (not part of pattern)
        assert!(!is_employee_id("E 123 456"));
        assert!(!is_student_id("S 123 456"));

        // Whitespace in patterns that explicitly allow it (like "ID 12345")
        assert!(is_badge_number("ID 12345")); // Space is part of pattern
    }

    #[test]
    fn test_empty_and_short_inputs() {
        // Empty strings
        assert!(!is_employee_id(""));
        assert!(!is_student_id(""));
        assert!(!is_badge_number(""));

        // Too short
        assert!(!is_employee_id("E"));
        assert!(!is_employee_id("E1"));
        assert!(!is_employee_id("E12"));
        assert!(!is_employee_id("E123")); // Below 5-digit minimum
        assert!(!is_student_id("S"));
        assert!(!is_student_id("S123")); // Below 7-digit minimum
        assert!(!is_badge_number("ID")); // No number
    }

    #[test]
    fn test_length_boundaries() {
        // Employee ID: 5-8 digits for E-numbers
        assert!(is_employee_id("E12345")); // Minimum
        assert!(is_employee_id("E123456"));
        assert!(is_employee_id("E1234567"));
        assert!(is_employee_id("E12345678")); // Maximum
        assert!(!is_employee_id("E123456789")); // Too long

        // Student ID: 7-9 digits for S-numbers
        assert!(is_student_id("S1234567")); // Minimum
        assert!(is_student_id("S12345678"));
        assert!(is_student_id("S123456789")); // Maximum
        assert!(!is_student_id("S12345")); // Too short
        assert!(!is_student_id("S1234567890")); // Too long

        // Badge: 4-10 digits for ID format
        assert!(is_badge_number("ID 1234")); // Minimum
        assert!(is_badge_number("ID 12345"));
        assert!(is_badge_number("ID 1234567890")); // Maximum
        assert!(!is_badge_number("ID 123")); // Too short
        assert!(!is_badge_number("ID 12345678901")); // Too long
    }

    #[test]
    fn test_case_sensitivity() {
        // E-numbers should be case-insensitive
        assert!(is_employee_id("E123456"));
        assert!(is_employee_id("e123456"));

        // S-numbers should be case-insensitive
        assert!(is_student_id("S12345678"));
        assert!(is_student_id("s12345678"));

        // Labeled prefixes are UPPERCASE only (not case-insensitive)
        assert!(is_employee_id("EMP123456"));
        assert!(!is_employee_id("emp123456")); // Lowercase not supported
        assert!(is_student_id("STUDENT# 123456"));
        assert!(!is_student_id("student# 123456")); // Lowercase not supported
    }

    #[test]
    fn test_special_characters() {
        // Valid separators
        assert!(is_employee_id("EMP-123456"));
        assert!(is_employee_id("EMP#123456"));
        assert!(is_employee_id("EMP:123456"));
        assert!(is_badge_number("BADGE-12345"));
        assert!(is_badge_number("BADGE#12345"));

        // Invalid special characters
        assert!(!is_employee_id("E123@456"));
        assert!(!is_employee_id("E123!456"));
        assert!(!is_student_id("S123$456"));
        assert!(!is_badge_number("BADGE% 123"));
    }

    #[test]
    fn test_redos_protection() {
        // Very long input should be rejected safely
        let long_text = "E".to_string() + &"1".repeat(100_000);
        assert!(!is_employee_id(&long_text));
    }

    #[test]
    fn test_numeric_only_strings() {
        // Pure numbers without prefixes
        assert!(!is_employee_id("123456"));
        assert!(!is_student_id("12345678"));

        // Exception: ID format badges accept numeric
        assert!(is_badge_number("ID 12345"));
    }

    #[test]
    fn test_alphabetic_only_strings() {
        // Letters only
        assert!(!is_employee_id("ABCDEF"));
        assert!(!is_student_id("STUDENT"));
        assert!(!is_badge_number("BADGE"));

        // Needs numbers too
        assert!(is_employee_id("EMP12345"));
        assert!(is_student_id("STUDENT# 123456"));
        assert!(is_badge_number("BADGE# 12345"));
    }
}

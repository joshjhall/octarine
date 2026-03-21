//! Organizational identifier patterns
//!
//! Regular expression patterns for detecting organization-issued identifiers:
//! - Employee IDs (E-numbers, EMP codes, badge numbers)
//! - Student IDs (S-numbers, student codes)
//!
//! These patterns are used by detection and sanitization modules.

#![allow(clippy::expect_used)] // Static regex initialization - expects are intentional

use once_cell::sync::Lazy;
use regex::Regex;

// ============================================================================
// Employee ID Patterns
// ============================================================================

pub mod employee_id {
    use super::*;

    /// Employee ID with explicit prefix
    /// Examples: "EMP00123", "EMPLOYEE-456", "STAFF#789"
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(?:EMP|EMPLOYEE|STAFF)[\s#:-]*[A-Z0-9]{4,12}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// E-number format (common in corporations)
    /// Examples: "E123456", "E12345", "e123456"
    pub static E_NUMBER: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b[Ee]\d{5,8}\b").expect("BUG: Invalid regex pattern"));

    /// Return all employee ID patterns
    pub fn all() -> Vec<&'static Lazy<Regex>> {
        vec![&LABELED, &E_NUMBER]
    }
}

// ============================================================================
// Student ID Patterns
// ============================================================================

pub mod student_id {
    use super::*;

    /// Student ID with explicit prefix
    /// Examples: "STUDENT# 1234567", "STU-123456"
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(?:STUDENT|STU|STUD)[\s#:-]*[A-Z0-9]{6,12}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// S-number format (common in universities)
    /// Examples: "S12345678", "s12345678"
    pub static S_NUMBER: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b[Ss]\d{7,9}\b").expect("BUG: Invalid regex pattern"));

    /// Formatted with dashes
    /// Example: "900-00-0001"
    /// Note: Overlaps with SSN format - requires context checking
    pub static WITH_DASHES: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("BUG: Invalid regex pattern"));

    /// Return all student ID patterns
    pub fn all() -> Vec<&'static Lazy<Regex>> {
        vec![&LABELED, &S_NUMBER, &WITH_DASHES]
    }
}

// ============================================================================
// Badge Number Patterns
// ============================================================================

pub mod badge_number {
    use super::*;

    /// Badge number with explicit prefix
    /// Examples: "BADGE# 98765", "BADGE-12345"
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(?:BADGE|BADGENO|BADGE-NUMBER)[\s#:-]*[A-Z0-9]{3,15}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Generic ID format (standalone numeric)
    /// Examples: "ID 12345", "ID#98765"
    pub static ID_FORMAT: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\bID[\s#:-]*\d{4,10}\b").expect("BUG: Invalid regex pattern"));

    /// Badge number as standalone sequence (requires context)
    /// Examples: "12345" (when context indicates it's a badge)
    pub static STANDALONE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b\d{4,10}\b").expect("BUG: Invalid regex pattern"));

    /// Return all badge number patterns
    pub fn all() -> Vec<&'static Lazy<Regex>> {
        vec![&LABELED, &ID_FORMAT]
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== Employee ID Pattern Tests =====

    #[test]
    fn test_employee_labeled_pattern() {
        assert!(employee_id::LABELED.is_match("EMP00123"));
        assert!(employee_id::LABELED.is_match("EMPLOYEE-456"));
        assert!(employee_id::LABELED.is_match("STAFF#7890"));
        assert!(!employee_id::LABELED.is_match("invalid"));
    }

    #[test]
    fn test_employee_e_number_pattern() {
        assert!(employee_id::E_NUMBER.is_match("E123456"));
        assert!(employee_id::E_NUMBER.is_match("e123456")); // Case insensitive
        assert!(employee_id::E_NUMBER.is_match("E12345")); // Minimum length
        assert!(!employee_id::E_NUMBER.is_match("E1234")); // Too short
        assert!(!employee_id::E_NUMBER.is_match("E123456789")); // Too long
    }

    // ===== Student ID Pattern Tests =====

    #[test]
    fn test_student_labeled_pattern() {
        assert!(student_id::LABELED.is_match("STUDENT# 1234567"));
        assert!(student_id::LABELED.is_match("STU-789012"));
        assert!(!student_id::LABELED.is_match("STU-12")); // Too short
    }

    #[test]
    fn test_student_s_number_pattern() {
        assert!(student_id::S_NUMBER.is_match("S12345678"));
        assert!(student_id::S_NUMBER.is_match("s12345678")); // Case insensitive
        assert!(!student_id::S_NUMBER.is_match("S123456")); // Too short
    }

    #[test]
    fn test_student_with_dashes_pattern() {
        assert!(student_id::WITH_DASHES.is_match("900-00-0001"));
        assert!(student_id::WITH_DASHES.is_match("123-45-6789"));
        assert!(!student_id::WITH_DASHES.is_match("900-0-001")); // Wrong format
    }

    #[test]
    fn test_employee_all_patterns() {
        let patterns = employee_id::all();
        assert_eq!(patterns.len(), 2);
    }

    #[test]
    fn test_student_all_patterns() {
        let patterns = student_id::all();
        assert_eq!(patterns.len(), 3);
    }

    // ===== Badge Number Pattern Tests =====

    #[test]
    fn test_badge_labeled_pattern() {
        assert!(badge_number::LABELED.is_match("BADGE# 98765"));
        assert!(badge_number::LABELED.is_match("BADGE-12345"));
        assert!(badge_number::LABELED.is_match("BADGENO 123ABC"));
        assert!(!badge_number::LABELED.is_match("BADGE# AB")); // Too short
    }

    #[test]
    fn test_badge_id_format() {
        assert!(badge_number::ID_FORMAT.is_match("ID 12345"));
        assert!(badge_number::ID_FORMAT.is_match("ID#98765"));
        assert!(!badge_number::ID_FORMAT.is_match("ID ABC")); // Not numeric
    }

    #[test]
    fn test_badge_all_patterns() {
        let patterns = badge_number::all();
        assert_eq!(patterns.len(), 2);
    }
}

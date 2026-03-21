// SAFETY: All expect() calls in this module are on capture.get(0), which always exists
// per the regex spec (group 0 is the full match and is guaranteed to exist).
#![allow(clippy::expect_used)]

//! Test pattern detection for organizational IDs
//!
//! Functions for detecting test/sample organizational identifiers:
//! - Test employee IDs
//! - Test student IDs
//! - Test badge numbers

// ============================================================================
// Test Pattern Detection
// ============================================================================

/// Check if an employee ID is a known test/sample pattern
///
/// Test employee IDs are commonly used in documentation and testing.
/// These should not be treated as real employee data.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::organizational::is_test_employee_id;
///
/// assert!(is_test_employee_id("TEST123"));
/// assert!(is_test_employee_id("TEMP-456"));
/// assert!(is_test_employee_id("E000000"));
/// assert!(!is_test_employee_id("E123456"));
/// ```
#[must_use]
pub fn is_test_employee_id(employee_id: &str) -> bool {
    let id_upper = employee_id.to_uppercase();

    // Common test prefixes
    let test_prefixes = ["TEST", "TEMP", "DEMO", "SAMPLE", "FAKE", "EXAMPLE"];
    for prefix in &test_prefixes {
        if id_upper.starts_with(prefix) || id_upper.contains(prefix) {
            return true;
        }
    }

    // All zeros (E000000, EMP000000)
    if id_upper
        .chars()
        .filter(|c| c.is_ascii_digit())
        .all(|c| c == '0')
    {
        return true;
    }

    // All same digit patterns
    let digits: String = id_upper.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 4
        && digits
            .chars()
            .all(|c| c == digits.chars().next().unwrap_or('0'))
    {
        return true;
    }

    // Sequential patterns (123456, 654321)
    if digits.contains("12345") || digits.contains("54321") {
        return true;
    }

    false
}

/// Check if a student ID is a known test/sample pattern
///
/// Test student IDs are commonly used in documentation and testing.
/// These should not be treated as real student data.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::organizational::is_test_student_id;
///
/// assert!(is_test_student_id("STUDENT-TEST"));
/// assert!(is_test_student_id("S00000000"));
/// assert!(is_test_student_id("S12345678")); // Sequential
/// assert!(!is_test_student_id("S98765432"));
/// ```
#[must_use]
pub fn is_test_student_id(student_id: &str) -> bool {
    let id_upper = student_id.to_uppercase();

    // Common test prefixes/keywords
    let test_keywords = ["TEST", "TEMP", "DEMO", "SAMPLE", "FAKE", "EXAMPLE"];
    for keyword in &test_keywords {
        if id_upper.contains(keyword) {
            return true;
        }
    }

    // All zeros (S00000000, 000-00-0000)
    let digits: String = id_upper.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 4 && digits.chars().all(|c| c == '0') {
        return true;
    }

    // All same digit patterns
    if digits.len() >= 4
        && digits
            .chars()
            .all(|c| c == digits.chars().next().unwrap_or('0'))
    {
        return true;
    }

    // Sequential patterns (S12345678, 123-45-6789)
    if digits.contains("12345678") || digits.contains("87654321") {
        return true;
    }

    // Common test SSN-format student IDs
    if student_id == "123-45-6789" || student_id == "000-00-0000" {
        return true;
    }

    false
}

/// Check if a badge number is a known test/sample pattern
///
/// Test badge numbers are commonly used in documentation and testing.
/// These should not be treated as real security badge data.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::organizational::is_test_badge_number;
///
/// assert!(is_test_badge_number("BADGE-TEST"));
/// assert!(is_test_badge_number("ID 00000"));
/// assert!(is_test_badge_number("BADGE# 11111"));
/// assert!(!is_test_badge_number("BADGE# 98765"));
/// ```
#[must_use]
pub fn is_test_badge_number(badge_number: &str) -> bool {
    let badge_upper = badge_number.to_uppercase();

    // Common test keywords
    let test_keywords = ["TEST", "TEMP", "DEMO", "SAMPLE", "FAKE", "EXAMPLE"];
    for keyword in &test_keywords {
        if badge_upper.contains(keyword) {
            return true;
        }
    }

    // All zeros
    let digits: String = badge_upper.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 3 && digits.chars().all(|c| c == '0') {
        return true;
    }

    // All same digit patterns (11111, 22222, etc.)
    if digits.len() >= 3
        && digits
            .chars()
            .all(|c| c == digits.chars().next().unwrap_or('0'))
    {
        return true;
    }

    // Sequential patterns
    if digits.contains("12345") || digits.contains("54321") {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== Test Pattern Detection Tests =====

    #[test]
    fn test_is_test_employee_id() {
        // Test prefixes
        assert!(is_test_employee_id("TEST123"));
        assert!(is_test_employee_id("TEMP-456"));
        assert!(is_test_employee_id("DEMO-789"));
        assert!(is_test_employee_id("SAMPLE123"));
        assert!(is_test_employee_id("EMP-TEST"));

        // All zeros
        assert!(is_test_employee_id("E000000"));
        assert!(is_test_employee_id("EMP00000"));

        // All same digits
        assert!(is_test_employee_id("E111111"));
        assert!(is_test_employee_id("E999999"));

        // Sequential patterns
        assert!(is_test_employee_id("E123456"));
        assert!(is_test_employee_id("EMP54321"));

        // Real IDs (should not match)
        assert!(!is_test_employee_id("E198273"));
        assert!(!is_test_employee_id("EMP94857"));
    }

    #[test]
    fn test_is_test_student_id() {
        // Test keywords
        assert!(is_test_student_id("STUDENT-TEST"));
        assert!(is_test_student_id("S-TEMP-123"));
        assert!(is_test_student_id("DEMO-STU"));

        // All zeros
        assert!(is_test_student_id("S00000000"));
        assert!(is_test_student_id("000-00-0000"));

        // All same digits
        assert!(is_test_student_id("S11111111"));
        assert!(is_test_student_id("S99999999"));

        // Sequential patterns
        assert!(is_test_student_id("S12345678"));
        assert!(is_test_student_id("123-45-6789"));

        // Real IDs (should not match)
        assert!(!is_test_student_id("S98765432"));
        assert!(!is_test_student_id("S20241234"));
    }

    #[test]
    fn test_is_test_badge_number() {
        // Test keywords
        assert!(is_test_badge_number("BADGE-TEST"));
        assert!(is_test_badge_number("ID-TEMP"));
        assert!(is_test_badge_number("DEMO123"));

        // All zeros
        assert!(is_test_badge_number("BADGE# 00000"));
        assert!(is_test_badge_number("ID 000"));

        // All same digits
        assert!(is_test_badge_number("BADGE# 11111"));
        assert!(is_test_badge_number("ID 99999"));

        // Sequential patterns
        assert!(is_test_badge_number("BADGE# 12345"));
        assert!(is_test_badge_number("ID 54321"));

        // Real badges (should not match)
        assert!(!is_test_badge_number("BADGE# 98765"));
        assert!(!is_test_badge_number("ID 84729"));
    }
}

//! Organizational identifier validation
//!
//! Validates identifiers issued by private organizations:
//! - **Employee ID**: Corporate HR systems (E-numbers, EMP codes, badge numbers)
//! - **Student ID**: Educational institutions (S-numbers, student codes)
//! - **Badge Number**: Security/access control systems
//!
//! # OWASP Compliance
//!
//! All validation follows OWASP Input Validation guidelines:
//! - Format validation against known patterns
//! - Length constraints to prevent buffer overflows
//! - Character set validation to prevent injection
//! - No logging of full IDs (privacy protection)
//!
//! # Security Considerations
//!
//! Organizational IDs are moderately sensitive:
//! - **Employee ID**: Can enable social engineering attacks
//! - **Student ID**: Protected under FERPA (Family Educational Rights and Privacy Act)
//! - **Badge Number**: Physical security risk if disclosed
//!
//! # Validation Strategy
//!
//! Unlike government IDs (SSN, passport) which have strict format rules,
//! organizational IDs vary widely by institution. We validate:
//! 1. Format matches common patterns (E-numbers, prefixed codes)
//! 2. Length is reasonable (4-12 characters typically)
//! 3. Character set is alphanumeric only
//! 4. No injection patterns (SQL, command, path traversal)
//!
//! # Design Principles
//!
//! - **No logging**: Pure validation functions (privacy protection)
//! - **No external dependencies**: Only uses primitives module
//! - **Dual API**: Lenient bool and strict Result versions
//!
//! # Usage
//!
//! ```ignore
//! use crate::primitives::identifiers::organizational;
//!
//! // Strict validation (returns Result)
//! organizational::validate_employee_id("E123456")?;
//!
//! // Check without detailed errors
//! if organizational::validate_employee_id("EMP00123").is_ok() {
//!     // Valid format
//! }
//! ```

use super::super::common::utils::is_injection_pattern_present;
use super::detection;
use crate::primitives::Problem;

/// Validate employee ID format (returns Result)
///
/// Validates corporate employee identification numbers.
/// Accepts common formats:
/// - E-numbers: "E123456" (5-8 digits)
/// - Prefixed: "EMP00123", "EMPLOYEE-456"
/// - Badge: "BADGE# 98765"
///
/// # Arguments
///
/// * `employee_id` - The employee ID string to validate
///
/// # Returns
///
/// * `Ok(())` - If the employee ID format is valid
/// * `Err(Problem)` - If the format is invalid or contains injection patterns
///
/// # Examples
///
/// ```ignore
/// // Valid formats
/// validate_employee_id("E123456")?;
/// validate_employee_id("EMP00123")?;
/// validate_employee_id("BADGE# 98765")?;
///
/// // Invalid formats
/// assert!(validate_employee_id("E123").is_err());  // Too short
/// assert!(validate_employee_id("E123456789012").is_err());  // Too long
/// assert!(validate_employee_id("$(whoami)").is_err());  // Injection
/// ```
///
/// # Security Considerations
///
/// - Never logs actual employee ID values
/// - Checks for command injection patterns
/// - Validates length to prevent buffer overflows
/// - Ensures alphanumeric-only character set
///
/// # OWASP Compliance
///
/// - **Input Validation**: Format and length constraints
/// - **Injection Prevention**: Rejects shell metacharacters
/// - **Privacy**: No logging (redacted in calling layers)
pub fn validate_employee_id(employee_id: &str) -> Result<(), Problem> {
    // First, use detection layer to check if it matches known patterns
    if !detection::is_employee_id(employee_id) {
        return Err(Problem::validation(
            "Employee ID does not match expected format",
        ));
    }

    // OWASP: Length validation (4-15 characters is reasonable for employee IDs)
    if employee_id.len() < 4 || employee_id.len() > 15 {
        return Err(Problem::validation("Employee ID must be 4-15 characters"));
    }

    // OWASP: Check for injection patterns
    if is_injection_pattern_present(employee_id) {
        return Err(Problem::validation(
            "Employee ID contains invalid characters",
        ));
    }

    // Validate character set (alphanumeric + common separators)
    if !employee_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '#' || c == ' ')
    {
        return Err(Problem::validation(
            "Employee ID must contain only alphanumeric characters and separators",
        ));
    }

    Ok(())
}

/// Validate student ID format (returns Result)
///
/// Validates educational institution student identification numbers.
/// Accepts common formats:
/// - S-numbers: "S12345678" (5-9 digits)
/// - Prefixed: "STUDENT# 123456"
/// - Formatted: "900-00-0001"
///
/// # Arguments
///
/// * `student_id` - The student ID string to validate
///
/// # Returns
///
/// * `Ok(())` - If the student ID format is valid
/// * `Err(Problem)` - If the format is invalid or contains injection patterns
///
/// # Examples
///
/// ```ignore
/// // Valid formats
/// validate_student_id("S12345678")?;
/// validate_student_id("STUDENT# 123456")?;
///
/// // Invalid formats
/// assert!(validate_student_id("S123").is_err());  // Too short
/// assert!(validate_student_id("$(cat /etc/passwd)").is_err());  // Injection
/// ```
///
/// # Security Considerations
///
/// - Protected under FERPA (Family Educational Rights and Privacy Act)
/// - Never logs actual student ID values
/// - Checks for command injection patterns
/// - Note: Formatted pattern (900-00-0001) overlaps with SSN format
///
/// # FERPA Compliance
///
/// Student IDs are considered "directory information" under FERPA and
/// require appropriate protection:
/// - Validate format before use in queries
/// - Never expose in URLs or logs
/// - Require authentication for lookup operations
pub fn validate_student_id(student_id: &str) -> Result<(), Problem> {
    // First, use detection layer to check if it matches known patterns
    if !detection::is_student_id(student_id) {
        return Err(Problem::validation(
            "Student ID does not match expected format",
        ));
    }

    // OWASP: Length validation (4-20 characters for student IDs)
    if student_id.len() < 4 || student_id.len() > 20 {
        return Err(Problem::validation("Student ID must be 4-20 characters"));
    }

    // OWASP: Check for injection patterns
    if is_injection_pattern_present(student_id) {
        return Err(Problem::validation(
            "Student ID contains invalid characters",
        ));
    }

    // Validate character set (alphanumeric + common separators)
    if !student_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '#' || c == ' ')
    {
        return Err(Problem::validation(
            "Student ID must contain only alphanumeric characters and separators",
        ));
    }

    Ok(())
}

/// Validate badge number format (returns Result)
///
/// Validates physical security badge identification numbers.
/// Accepts formats:
/// - Labeled: "BADGE# 98765"
/// - Prefixed: "ID-12345"
/// - Numeric: "000123" (zero-padded)
///
/// # Arguments
///
/// * `badge_number` - The badge number string to validate
///
/// # Returns
///
/// * `Ok(())` - If the badge number format is valid
/// * `Err(Problem)` - If the format is invalid
///
/// # Examples
///
/// ```ignore
/// validate_badge_number("BADGE# 98765")?;
/// validate_badge_number("ID-12345")?;
/// ```
///
/// # Security Considerations
///
/// - Badge numbers control physical access to facilities
/// - Disclosure can enable unauthorized entry
/// - Should be treated as moderately sensitive
pub fn validate_badge_number(badge_number: &str) -> Result<(), Problem> {
    // First, use detection layer to check if it matches known patterns
    if !detection::is_badge_number(badge_number) {
        return Err(Problem::validation(
            "Badge number does not match expected format",
        ));
    }

    // OWASP: Length validation (3-15 characters)
    if badge_number.len() < 3 || badge_number.len() > 15 {
        return Err(Problem::validation("Badge number must be 3-15 characters"));
    }

    // OWASP: Check for injection patterns
    if is_injection_pattern_present(badge_number) {
        return Err(Problem::validation(
            "Badge number contains invalid characters",
        ));
    }

    // Validate character set (alphanumeric + separators)
    if !badge_number
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '#' || c == ' ')
    {
        return Err(Problem::validation(
            "Badge number must contain only alphanumeric characters and separators",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== Employee ID Tests =====

    #[test]
    fn test_employee_id_e_number() {
        assert!(validate_employee_id("E123456").is_ok());
        assert!(validate_employee_id("E12345").is_ok());
        assert!(validate_employee_id("E12345678").is_ok());
        assert!(validate_employee_id("e123456").is_ok()); // Case insensitive
    }

    #[test]
    fn test_employee_id_prefixed() {
        assert!(validate_employee_id("EMP00123").is_ok());
        assert!(validate_employee_id("EMPLOYEE-456").is_ok());
        assert!(validate_employee_id("STAFF#7890").is_ok());
    }

    #[test]
    fn test_employee_id_invalid_length() {
        assert!(validate_employee_id("E12").is_err()); // Too short
        assert!(validate_employee_id("E1234567890123456").is_err()); // Too long
    }

    #[test]
    fn test_employee_id_injection() {
        assert!(validate_employee_id("E$(whoami)").is_err());
        assert!(validate_employee_id("E12; rm -rf /").is_err());
        assert!(validate_employee_id("EMP`ls`").is_err());
    }

    #[test]
    fn test_employee_id_invalid_chars() {
        assert!(validate_employee_id("E123@456").is_err());
        assert!(validate_employee_id("EMP<script>").is_err());
    }

    #[test]
    fn test_employee_id_invalid_format() {
        assert!(validate_employee_id("XYZ123").is_err()); // Doesn't start with valid prefix
        assert!(validate_employee_id("123456").is_err()); // No prefix
    }

    // ===== Student ID Tests =====

    #[test]
    fn test_student_id_s_number() {
        assert!(validate_student_id("S12345678").is_ok()); // 8 digits
        assert!(validate_student_id("S1234567").is_ok()); // 7 digits (minimum)
        assert!(validate_student_id("s12345678").is_ok()); // Case insensitive
    }

    #[test]
    fn test_student_id_prefixed() {
        assert!(validate_student_id("STUDENT# 123456").is_ok());
        assert!(validate_student_id("STU-789012").is_ok());
    }

    #[test]
    fn test_student_id_formatted() {
        assert!(validate_student_id("900-00-0001").is_ok()); // SSN-like format
    }

    #[test]
    fn test_student_id_invalid_length() {
        assert!(validate_student_id("S12").is_err()); // Too short
        assert!(validate_student_id("S123456789012345678901").is_err()); // Too long
    }

    #[test]
    fn test_student_id_injection() {
        assert!(validate_student_id("S$(cat /etc/passwd)").is_err());
        assert!(validate_student_id("STUDENT# ${USER}").is_err());
    }

    // ===== Badge Number Tests =====

    #[test]
    fn test_badge_number_labeled() {
        assert!(validate_badge_number("BADGE# 98765").is_ok());
        assert!(validate_badge_number("BADGE-12345").is_ok());
        assert!(validate_badge_number("ID 12345").is_ok());
    }

    #[test]
    fn test_badge_number_invalid_length() {
        assert!(validate_badge_number("12").is_err()); // Too short
        assert!(validate_badge_number("1234567890123456").is_err()); // Too long
    }

    #[test]
    fn test_badge_number_injection() {
        assert!(validate_badge_number("BADGE# $(whoami)").is_err());
        assert!(validate_badge_number("ID; DROP TABLE users").is_err());
    }
}

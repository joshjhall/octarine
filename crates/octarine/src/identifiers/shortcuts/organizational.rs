//! Organizational identifier shortcuts (employee, student, badge).
//!
//! Convenience functions over [`OrganizationalBuilder`](super::super::OrganizationalBuilder).

use crate::observe::Problem;

use super::super::OrganizationalBuilder;
use super::super::types::IdentifierMatch;

/// Check if value is an employee ID
#[must_use]
pub fn is_employee_id(value: &str) -> bool {
    OrganizationalBuilder::new().is_employee_id(value)
}

/// Check if value is a student ID
#[must_use]
pub fn is_student_id(value: &str) -> bool {
    OrganizationalBuilder::new().is_student_id(value)
}

/// Check if value is a badge number
#[must_use]
pub fn is_badge_number(value: &str) -> bool {
    OrganizationalBuilder::new().is_badge_number(value)
}

/// Validate an employee ID format
///
/// # Errors
///
/// Returns `Problem` if the employee ID format is invalid.
pub fn validate_employee_id(employee_id: &str) -> Result<(), Problem> {
    OrganizationalBuilder::new().validate_employee_id(employee_id)
}

/// Validate a student ID format
///
/// # Errors
///
/// Returns `Problem` if the student ID format is invalid.
pub fn validate_student_id(student_id: &str) -> Result<(), Problem> {
    OrganizationalBuilder::new().validate_student_id(student_id)
}

/// Validate a badge number format
///
/// # Errors
///
/// Returns `Problem` if the badge number format is invalid.
pub fn validate_badge_number(badge_number: &str) -> Result<(), Problem> {
    OrganizationalBuilder::new().validate_badge_number(badge_number)
}

/// Redact an employee ID
#[must_use]
pub fn redact_employee_id(employee_id: &str) -> String {
    OrganizationalBuilder::new().redact_employee_id(employee_id)
}

/// Redact a student ID
#[must_use]
pub fn redact_student_id(student_id: &str) -> String {
    OrganizationalBuilder::new().redact_student_id(student_id)
}

/// Redact a badge number
#[must_use]
pub fn redact_badge_number(badge_number: &str) -> String {
    OrganizationalBuilder::new().redact_badge_number(badge_number)
}

/// Find all employee IDs in text
#[must_use]
pub fn find_employee_ids(text: &str) -> Vec<IdentifierMatch> {
    OrganizationalBuilder::new().find_employee_ids_in_text(text)
}

/// Redact all organizational identifiers in text
#[must_use]
pub fn redact_organizational(text: &str) -> String {
    OrganizationalBuilder::new()
        .redact_all_in_text(text)
        .to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_organizational_identifier_shortcuts() {
        assert!(is_student_id("S12345678"));
        assert!(!is_student_id("invalid"));

        assert!(is_badge_number("BADGE# 98765"));
        assert!(!is_badge_number("invalid"));

        assert!(validate_employee_id("E123456").is_ok());
        assert!(validate_employee_id("E12").is_err()); // too short

        assert!(validate_student_id("S12345678").is_ok());
        assert!(validate_student_id("$(whoami)").is_err()); // injection

        assert!(validate_badge_number("BADGE-12345").is_ok());
        assert!(validate_badge_number("B").is_err());

        // Redaction should not return the original input verbatim
        let emp = redact_employee_id("E123456");
        assert!(!emp.contains("E123456"));
        let stu = redact_student_id("S12345678");
        assert!(!stu.contains("S12345678"));
        let badge = redact_badge_number("BADGE-12345");
        assert!(!badge.contains("BADGE-12345"));
    }
}

//! Builder pattern for organizational identifier operations
//!
//! Provides a clean interface to detection, validation, and sanitization
//! functions for organizational identifiers.
//!
//! ## Design Philosophy
//!
//! - **No business logic**: Builder is purely an interface
//! - **Delegates to modules**: All work done by detection, validation, etc.
//! - **Consistent API**: Same pattern across all identifier domains

use super::super::types::{IdentifierMatch, IdentifierType};
use crate::primitives::Problem;

use super::detection;
use super::redaction::{
    BadgeRedactionStrategy, EmployeeIdRedactionStrategy, StudentIdRedactionStrategy,
    TextRedactionPolicy,
};
use super::sanitization;
use super::validation;

/// Builder for organizational identifier operations
///
/// Provides access to detection, validation, and sanitization functions
/// for organizational identifiers (employee IDs, student IDs, etc.).
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::organizational::OrganizationalIdentifierBuilder;
///
/// let builder = OrganizationalIdentifierBuilder::new();
///
/// // Detection
/// let is_employee = builder.is_employee_id("E123456");
/// assert!(is_employee);
///
/// // Validation
/// if builder.validate_employee_id("E123456").is_ok() {
///     println!("Valid employee ID");
/// }
///
/// // Sanitization
/// let safe = builder.redact_employee_id("E123456");
/// assert_eq!(safe, "[EMPLOYEE_ID]");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct OrganizationalIdentifierBuilder;

impl OrganizationalIdentifierBuilder {
    /// Create a new OrganizationalIdentifierBuilder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // =========================================================================
    // Detection Methods
    // =========================================================================

    /// Detect organizational identifier type from input string
    ///
    /// Returns the type of organizational identifier detected, or None if not recognized.
    #[must_use]
    pub fn detect(&self, value: &str) -> Option<IdentifierType> {
        detection::detect_organizational_id(value)
    }

    /// Check if value is an organizational identifier
    #[must_use]
    pub fn is_organizational_id(&self, value: &str) -> bool {
        detection::is_organizational_id(value)
    }

    /// Check if value is an employee ID
    #[must_use]
    pub fn is_employee_id(&self, value: &str) -> bool {
        detection::is_employee_id(value)
    }

    /// Check if value is a student ID
    #[must_use]
    pub fn is_student_id(&self, value: &str) -> bool {
        detection::is_student_id(value)
    }

    /// Check if value is a badge number
    #[must_use]
    pub fn is_badge_number(&self, value: &str) -> bool {
        detection::is_badge_number(value)
    }

    /// Find all employee IDs in text
    #[must_use]
    pub fn find_employee_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_employee_ids_in_text(text)
    }

    /// Find all student IDs in text
    #[must_use]
    pub fn find_student_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_student_ids_in_text(text)
    }

    /// Find all badge numbers in text
    #[must_use]
    pub fn find_badge_numbers_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_badge_numbers_in_text(text)
    }

    /// Find all organizational IDs in text
    #[must_use]
    pub fn find_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_all_organizational_ids_in_text(text)
    }

    /// Check if text contains any organizational identifiers
    #[must_use]
    pub fn is_organizational_present(&self, text: &str) -> bool {
        detection::is_organizational_present(text)
    }

    // =========================================================================
    // Test Pattern Detection Methods
    // =========================================================================

    /// Check if employee ID is a known test pattern
    #[must_use]
    pub fn is_test_employee_id(&self, employee_id: &str) -> bool {
        detection::is_test_employee_id(employee_id)
    }

    /// Check if student ID is a known test pattern
    #[must_use]
    pub fn is_test_student_id(&self, student_id: &str) -> bool {
        detection::is_test_student_id(student_id)
    }

    /// Check if badge number is a known test pattern
    #[must_use]
    pub fn is_test_badge_number(&self, badge_number: &str) -> bool {
        detection::is_test_badge_number(badge_number)
    }

    // =========================================================================
    // Validation Methods
    // =========================================================================

    /// Validate employee ID format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the employee ID format is invalid
    pub fn validate_employee_id(&self, employee_id: &str) -> Result<(), Problem> {
        validation::validate_employee_id(employee_id)
    }

    /// Validate student ID format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the student ID format is invalid
    pub fn validate_student_id(&self, student_id: &str) -> Result<(), Problem> {
        validation::validate_student_id(student_id)
    }

    /// Validate badge number format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the badge number format is invalid
    pub fn validate_badge_number(&self, badge_number: &str) -> Result<(), Problem> {
        validation::validate_badge_number(badge_number)
    }

    // =========================================================================
    // Sanitization Methods
    // =========================================================================

    /// Redact employee ID completely (uses Token strategy by default)
    #[must_use]
    pub fn redact_employee_id(&self, employee_id: &str) -> String {
        sanitization::redact_employee_id_with_strategy(
            employee_id,
            EmployeeIdRedactionStrategy::Token,
        )
    }

    /// Redact student ID completely (uses Token strategy by default)
    #[must_use]
    pub fn redact_student_id(&self, student_id: &str) -> String {
        sanitization::redact_student_id_with_strategy(student_id, StudentIdRedactionStrategy::Token)
    }

    /// Redact badge number completely (uses Token strategy by default)
    #[must_use]
    pub fn redact_badge_number(&self, badge_number: &str) -> String {
        sanitization::redact_badge_number_with_strategy(badge_number, BadgeRedactionStrategy::Token)
    }

    /// Redact all employee IDs in text (uses Complete policy by default)
    #[must_use]
    pub fn redact_employee_ids_in_text<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
        sanitization::redact_employee_ids_in_text(text, TextRedactionPolicy::Complete)
    }

    /// Redact all student IDs in text (uses Complete policy by default)
    #[must_use]
    pub fn redact_student_ids_in_text<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
        sanitization::redact_student_ids_in_text(text, TextRedactionPolicy::Complete)
    }

    /// Redact all badge numbers in text (uses Complete policy by default)
    #[must_use]
    pub fn redact_badge_numbers_in_text<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
        sanitization::redact_badge_numbers_in_text(text, TextRedactionPolicy::Complete)
    }

    /// Redact all organizational IDs in text (uses Complete policy by default)
    #[must_use]
    pub fn redact_all_in_text(&self, text: &str) -> String {
        sanitization::redact_all_organizational_ids_in_text(text, TextRedactionPolicy::Complete)
    }

    /// Redact all organizational IDs in text with custom policy
    #[must_use]
    pub fn redact_all_in_text_with_policy(
        &self,
        text: &str,
        policy: TextRedactionPolicy,
    ) -> String {
        sanitization::redact_all_organizational_ids_in_text(text, policy)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = OrganizationalIdentifierBuilder::new();
        assert!(builder.is_employee_id("E123456"));
    }

    #[test]
    fn test_detection_methods() {
        let builder = OrganizationalIdentifierBuilder::new();

        // Employee ID
        assert!(builder.is_employee_id("E123456"));
        assert!(!builder.is_employee_id("invalid"));

        // Student ID
        assert!(builder.is_student_id("S12345678"));
        assert!(!builder.is_student_id("invalid"));

        // Generic
        assert!(builder.is_organizational_id("E123456"));
        assert!(builder.is_organizational_id("S12345678"));
    }

    #[test]
    fn test_validation_methods() {
        let builder = OrganizationalIdentifierBuilder::new();

        // Employee ID
        assert!(builder.validate_employee_id("E123456").is_ok());
        assert!(builder.validate_employee_id("invalid").is_err());

        // Student ID
        assert!(builder.validate_student_id("S12345678").is_ok());
        assert!(builder.validate_student_id("invalid").is_err());

        // Badge number
        assert!(builder.validate_badge_number("BADGE# 98765").is_ok());
        assert!(builder.validate_badge_number("invalid").is_err());
    }

    #[test]
    fn test_sanitization_methods() {
        let builder = OrganizationalIdentifierBuilder::new();

        // Single value
        assert_eq!(builder.redact_employee_id("E123456"), "[EMPLOYEE_ID]");
        assert_eq!(builder.redact_student_id("S12345678"), "[STUDENT_ID]");
        assert_eq!(
            builder.redact_badge_number("BADGE# 98765"),
            "[BADGE_NUMBER]"
        );

        // Text
        let text = "Employee: E123456, Student: S12345678, Badge: BADGE# 98765";
        let result = builder.redact_all_in_text(text);
        assert!(result.contains("[EMPLOYEE_ID]"));
        assert!(result.contains("[STUDENT_ID]"));
        assert!(result.contains("[BADGE_NUMBER]"));
    }

    #[test]
    fn test_find_in_text_methods() {
        let builder = OrganizationalIdentifierBuilder::new();

        let text = "Employee: E123456, Student: S12345678";

        let employees = builder.find_employee_ids_in_text(text);
        assert_eq!(employees.len(), 1);

        let students = builder.find_student_ids_in_text(text);
        assert_eq!(students.len(), 1);

        let all = builder.find_all_in_text(text);
        assert!(all.len() >= 2);
    }
}

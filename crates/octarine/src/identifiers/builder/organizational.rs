//! Organizational identifier builder with observability
//!
//! Wraps `primitives::identifiers::OrganizationalIdentifierBuilder` with observe instrumentation.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.

use std::borrow::Cow;

use crate::observe::Problem;
use crate::primitives::identifiers::OrganizationalIdentifierBuilder;

use super::super::types::{IdentifierMatch, IdentifierType, OrganizationalTextPolicy};

/// Organizational identifier builder with observability
#[derive(Debug, Clone, Copy, Default)]
pub struct OrganizationalBuilder {
    inner: OrganizationalIdentifierBuilder,
    emit_events: bool,
}

impl OrganizationalBuilder {
    /// Create a new OrganizationalBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: OrganizationalIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: OrganizationalIdentifierBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // =========================================================================
    // Detection Methods
    // =========================================================================

    /// Detect organizational identifier type from input string
    #[must_use]
    pub fn detect(&self, value: &str) -> Option<IdentifierType> {
        self.inner.detect(value).map(Into::into)
    }

    /// Check if value is an organizational identifier
    #[must_use]
    pub fn is_organizational_id(&self, value: &str) -> bool {
        self.inner.is_organizational_id(value)
    }

    /// Check if value is an employee ID
    #[must_use]
    pub fn is_employee_id(&self, value: &str) -> bool {
        self.inner.is_employee_id(value)
    }

    /// Check if value is a student ID
    #[must_use]
    pub fn is_student_id(&self, value: &str) -> bool {
        self.inner.is_student_id(value)
    }

    /// Check if value is a badge number
    #[must_use]
    pub fn is_badge_number(&self, value: &str) -> bool {
        self.inner.is_badge_number(value)
    }

    /// Find all employee IDs in text
    #[must_use]
    pub fn find_employee_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner
            .find_employee_ids_in_text(text)
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// Find all student IDs in text
    #[must_use]
    pub fn find_student_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner
            .find_student_ids_in_text(text)
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// Find all badge numbers in text
    #[must_use]
    pub fn find_badge_numbers_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner
            .find_badge_numbers_in_text(text)
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// Find all organizational IDs in text
    #[must_use]
    pub fn find_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner
            .find_all_in_text(text)
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// Check if text contains any organizational identifiers
    #[must_use]
    pub fn is_organizational_present(&self, text: &str) -> bool {
        self.inner.is_organizational_present(text)
    }

    // =========================================================================
    // Test Pattern Detection Methods
    // =========================================================================

    /// Check if employee ID is a known test pattern
    #[must_use]
    pub fn is_test_employee_id(&self, employee_id: &str) -> bool {
        self.inner.is_test_employee_id(employee_id)
    }

    /// Check if student ID is a known test pattern
    #[must_use]
    pub fn is_test_student_id(&self, student_id: &str) -> bool {
        self.inner.is_test_student_id(student_id)
    }

    /// Check if badge number is a known test pattern
    #[must_use]
    pub fn is_test_badge_number(&self, badge_number: &str) -> bool {
        self.inner.is_test_badge_number(badge_number)
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
        self.inner.validate_employee_id(employee_id)
    }

    /// Validate student ID format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the student ID format is invalid
    pub fn validate_student_id(&self, student_id: &str) -> Result<(), Problem> {
        self.inner.validate_student_id(student_id)
    }

    /// Validate badge number format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the badge number format is invalid
    pub fn validate_badge_number(&self, badge_number: &str) -> Result<(), Problem> {
        self.inner.validate_badge_number(badge_number)
    }

    // =========================================================================
    // Sanitization Methods
    // =========================================================================

    /// Redact employee ID completely
    #[must_use]
    pub fn redact_employee_id(&self, employee_id: &str) -> String {
        self.inner.redact_employee_id(employee_id)
    }

    /// Redact student ID completely
    #[must_use]
    pub fn redact_student_id(&self, student_id: &str) -> String {
        self.inner.redact_student_id(student_id)
    }

    /// Redact badge number completely
    #[must_use]
    pub fn redact_badge_number(&self, badge_number: &str) -> String {
        self.inner.redact_badge_number(badge_number)
    }

    /// Redact all employee IDs in text
    #[must_use]
    pub fn redact_employee_ids_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.inner.redact_employee_ids_in_text(text)
    }

    /// Redact all student IDs in text
    #[must_use]
    pub fn redact_student_ids_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.inner.redact_student_ids_in_text(text)
    }

    /// Redact all badge numbers in text
    #[must_use]
    pub fn redact_badge_numbers_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.inner.redact_badge_numbers_in_text(text)
    }

    /// Redact all organizational IDs in text using Complete policy
    #[must_use]
    pub fn redact_all_in_text(&self, text: &str) -> String {
        self.inner.redact_all_in_text(text)
    }

    /// Redact all organizational IDs in text with custom policy
    #[must_use]
    pub fn redact_all_in_text_with_policy(
        &self,
        text: &str,
        policy: OrganizationalTextPolicy,
    ) -> String {
        self.inner
            .redact_all_in_text_with_policy(text, policy.into())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = OrganizationalBuilder::new();
        assert!(builder.emit_events);

        let silent = OrganizationalBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = OrganizationalBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_employee_id_detection() {
        let builder = OrganizationalBuilder::silent();
        assert!(builder.is_employee_id("E123456"));
    }
}

//! Organizational identifier redaction functions
//!
//! Redacts employee IDs, student IDs, and badge numbers.

use super::super::config::RedactionProfile;
use crate::primitives::identifiers::OrganizationalIdentifierBuilder;

// Note: Organizational builder uses fixed Complete policy internally
// For profile-aware redaction, we skip in dev/testing modes

/// Redact employee IDs based on profile
pub(super) fn redact_employee_ids(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = OrganizationalIdentifierBuilder::new();
            builder.redact_employee_ids_in_text(text).into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact student IDs based on profile
pub(super) fn redact_student_ids(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = OrganizationalIdentifierBuilder::new();
            builder.redact_student_ids_in_text(text).into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact badge numbers based on profile
pub(super) fn redact_badge_numbers(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = OrganizationalIdentifierBuilder::new();
            builder.redact_badge_numbers_in_text(text).into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // ===== Employee IDs =====

    #[test]
    fn test_redact_employee_ids_strict() {
        let text = "Employee ID: E123456";
        let result = redact_employee_ids(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[EMPLOYEE_ID]"));
        assert!(!result.contains("E123456"));
    }

    #[test]
    fn test_redact_employee_ids_testing_unchanged() {
        let text = "Employee ID: E123456";
        let result = redact_employee_ids(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_employee_ids_no_pii() {
        let text = "Employee onboarding complete";
        let result = redact_employee_ids(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    // ===== Student IDs =====

    #[test]
    fn test_redact_student_ids_strict() {
        let text = "Student ID: S12345678";
        let result = redact_student_ids(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[STUDENT_ID]"));
        assert!(!result.contains("S12345678"));
    }

    #[test]
    fn test_redact_student_ids_testing_unchanged() {
        let text = "Student ID: S12345678";
        let result = redact_student_ids(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_student_ids_no_pii() {
        let text = "Student registration open";
        let result = redact_student_ids(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    // ===== Badge Numbers =====

    #[test]
    fn test_redact_badge_numbers_strict() {
        let text = "Badge: BADGE# 98765";
        let result = redact_badge_numbers(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[BADGE_NUMBER]"));
        assert!(!result.contains("98765"));
    }

    #[test]
    fn test_redact_badge_numbers_testing_unchanged() {
        let text = "Badge: BADGE# 98765";
        let result = redact_badge_numbers(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_badge_numbers_no_pii() {
        let text = "Badge system maintenance scheduled";
        let result = redact_badge_numbers(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }
}

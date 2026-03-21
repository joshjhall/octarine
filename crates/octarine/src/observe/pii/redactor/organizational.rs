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

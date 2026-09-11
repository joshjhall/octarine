//! Organizational ID scanning (employee, student, badge)
//!
//! Part of the PII scanner domain split (issue #411).

use super::super::super::types::PiiType;
use crate::primitives::identifiers::OrganizationalIdentifierBuilder;

/// Scan for organizational IDs (employee, student, badge)
pub(super) fn scan_organizational(text: &str, pii_types: &mut Vec<PiiType>) {
    let org = OrganizationalIdentifierBuilder::new();

    if !org.find_employee_ids_in_text(text).is_empty() {
        pii_types.push(PiiType::EmployeeId);
    }
    if !org.find_student_ids_in_text(text).is_empty() {
        pii_types.push(PiiType::StudentId);
    }
    if !org.find_badge_numbers_in_text(text).is_empty() {
        pii_types.push(PiiType::BadgeNumber);
    }
}

/// Coarse pre-filter for the organizational domain.
pub(super) fn is_organizational_present(text: &str) -> bool {
    let org = OrganizationalIdentifierBuilder::new();
    !org.find_employee_ids_in_text(text).is_empty()
        || !org.find_student_ids_in_text(text).is_empty()
        || !org.find_badge_numbers_in_text(text).is_empty()
}

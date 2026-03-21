//! Organizational identifier sanitization primitives
//!
//! Pure sanitization functions for organizational identifiers with ZERO
//! rust-core dependencies beyond the common utilities.
//!
//! ## Design Principles
//!
//! 1. **No Logging**: Pure functions, no trace/debug calls
//! 2. **No Side Effects**: Only string transformations
//! 3. **Reusable**: Used by observe/pii and security modules
//! 4. **Type-Safe API**: Domain-specific redaction strategies
//!
//! ## Two-Tier Redaction API
//!
//! ### Domain-Specific Strategies (Single Identifiers)
//! Each identifier type has its own strategy enum with only valid options:
//! - `redact_employee_id(id, EmployeeIdRedactionStrategy)` - ShowPrefix, Token, etc.
//! - `redact_student_id(id, StudentIdRedactionStrategy)` - ShowYear, Token, etc.
//! - `redact_badge_number(badge, BadgeRedactionStrategy)` - ShowFacility, Token, etc.
//!
//! ### Generic Text Policy (Text Scanning)
//! For scanning text with multiple identifier types, use `TextRedactionPolicy`:
//! - `None` - No redaction
//! - `Partial` - Show some information (sensible defaults per type)
//! - `Complete` - Full token redaction ([EMPLOYEE_ID], [STUDENT_ID], etc.)
//! - `Anonymous` - Generic [REDACTED] for everything
//!
//! Compliance-ready options (FERPA, GDPR, CCPA).

use super::super::common::patterns::organizational;
use super::detection;
use super::redaction::{
    BadgeRedactionStrategy, EmployeeIdRedactionStrategy, StudentIdRedactionStrategy,
    TextRedactionPolicy,
};
use crate::primitives::data::tokens::RedactionTokenCore;
use std::borrow::Cow;

// ============================================================================
// Employee ID Redaction
// ============================================================================

/// Redact employee ID using domain-specific redaction strategy
///
/// Provides type-safe employee ID redaction with compile-time guarantees that only
/// valid employee ID strategies can be applied. Validates format using detection
/// layer before redaction to prevent information leakage.
///
/// # Arguments
///
/// * `employee_id` - Employee ID to redact
/// * `strategy` - Employee-specific redaction strategy (ShowPrefix, ShowDepartment, Token, etc.)
///
/// # Returns
///
/// Redacted employee ID string according to strategy:
/// - **None**: Returns ID as-is (dev/qa only)
/// - **ShowPrefix**: `"EMP-****"` or `"E-****"`
/// - **ShowDepartment**: `"[EMP-Engineering-****]"` (requires metadata)
/// - **Token**: `"[EMPLOYEE_ID]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"*******"` (length-preserving)
/// - **Hashes**: `"#######"` (length-preserving)
///
/// # Security
///
/// Invalid employee IDs return full redaction token to avoid leaking partial
/// information. For example, a malformed ID returns `[EMPLOYEE_ID]` instead of
/// potentially exposing attack payloads.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::organizational::{EmployeeIdRedactionStrategy, redact_employee_id_with_strategy};
///
/// let emp_id = "E123456";
///
/// // Partial redaction - show prefix
/// assert_eq!(redact_employee_id_with_strategy(emp_id, EmployeeIdRedactionStrategy::ShowPrefix), "E-****");
///
/// // Full redaction - type token
/// assert_eq!(redact_employee_id_with_strategy(emp_id, EmployeeIdRedactionStrategy::Token), "[EMPLOYEE_ID]");
///
/// // Full redaction - anonymous
/// assert_eq!(redact_employee_id_with_strategy(emp_id, EmployeeIdRedactionStrategy::Anonymous), "[REDACTED]");
///
/// // Invalid ID - always fully redacted
/// assert_eq!(redact_employee_id_with_strategy("invalid", EmployeeIdRedactionStrategy::ShowPrefix), "[EMPLOYEE_ID]");
/// ```
#[must_use]
pub fn redact_employee_id_with_strategy(
    employee_id: &str,
    strategy: EmployeeIdRedactionStrategy,
) -> String {
    // No redaction - return as-is (dev/qa)
    if matches!(strategy, EmployeeIdRedactionStrategy::Skip) {
        return employee_id.to_string();
    }

    // Validate format first to prevent information leakage
    if !detection::is_employee_id(employee_id) {
        return RedactionTokenCore::EmployeeId.into();
    }

    match strategy {
        EmployeeIdRedactionStrategy::Skip => employee_id.to_string(),

        EmployeeIdRedactionStrategy::ShowPrefix => {
            // Show first 1-3 characters: "E-****" or "EMP-****"
            if employee_id.starts_with("EMP") {
                "EMP-****".to_string()
            } else if employee_id.starts_with("EMPLOYEE") {
                "EMPLOYEE-****".to_string()
            } else if employee_id.starts_with('E') || employee_id.starts_with('e') {
                "E-****".to_string()
            } else if employee_id.starts_with("STAFF") {
                "STAFF-****".to_string()
            } else {
                RedactionTokenCore::EmployeeId.into()
            }
        }

        EmployeeIdRedactionStrategy::ShowDepartment => {
            // Would require metadata - default to token for now
            "[EMP-****]".to_string()
        }

        EmployeeIdRedactionStrategy::Token => RedactionTokenCore::EmployeeId.into(),
        EmployeeIdRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        EmployeeIdRedactionStrategy::Asterisks => "*".repeat(employee_id.len()),
        EmployeeIdRedactionStrategy::Hashes => "#".repeat(employee_id.len()),
    }
}

// ============================================================================
// Student ID Redaction
// ============================================================================

/// Redact student ID using domain-specific redaction strategy
///
/// Provides type-safe student ID redaction protected under FERPA. Validates format
/// using detection layer before redaction.
///
/// # Arguments
///
/// * `student_id` - Student ID to redact
/// * `strategy` - Student-specific redaction strategy (ShowYear, Token, etc.)
///
/// # Returns
///
/// Redacted student ID string according to strategy:
/// - **None**: Returns ID as-is (dev/qa only)
/// - **ShowYear**: `"2024-****"` (requires year parsing)
/// - **Token**: `"[STUDENT_ID]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"*********"` (length-preserving)
/// - **Hashes**: `"#########"` (length-preserving)
///
/// # Security
///
/// Invalid student IDs return `[STUDENT_ID]` token to avoid leaking partial
/// information from malformed input.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::organizational::{StudentIdRedactionStrategy, redact_student_id_with_strategy};
///
/// let student_id = "S12345678";
///
/// // Partial - show year (requires parsing)
/// assert_eq!(redact_student_id_with_strategy(student_id, StudentIdRedactionStrategy::ShowYear), "20**-****");
///
/// // Full - type token
/// assert_eq!(redact_student_id_with_strategy(student_id, StudentIdRedactionStrategy::Token), "[STUDENT_ID]");
/// ```
#[must_use]
pub fn redact_student_id_with_strategy(
    student_id: &str,
    strategy: StudentIdRedactionStrategy,
) -> String {
    // No redaction
    if matches!(strategy, StudentIdRedactionStrategy::Skip) {
        return student_id.to_string();
    }

    // Validate format to prevent information leakage
    if !detection::is_student_id(student_id) {
        return RedactionTokenCore::StudentId.into();
    }

    match strategy {
        StudentIdRedactionStrategy::Skip => student_id.to_string(),

        StudentIdRedactionStrategy::ShowYear => {
            // If it starts with digits that look like year, show partial
            if student_id.len() >= 4 && student_id.chars().take(4).all(|c| c.is_ascii_digit()) {
                let year_prefix = &student_id[..4];
                if let Ok(year) = year_prefix.parse::<u32>()
                    && (1900..=2100).contains(&year)
                {
                    return format!("{year}-****");
                }
            }
            // Otherwise default to token
            RedactionTokenCore::StudentId.into()
        }

        StudentIdRedactionStrategy::Token => RedactionTokenCore::StudentId.into(),
        StudentIdRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        StudentIdRedactionStrategy::Asterisks => "*".repeat(student_id.len()),
        StudentIdRedactionStrategy::Hashes => "#".repeat(student_id.len()),
    }
}

// ============================================================================
// Badge Number Redaction
// ============================================================================

/// Redact badge number using domain-specific redaction strategy
///
/// Provides type-safe badge number redaction for physical security badges.
/// Validates format using detection layer before redaction.
///
/// # Arguments
///
/// * `badge_number` - Badge number to redact
/// * `strategy` - Badge-specific redaction strategy (ShowFacility, Token, etc.)
///
/// # Returns
///
/// Redacted badge string according to strategy:
/// - **None**: Returns badge as-is (dev/qa only)
/// - **ShowFacility**: `"[BADGE-Building5-****]"` (requires metadata)
/// - **Token**: `"[BADGE]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"*********"` (length-preserving)
/// - **Hashes**: `"#########"` (length-preserving)
///
/// # Security
///
/// Invalid badge numbers return `[BADGE]` token to avoid leaking partial
/// information from malformed input.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::organizational::{BadgeRedactionStrategy, redact_badge_number_with_strategy};
///
/// let badge = "BADGE# 98765";
///
/// // Partial - show facility (requires metadata)
/// assert_eq!(redact_badge_number_with_strategy(badge, BadgeRedactionStrategy::ShowFacility), "[BADGE-****]");
///
/// // Full - type token
/// assert_eq!(redact_badge_number_with_strategy(badge, BadgeRedactionStrategy::Token), "[BADGE]");
/// ```
#[must_use]
pub fn redact_badge_number_with_strategy(
    badge_number: &str,
    strategy: BadgeRedactionStrategy,
) -> String {
    // No redaction
    if matches!(strategy, BadgeRedactionStrategy::Skip) {
        return badge_number.to_string();
    }

    // Validate format to prevent information leakage
    if !detection::is_badge_number(badge_number) {
        return RedactionTokenCore::BadgeNumber.into();
    }

    match strategy {
        BadgeRedactionStrategy::Skip => badge_number.to_string(),

        BadgeRedactionStrategy::ShowFacility => {
            // Would require metadata - default to generic badge token
            "[BADGE-****]".to_string()
        }

        BadgeRedactionStrategy::Token => RedactionTokenCore::BadgeNumber.into(),
        BadgeRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        BadgeRedactionStrategy::Asterisks => "*".repeat(badge_number.len()),
        BadgeRedactionStrategy::Hashes => "#".repeat(badge_number.len()),
    }
}

// ============================================================================
// Text Redaction (Find and Replace in Documents)
// ============================================================================

/// Redact all employee ID patterns in text using text redaction policy
///
/// Scans text for employee IDs and replaces them according to the policy.
/// The policy is mapped to appropriate domain strategies internally.
///
/// # Returns
///
/// `Cow<'_, str>` - Borrowed if no IDs found, owned if replacements made.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::organizational::{TextRedactionPolicy, redact_employee_ids_in_text};
///
/// let text = "Employee ID: E123456";
///
/// // Partial redaction
/// let safe = redact_employee_ids_in_text(text, TextRedactionPolicy::Partial);
/// assert!(safe.contains("E-****"));
///
/// // Complete redaction
/// let safe = redact_employee_ids_in_text(text, TextRedactionPolicy::Complete);
/// assert!(safe.contains("[EMPLOYEE_ID]"));
/// ```
pub fn redact_employee_ids_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_employee_id_strategy();

    // None policy - return as-is
    if matches!(strategy, EmployeeIdRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let mut result = Cow::Borrowed(text);

    for pattern in organizational::employee_id::all() {
        if pattern.is_match(&result) {
            result = Cow::Owned(
                pattern
                    .replace_all(&result, |caps: &regex::Captures<'_>| {
                        let matched = &caps[0];
                        redact_employee_id_with_strategy(matched, strategy)
                    })
                    .into_owned(),
            );
        }
    }

    result
}

/// Redact all student ID patterns in text using text redaction policy
///
/// Only redacts when context suggests student ID (to avoid false positives
/// with SSN format). The policy is mapped to appropriate domain strategies.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::organizational::{TextRedactionPolicy, redact_student_ids_in_text};
///
/// let text = "Student ID: S12345678";
///
/// // Complete redaction
/// let safe = redact_student_ids_in_text(text, TextRedactionPolicy::Complete);
/// assert!(safe.contains("[STUDENT_ID]"));
/// ```
pub fn redact_student_ids_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_student_id_strategy();

    // None policy - return as-is
    if matches!(strategy, StudentIdRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let mut result = Cow::Borrowed(text);

    for pattern in organizational::student_id::all() {
        if pattern.is_match(&result) {
            result = Cow::Owned(
                pattern
                    .replace_all(&result, |caps: &regex::Captures<'_>| {
                        let matched = &caps[0];
                        // Only redact if context suggests student ID
                        if is_likely_student_id_context(&result, matched) {
                            redact_student_id_with_strategy(matched, strategy)
                        } else {
                            matched.to_string()
                        }
                    })
                    .into_owned(),
            );
        }
    }

    result
}

/// Redact all badge number patterns in text using text redaction policy
///
/// Scans text for badge numbers and replaces them according to the policy.
/// The policy is mapped to appropriate domain strategies internally.
///
/// # Returns
///
/// `Cow<'_, str>` - Borrowed if no badges found, owned if replacements made.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::organizational::{TextRedactionPolicy, redact_badge_numbers_in_text};
///
/// let text = "Badge: BADGE# 98765";
///
/// // Complete redaction
/// let safe = redact_badge_numbers_in_text(text, TextRedactionPolicy::Complete);
/// assert!(safe.contains("[BADGE]"));
/// ```
pub fn redact_badge_numbers_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_badge_strategy();

    // None policy - return as-is
    if matches!(strategy, BadgeRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let mut result = Cow::Borrowed(text);

    for pattern in organizational::badge_number::all() {
        if pattern.is_match(&result) {
            result = Cow::Owned(
                pattern
                    .replace_all(&result, |caps: &regex::Captures<'_>| {
                        let matched = &caps[0];
                        redact_badge_number_with_strategy(matched, strategy)
                    })
                    .into_owned(),
            );
        }
    }

    result
}

/// Check if a match is likely a student ID based on surrounding context
fn is_likely_student_id_context(text: &str, potential_id: &str) -> bool {
    // S-number format is unambiguous
    if potential_id.starts_with('S') || potential_id.starts_with('s') {
        return true;
    }

    // For XXX-XX-XXXX format, check for student-related keywords
    let context_keywords = [
        "student",
        "stu",
        "enrollment",
        "university",
        "college",
        "school",
    ];

    let id_pos = text.find(potential_id).unwrap_or(0);
    let start = id_pos.saturating_sub(30);
    let end = id_pos
        .saturating_add(potential_id.len())
        .saturating_add(30)
        .min(text.len());
    let context = &text[start..end].to_lowercase();

    context_keywords
        .iter()
        .any(|&keyword| context.contains(keyword))
}

/// Redact all organizational ID patterns in text using text redaction policy
///
/// Comprehensive redaction for employee IDs, student IDs, and badge numbers.
/// The policy is applied consistently across all identifier types.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::organizational::{TextRedactionPolicy, redact_all_organizational_ids_in_text};
///
/// let text = "Employee: E123456, Student: S98765432, Badge: BADGE# 98765";
///
/// // Complete redaction
/// let safe = redact_all_organizational_ids_in_text(text, TextRedactionPolicy::Complete);
/// assert!(safe.contains("[EMPLOYEE_ID]"));
/// assert!(safe.contains("[STUDENT_ID]"));
/// assert!(safe.contains("[BADGE]"));
/// ```
pub fn redact_all_organizational_ids_in_text(text: &str, policy: TextRedactionPolicy) -> String {
    let result = redact_employee_ids_in_text(text, policy);
    let result = redact_student_ids_in_text(&result, policy);
    let result = redact_badge_numbers_in_text(&result, policy);

    result.into_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== Employee ID Redaction Tests =====

    #[test]
    fn test_redact_employee_id_with_strategy_show_prefix() {
        assert_eq!(
            redact_employee_id_with_strategy("E123456", EmployeeIdRedactionStrategy::ShowPrefix),
            "E-****"
        );
        assert_eq!(
            redact_employee_id_with_strategy("EMP00123", EmployeeIdRedactionStrategy::ShowPrefix),
            "EMP-****"
        );
    }

    #[test]
    fn test_redact_employee_id_with_strategy_token() {
        assert_eq!(
            redact_employee_id_with_strategy("E123456", EmployeeIdRedactionStrategy::Token),
            "[EMPLOYEE_ID]"
        );
    }

    #[test]
    fn test_redact_employee_id_with_strategy_invalid() {
        // Invalid format should return token
        assert_eq!(
            redact_employee_id_with_strategy("invalid", EmployeeIdRedactionStrategy::ShowPrefix),
            "[EMPLOYEE_ID]"
        );
    }

    // ===== Student ID Redaction Tests =====

    #[test]
    fn test_redact_student_id_with_strategy_token() {
        assert_eq!(
            redact_student_id_with_strategy("S12345678", StudentIdRedactionStrategy::Token),
            "[STUDENT_ID]"
        );
    }

    #[test]
    fn test_redact_student_id_with_strategy_invalid() {
        assert_eq!(
            redact_student_id_with_strategy("invalid", StudentIdRedactionStrategy::Token),
            "[STUDENT_ID]"
        );
    }

    // ===== Badge Number Redaction Tests =====

    #[test]
    fn test_redact_badge_number_with_strategy_token() {
        assert_eq!(
            redact_badge_number_with_strategy("BADGE# 98765", BadgeRedactionStrategy::Token),
            "[BADGE_NUMBER]"
        );
    }

    #[test]
    fn test_redact_badge_number_with_strategy_invalid() {
        assert_eq!(
            redact_badge_number_with_strategy("invalid", BadgeRedactionStrategy::Token),
            "[BADGE_NUMBER]"
        );
    }

    // ===== Text Redaction Tests =====

    #[test]
    fn test_redact_employee_ids_in_text_complete() {
        let text = "Employee ID: E123456";
        let result = redact_employee_ids_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[EMPLOYEE_ID]"));
    }

    #[test]
    fn test_redact_employee_ids_multiple() {
        let text = "Employees: E123456, E234567, E345678";
        let result = redact_employee_ids_in_text(text, TextRedactionPolicy::Complete);
        // Should have 3 redactions
        assert_eq!(result.matches("[EMPLOYEE_ID]").count(), 3);
    }

    #[test]
    fn test_redact_student_ids_in_text_complete() {
        let text = "Student ID: S12345678";
        let result = redact_student_ids_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[STUDENT_ID]"));
    }

    #[test]
    fn test_student_id_requires_context() {
        // XXX-XX-XXXX without student context should NOT redact
        let text = "Reference: 900-00-0001";
        let result = redact_student_ids_in_text(text, TextRedactionPolicy::Complete);
        assert!(!result.contains("[STUDENT_ID]"));

        // Same format with student context SHOULD redact
        let text = "Student enrollment: 900-00-0001";
        let result = redact_student_ids_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[STUDENT_ID]"));
    }

    #[test]
    fn test_redact_badge_numbers_in_text_complete() {
        let text = "Badge: BADGE# 98765";
        let result = redact_badge_numbers_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[BADGE_NUMBER]"));
    }

    #[test]
    fn test_redact_all_organizational_ids() {
        let text = "Employee: E123456, Student: S98765432, Badge: BADGE# 98765";
        let result = redact_all_organizational_ids_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[EMPLOYEE_ID]"));
        assert!(result.contains("[STUDENT_ID]"));
        assert!(result.contains("[BADGE_NUMBER]"));
    }

    #[test]
    fn test_no_redaction_in_clean_text() {
        let text = "This text contains no organizational IDs";
        let result = redact_all_organizational_ids_in_text(text, TextRedactionPolicy::Complete);
        assert_eq!(result, text);
    }

    #[test]
    fn test_cow_optimization() {
        // Clean text should return borrowed
        let text = "Clean text";
        let result = redact_employee_ids_in_text(text, TextRedactionPolicy::Complete);
        assert!(matches!(result, Cow::Borrowed(_)));

        // Dirty text should return owned
        let text = "Employee: E123456";
        let result = redact_employee_ids_in_text(text, TextRedactionPolicy::Complete);
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn test_none_policy_passthrough() {
        let text = "Employee: E123456";
        let result = redact_employee_ids_in_text(text, TextRedactionPolicy::Skip);
        assert_eq!(result, text);
    }
}

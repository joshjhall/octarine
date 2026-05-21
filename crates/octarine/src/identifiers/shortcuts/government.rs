//! Government identifier shortcuts (SSN, EIN, Singapore, Australia).
//!
//! Convenience functions over [`GovernmentBuilder`](super::super::GovernmentBuilder).

use crate::observe::Problem;
use crate::primitives::identifiers::SsnRedactionStrategy;

use super::super::GovernmentBuilder;
use super::super::types::IdentifierMatch;

/// Check if value is an SSN
#[must_use]
pub fn is_ssn(value: &str) -> bool {
    GovernmentBuilder::new().is_ssn(value)
}

/// Validate an SSN format
///
/// # Errors
///
/// Returns `Problem` if the SSN format is invalid.
pub fn validate_ssn(ssn: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_ssn(ssn)
}

/// Find all SSNs in text
#[must_use]
pub fn find_ssns(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_ssns_in_text(text)
}

/// Redact an SSN
#[must_use]
pub fn redact_ssn(ssn: &str) -> String {
    GovernmentBuilder::new().redact_ssn_with_strategy(ssn, SsnRedactionStrategy::Token)
}

/// Redact all SSNs in text
#[must_use]
pub fn redact_ssns(text: &str) -> String {
    GovernmentBuilder::new().redact_ssns_in_text_with_strategy(text, SsnRedactionStrategy::Token)
}

/// Check if value is a valid EIN (Employer Identification Number)
#[must_use]
pub fn is_ein(value: &str) -> bool {
    GovernmentBuilder::new().is_ein(value)
}

/// Find all valid EINs in text
#[must_use]
pub fn find_eins(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_eins_in_text(text)
}

/// Validate an EIN format
///
/// # Errors
///
/// Returns `Problem` if the EIN format or IRS campus code prefix is invalid.
pub fn validate_ein(ein: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_ein(ein)
}

// =============================================================================
// Singapore UEN
// =============================================================================

/// Check if value is a Singapore UEN
#[must_use]
pub fn is_singapore_uen(value: &str) -> bool {
    GovernmentBuilder::new().is_singapore_uen(value)
}

/// Find all Singapore UEN values in text
#[must_use]
pub fn find_singapore_uens(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_singapore_uens_in_text(text)
}

/// Validate a Singapore UEN layout
///
/// # Errors
///
/// Returns `Problem` if the UEN does not match any published layout.
pub fn validate_singapore_uen(uen: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_singapore_uen(uen)
}

// =============================================================================
// Australia Medicare
// =============================================================================

/// Check if value is an Australian Medicare number
#[must_use]
pub fn is_australia_medicare(value: &str) -> bool {
    GovernmentBuilder::new().is_australia_medicare(value)
}

/// Find all Australian Medicare numbers in text
#[must_use]
pub fn find_australia_medicares(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_australia_medicares_in_text(text)
}

/// Validate an Australian Medicare format
///
/// # Errors
///
/// Returns `Problem` if the Medicare format is invalid.
pub fn validate_australia_medicare(value: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_australia_medicare(value)
}

// =============================================================================
// Australia ACN
// =============================================================================

/// Check if value is an Australian Company Number
#[must_use]
pub fn is_australia_acn(value: &str) -> bool {
    GovernmentBuilder::new().is_australia_acn(value)
}

/// Find all Australian ACNs in text
#[must_use]
pub fn find_australia_acns(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_australia_acns_in_text(text)
}

/// Validate an Australian ACN format
///
/// # Errors
///
/// Returns `Problem` if the ACN format is invalid.
pub fn validate_australia_acn(acn: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_australia_acn(acn)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validate_ssn_shortcut() {
        // Valid SSN (non-test pattern, valid area/group/serial)
        assert!(validate_ssn("517-29-8346").is_ok());
        // Invalid SSN (all zeros area)
        assert!(validate_ssn("000-00-0000").is_err());
        assert!(validate_ssn("not-an-ssn").is_err());
    }

    #[test]
    fn test_singapore_uen_shortcuts() {
        assert!(is_singapore_uen("201912345K"));
        assert!(!is_singapore_uen("not a uen"));
        assert!(validate_singapore_uen("201912345K").is_ok());
        assert!(validate_singapore_uen("").is_err());
        assert!(!find_singapore_uens("UEN: 201912345K registered").is_empty());
    }

    #[test]
    fn test_australia_medicare_shortcuts() {
        assert!(is_australia_medicare("2123 45670 1"));
        assert!(!is_australia_medicare("1234567890")); // first digit not 2-6
        assert!(validate_australia_medicare("2123456701").is_ok());
        assert!(validate_australia_medicare("").is_err());
        assert!(!find_australia_medicares("Patient Medicare 2123 45670 1").is_empty());
    }

    #[test]
    fn test_australia_acn_shortcuts() {
        assert!(is_australia_acn("004 085 616"));
        assert!(!is_australia_acn("12345678")); // too short
        assert!(validate_australia_acn("004085616").is_ok());
        assert!(validate_australia_acn("").is_err());
        assert!(!find_australia_acns("ACN 004 085 616 active").is_empty());
    }
}

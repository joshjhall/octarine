//! Government identifier shortcuts (SSN, EIN).
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
}

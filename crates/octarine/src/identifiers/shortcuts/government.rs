//! US government identifier shortcuts (SSN, EIN, ITIN, MBI, Driver License, Passport).
//!
//! Convenience functions over [`GovernmentBuilder`](super::super::GovernmentBuilder).
//! Non-US jurisdictions live in [`super::government_international`].

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
// US ITIN (Individual Taxpayer Identification Number)
// =============================================================================

/// Check if value is a valid ITIN (Individual Taxpayer Identification Number)
///
/// Strict — area must be `9XX` and the middle group must lie in
/// `{50-65, 70-88, 90-92, 94-99}` per IRS Publication 1915.
#[must_use]
pub fn is_itin(value: &str) -> bool {
    GovernmentBuilder::new().is_itin(value)
}

/// Find all valid ITINs in text
#[must_use]
pub fn find_itins(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_itins_in_text(text)
}

/// Validate an ITIN format
///
/// # Errors
///
/// Returns `Problem` if the ITIN format, area, middle group, or serial is
/// invalid.
pub fn validate_itin(itin: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_itin(itin)
}

// =============================================================================
// US MBI (Medicare Beneficiary Identifier)
// =============================================================================

/// Check if value is a valid US Medicare Beneficiary Identifier (MBI)
///
/// Strict — enforces the 11-character CMS layout and the letter alphabet
/// `ACDEFGHJKMNPQRTUVWXY` (excluding `S, L, O, I, B, Z`). Accepts both the bare
/// and dashed `XXXX-XXX-XXXX` forms.
#[must_use]
pub fn is_us_mbi(value: &str) -> bool {
    GovernmentBuilder::new().is_us_mbi(value)
}

/// Find all valid US MBIs in text
#[must_use]
pub fn find_us_mbis(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_us_mbis_in_text(text)
}

/// Validate a US MBI format
///
/// # Errors
///
/// Returns `Problem` if the MBI length, dash grouping, positional layout, or
/// letter alphabet is invalid.
pub fn validate_us_mbi(mbi: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_us_mbi(mbi)
}

// =============================================================================
// US Driver License
// =============================================================================

/// Check if value looks like a US driver's license
#[must_use]
pub fn is_driver_license(value: &str) -> bool {
    GovernmentBuilder::new().is_driver_license(value)
}

/// Find all driver's licenses in text
#[must_use]
pub fn find_driver_licenses(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_driver_licenses_in_text(text)
}

/// Validate a driver's license format for a US state
///
/// Covers the top 20 states by population. An unrecognised state code is an
/// error, not a pass-through — use the detection layer for shape-only checks.
///
/// # Errors
///
/// Returns `Problem` if the license does not match any layout the state
/// issues, or if the state is not a supported jurisdiction.
pub fn validate_driver_license(license: &str, state: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_driver_license(license, state)
}

/// Validate a driver's license format **and** check digit for a US state
///
/// Stricter than [`validate_driver_license`]: also verifies the check digit
/// for the jurisdictions that publish one (CA, FL, WA).
///
/// # Errors
///
/// Returns `Problem` if the format is invalid, the check digit fails, or the
/// state is not a supported jurisdiction.
pub fn validate_driver_license_with_checksum(license: &str, state: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_driver_license_with_checksum(license, state)
}

// =============================================================================
// US Passport
// =============================================================================

/// Validate a US passport number (lenient)
///
/// Accepts both layouts the US has issued and that remain in circulation:
/// 9 digits (legacy books) and 1 letter + 8 digits (Next Generation). Test
/// patterns are **not** rejected — a real number is not invalid because its
/// digits happen to run in sequence. Use [`validate_us_passport_strict`] when
/// filtering sample and documentation numbers is the point.
///
/// # Errors
///
/// Returns `Problem` if the number matches neither US layout.
pub fn validate_us_passport(passport: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_us_passport(passport)
}

/// Validate a US passport number, rejecting known test patterns (strict)
///
/// # Errors
///
/// Returns `Problem` if the format is invalid, or the number is a known test
/// pattern (all-zero, all-same-digit, or a sequential run).
pub fn validate_us_passport_strict(passport: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_us_passport_strict(passport)
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
    fn test_us_mbi_shortcuts() {
        assert!(is_us_mbi("1EG4TE5MK73"));
        assert!(is_us_mbi("1EG4-TE5-MK73"));
        assert!(!is_us_mbi("1AB2C3D4EF5")); // excluded letter / bad layout
        assert!(validate_us_mbi("1EG4TE5MK73").is_ok());
        assert!(validate_us_mbi("").is_err());
        assert!(!find_us_mbis("Medicare MBI: 1EG4-TE5-MK73").is_empty());
    }

    #[test]
    fn test_us_driver_license_shortcuts() {
        assert!(is_driver_license("A1234567"));
        assert!(!is_driver_license("!"));
        assert!(validate_driver_license("A1234567", "CA").is_ok());
        assert!(validate_driver_license("12345678", "PA").is_ok());
        // Unknown jurisdiction is an error, not a pass-through (issue #440).
        assert!(validate_driver_license("CUST123456", "XX").is_err());
        // The checksum variant is stricter on a jurisdiction that has one.
        assert!(validate_driver_license_with_checksum("A1234567", "CA").is_err());
        assert!(!find_driver_licenses("DL# A1234567").is_empty());
    }

    #[test]
    fn test_us_passport_shortcuts() {
        // Legacy 9-digit books are accepted (issue #440).
        assert!(validate_us_passport("123456789").is_ok());
        assert!(validate_us_passport("A83726159").is_ok());
        assert!(validate_us_passport("AB1234567").is_err());
        // Strict rejects test patterns the lenient variant allows.
        assert!(validate_us_passport("A12345678").is_ok());
        assert!(validate_us_passport_strict("A12345678").is_err());
        assert!(validate_us_passport_strict("A83726159").is_ok());
    }
}

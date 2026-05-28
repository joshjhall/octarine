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

// =============================================================================
// South Korea — RRN, FRN, Driver License, Passport, BRN
// =============================================================================

/// Check if value is a South Korea RRN (Resident Registration Number)
#[must_use]
pub fn is_korea_rrn(value: &str) -> bool {
    GovernmentBuilder::new().is_korea_rrn(value)
}

/// Find all South Korea RRNs in text
#[must_use]
pub fn find_korea_rrns(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_korea_rrns_in_text(text)
}

/// Validate a South Korea RRN format
///
/// # Errors
///
/// Returns `Problem` if the RRN format is invalid.
pub fn validate_korea_rrn(rrn: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_korea_rrn(rrn)
}

/// Check if value is a South Korea FRN (Foreign Registration Number)
#[must_use]
pub fn is_korea_frn(value: &str) -> bool {
    GovernmentBuilder::new().is_korea_frn(value)
}

/// Find all South Korea FRNs in text
#[must_use]
pub fn find_korea_frns(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_korea_frns_in_text(text)
}

/// Validate a South Korea FRN format
///
/// # Errors
///
/// Returns `Problem` if the FRN format is invalid.
pub fn validate_korea_frn(frn: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_korea_frn(frn)
}

/// Check if value is a South Korea Driver License
#[must_use]
pub fn is_korea_driver_license(value: &str) -> bool {
    GovernmentBuilder::new().is_korea_driver_license(value)
}

/// Find all South Korea Driver Licenses in text
#[must_use]
pub fn find_korea_driver_licenses(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_korea_driver_licenses_in_text(text)
}

/// Validate a South Korea Driver License format
///
/// # Errors
///
/// Returns `Problem` if the license format or region is invalid.
pub fn validate_korea_driver_license(dl: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_korea_driver_license(dl)
}

/// Check if value is a South Korea Passport
#[must_use]
pub fn is_korea_passport(value: &str) -> bool {
    GovernmentBuilder::new().is_korea_passport(value)
}

/// Find all South Korea passports in text
#[must_use]
pub fn find_korea_passports(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_korea_passports_in_text(text)
}

/// Validate a South Korea Passport format
///
/// # Errors
///
/// Returns `Problem` if the passport format is invalid.
pub fn validate_korea_passport(passport: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_korea_passport(passport)
}

/// Check if value is a South Korea BRN (Business Registration Number)
#[must_use]
pub fn is_korea_brn(value: &str) -> bool {
    GovernmentBuilder::new().is_korea_brn(value)
}

/// Find all South Korea BRNs in text
#[must_use]
pub fn find_korea_brns(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_korea_brns_in_text(text)
}

/// Validate a South Korea BRN format
///
/// # Errors
///
/// Returns `Problem` if the BRN format is invalid.
pub fn validate_korea_brn(brn: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_korea_brn(brn)
}

// =============================================================================
// Italy — Partita IVA (VAT), Passport, Identity Card, Driver License
// =============================================================================
//
// `ItalyFiscalCode` (Codice Fiscale) shortcuts are deliberately omitted —
// they predate the shortcuts file and remain accessible through
// `GovernmentBuilder` directly.

/// Check if value is an Italy Partita IVA (VAT)
#[must_use]
pub fn is_italy_vat(value: &str) -> bool {
    GovernmentBuilder::new().is_italy_vat(value)
}

/// Find all Italy VAT mentions in text (label-anchored)
#[must_use]
pub fn find_italy_vats(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_italy_vats_in_text(text)
}

/// Validate an Italy VAT format
///
/// # Errors
///
/// Returns `Problem` if the VAT is not exactly 11 digits.
pub fn validate_italy_vat(vat: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_italy_vat(vat)
}

/// Validate an Italy VAT with mod-10 Luhn-style checksum
///
/// # Errors
///
/// Returns `Problem` if format or checksum fails.
pub fn validate_italy_vat_with_checksum(vat: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_italy_vat_with_checksum(vat)
}

/// Check if value is an Italy passport
#[must_use]
pub fn is_italy_passport(value: &str) -> bool {
    GovernmentBuilder::new().is_italy_passport(value)
}

/// Find all Italy passport mentions in text (label-anchored)
#[must_use]
pub fn find_italy_passports(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_italy_passports_in_text(text)
}

/// Validate an Italy passport format
///
/// # Errors
///
/// Returns `Problem` if the format is invalid.
pub fn validate_italy_passport(passport: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_italy_passport(passport)
}

/// Check if value is an Italy identity card (paper, CIE 2.0, or CIE 3.0)
#[must_use]
pub fn is_italy_identity_card(value: &str) -> bool {
    GovernmentBuilder::new().is_italy_identity_card(value)
}

/// Find all Italy identity card mentions in text (label-anchored)
#[must_use]
pub fn find_italy_identity_cards(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_italy_identity_cards_in_text(text)
}

/// Validate an Italy identity card format
///
/// # Errors
///
/// Returns `Problem` if the format matches none of the three supported
/// layouts.
pub fn validate_italy_identity_card(card: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_italy_identity_card(card)
}

/// Check if value is an Italy driver license (standard or U1 Carta
/// Conducente)
#[must_use]
pub fn is_italy_driver_license(value: &str) -> bool {
    GovernmentBuilder::new().is_italy_driver_license(value)
}

/// Find all Italy driver license mentions in text
#[must_use]
pub fn find_italy_driver_licenses(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_italy_driver_licenses_in_text(text)
}

/// Validate an Italy driver license format
///
/// # Errors
///
/// Returns `Problem` if the format matches neither the standard nor U1
/// form.
pub fn validate_italy_driver_license(license: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_italy_driver_license(license)
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

    #[test]
    fn test_korea_rrn_shortcuts() {
        assert!(is_korea_rrn("900115-1234567"));
        assert!(!is_korea_rrn("900115-5234567")); // gender 5 is FRN, not RRN
        assert!(validate_korea_rrn("900115-1234567").is_ok());
        assert!(validate_korea_rrn("").is_err());
        assert!(!find_korea_rrns("RRN: 900115-1234567").is_empty());
    }

    #[test]
    fn test_korea_frn_shortcuts() {
        assert!(is_korea_frn("900115-5234567"));
        assert!(!is_korea_frn("900115-1234567")); // gender 1 is RRN, not FRN
        assert!(validate_korea_frn("900115-5234567").is_ok());
        assert!(validate_korea_frn("").is_err());
        assert!(!find_korea_frns("FRN: 900115-5234567").is_empty());
    }

    #[test]
    fn test_korea_driver_license_shortcuts() {
        assert!(is_korea_driver_license("11-90-123456-78"));
        assert!(!is_korea_driver_license("10-90-123456-78")); // region 10 out of range
        assert!(validate_korea_driver_license("11-90-123456-78").is_ok());
        assert!(validate_korea_driver_license("").is_err());
        assert!(!find_korea_driver_licenses("Driver License: 11-90-123456-78 issued").is_empty());
    }

    #[test]
    fn test_korea_passport_shortcuts() {
        assert!(is_korea_passport("M12345678"));
        assert!(is_korea_passport("MA12345678"));
        assert!(!is_korea_passport("A12345678")); // wrong prefix
        assert!(validate_korea_passport("M12345678").is_ok());
        assert!(validate_korea_passport("").is_err());
        assert!(!find_korea_passports("KR passport: M12345678 valid").is_empty());
    }

    #[test]
    fn test_korea_brn_shortcuts() {
        assert!(is_korea_brn("123-45-67890"));
        assert!(!is_korea_brn("12-345-6789")); // wrong shape (SSN-like)
        assert!(validate_korea_brn("123-45-67890").is_ok());
        assert!(validate_korea_brn("").is_err());
        assert!(!find_korea_brns("BRN: 123-45-67890 registered").is_empty());
    }
}

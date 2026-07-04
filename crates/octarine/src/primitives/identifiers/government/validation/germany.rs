//! German government-identifier validation — Steuer-IdNr (tax ID),
//! Personalausweis (nPA), and Reisepass (passport).
//!
//! Format validators check shape and reject empty input; the
//! `*_with_checksum` variants additionally verify the ISO 7064 mod-11,10
//! (tax ID) or ICAO Doc 9303 (nPA/passport) check digit. Each validator calls
//! detection first, honoring the inheritance arrow.

use super::super::common::{germany_tax_id as tax_id_checks, icao_doc_9303};
use super::super::detection;
use crate::primitives::types::Problem;

/// Length of the ICAO document-number body (before the check digit).
const ICAO_DOC_BODY_LEN: usize = 9;

// ============================================================================
// Steuer-IdNr
// ============================================================================

/// Validate German Steuer-IdNr format (11 digits, structural + checksum rules).
///
/// Because the Steuer-IdNr's validity is defined by its checksum and
/// structural rule, this format check is equivalent to full validation:
/// `is_germany_tax_id` already enforces both.
///
/// # Errors
///
/// Returns `Problem::Validation` if the value is not a valid Steuer-IdNr.
pub fn validate_germany_tax_id(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Germany Steuer-IdNr cannot be empty".to_string(),
        ));
    }
    if !detection::is_germany_tax_id(trimmed) {
        return Err(Problem::Validation(
            "Invalid Germany Steuer-IdNr format".to_string(),
        ));
    }
    Ok(())
}

/// Validate German Steuer-IdNr with explicit ISO 7064 mod-11,10 checksum.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format, structural rule, or checksum
/// is invalid.
pub fn validate_germany_tax_id_with_checksum(value: &str) -> Result<(), Problem> {
    validate_germany_tax_id(value)?;

    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if !tax_id_checks::verify_structure(&digits) {
        return Err(Problem::Validation(
            "Germany Steuer-IdNr structural rule failed (expected exactly one repeated digit)"
                .to_string(),
        ));
    }
    if !tax_id_checks::verify_checksum(&digits) {
        return Err(Problem::Validation(
            "Germany Steuer-IdNr ISO 7064 mod-11,10 checksum failed".to_string(),
        ));
    }
    Ok(())
}

/// Check if a value is a well-known test/dummy Steuer-IdNr.
///
/// The BZSt documentation number `02476291358` (leading-zero, not issuable)
/// and repeated-digit placeholders are treated as test patterns.
#[must_use]
pub fn is_test_germany_tax_id(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 11 {
        return false;
    }
    // Documentation example, and any leading-zero value (non-issuable).
    if digits.starts_with('0') {
        return true;
    }
    // All-same or trivially sequential leading run.
    let bytes = digits.as_bytes();
    let first = bytes.first().copied();
    if first.is_some() && bytes.iter().all(|&b| Some(b) == first) {
        return true;
    }
    false
}

// ============================================================================
// Personalausweis (nPA)
// ============================================================================

/// Validate German Personalausweis (nPA) format.
///
/// # Errors
///
/// Returns `Problem::Validation` if the value is not a valid nPA number.
pub fn validate_germany_id_card(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Germany Personalausweis cannot be empty".to_string(),
        ));
    }
    if !detection::is_germany_id_card(trimmed) {
        return Err(Problem::Validation(
            "Invalid Germany Personalausweis format".to_string(),
        ));
    }
    Ok(())
}

/// Validate German Personalausweis with explicit ICAO Doc 9303 check digit.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format or check digit is invalid.
pub fn validate_germany_id_card_with_checksum(value: &str) -> Result<(), Problem> {
    validate_germany_id_card(value)?;
    if !icao_doc_9303::verify(&value.trim().to_uppercase(), ICAO_DOC_BODY_LEN) {
        return Err(Problem::Validation(
            "Germany Personalausweis ICAO Doc 9303 check digit failed".to_string(),
        ));
    }
    Ok(())
}

// ============================================================================
// Reisepass (passport)
// ============================================================================

/// Validate German Reisepass (passport) format.
///
/// # Errors
///
/// Returns `Problem::Validation` if the value is not a valid passport number.
pub fn validate_germany_passport(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Germany Reisepass cannot be empty".to_string(),
        ));
    }
    if !detection::is_germany_passport(trimmed) {
        return Err(Problem::Validation(
            "Invalid Germany Reisepass format".to_string(),
        ));
    }
    Ok(())
}

/// Validate German Reisepass with explicit ICAO Doc 9303 check digit.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format or check digit is invalid.
pub fn validate_germany_passport_with_checksum(value: &str) -> Result<(), Problem> {
    validate_germany_passport(value)?;
    if !icao_doc_9303::verify(&value.trim().to_uppercase(), ICAO_DOC_BODY_LEN) {
        return Err(Problem::Validation(
            "Germany Reisepass ICAO Doc 9303 check digit failed".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    const VALID_TAX_ID: &str = "10002345676";
    const VALID_ID_CARD: &str = "CH20064148";
    const VALID_PASSPORT: &str = "T220001293";

    // ----- Steuer-IdNr -----

    #[test]
    fn test_validate_germany_tax_id_valid() {
        assert!(validate_germany_tax_id(VALID_TAX_ID).is_ok());
        assert!(validate_germany_tax_id_with_checksum(VALID_TAX_ID).is_ok());
    }

    #[test]
    fn test_validate_germany_tax_id_empty() {
        assert!(validate_germany_tax_id("").is_err());
    }

    #[test]
    fn test_validate_germany_tax_id_bad_checksum() {
        assert!(validate_germany_tax_id_with_checksum("10002345675").is_err());
    }

    #[test]
    fn test_validate_germany_tax_id_wrong_length() {
        assert!(validate_germany_tax_id("1000234567").is_err());
    }

    #[test]
    fn test_is_test_germany_tax_id() {
        assert!(is_test_germany_tax_id("02476291358")); // doc example
        assert!(is_test_germany_tax_id("11111111111")); // all same
        assert!(!is_test_germany_tax_id(VALID_TAX_ID));
    }

    // ----- Personalausweis -----

    #[test]
    fn test_validate_germany_id_card_valid() {
        assert!(validate_germany_id_card(VALID_ID_CARD).is_ok());
        assert!(validate_germany_id_card_with_checksum(VALID_ID_CARD).is_ok());
    }

    #[test]
    fn test_validate_germany_id_card_bad_check_digit() {
        assert!(validate_germany_id_card_with_checksum("CH20064149").is_err());
    }

    #[test]
    fn test_validate_germany_id_card_empty() {
        assert!(validate_germany_id_card("").is_err());
    }

    // ----- Reisepass -----

    #[test]
    fn test_validate_germany_passport_valid() {
        assert!(validate_germany_passport(VALID_PASSPORT).is_ok());
        assert!(validate_germany_passport_with_checksum(VALID_PASSPORT).is_ok());
    }

    #[test]
    fn test_validate_germany_passport_bad_check_digit() {
        assert!(validate_germany_passport_with_checksum("T220001294").is_err());
    }

    #[test]
    fn test_validate_germany_passport_empty() {
        assert!(validate_germany_passport("").is_err());
    }
}

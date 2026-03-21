//! Strict sanitization functions
//!
//! Functions that normalize and validate government identifiers.

use crate::primitives::Problem;

use super::super::{conversion, validation};

// ============================================================================
// Strict Sanitization (Normalize + Validate)
// ============================================================================

/// Sanitize SSN strict (normalize format + validate)
///
/// Removes formatting and validates the SSN format and area code.
/// Returns normalized format (XXX-XX-XXXX) if valid, error otherwise.
///
/// This combines normalization and validation in one step - the most
/// common pattern for accepting SSN input.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization;
///
/// // Valid SSN with spaces
/// let sanitized = sanitization::sanitize_ssn_strict("900 00 0001")?;
/// assert_eq!(sanitized, "900-00-0001");
///
/// // Valid SSN already formatted
/// let sanitized = sanitization::sanitize_ssn_strict("900-00-0001")?;
/// assert_eq!(sanitized, "900-00-0001");
///
/// // Invalid SSN (bad format)
/// assert!(sanitization::sanitize_ssn_strict("123456789").is_err());
/// ```
pub fn sanitize_ssn_strict(ssn: &str) -> Result<String, Problem> {
    // Normalize format (remove spaces, ensure dashes)
    let normalized = conversion::normalize_ssn(ssn);

    // Format with dashes
    let formatted = conversion::to_ssn_with_hyphens(&normalized);

    // Validate using validation layer (includes format and area code checks)
    validation::validate_ssn(&formatted)?;

    Ok(formatted)
}

/// Sanitize EIN strict (normalize format + validate)
///
/// Removes formatting and validates the EIN format and campus code prefix.
/// Returns normalized format (XX-XXXXXXX) if valid, error otherwise.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization;
///
/// // Valid EIN with spaces
/// let sanitized = sanitization::sanitize_ein_strict("12 3456789")?;
/// assert_eq!(sanitized, "12-3456789");
///
/// // Invalid EIN (bad prefix)
/// assert!(sanitization::sanitize_ein_strict("00-0000000").is_err());
/// ```
pub fn sanitize_ein_strict(ein: &str) -> Result<String, Problem> {
    // Normalize format (remove dashes, spaces)
    let normalized = conversion::normalize_ein(ein);

    // Format with hyphen
    let formatted = conversion::to_ein_with_hyphen(&normalized);

    // Validate using validation layer (includes format and campus code checks)
    validation::validate_ein(&formatted)?;

    Ok(formatted)
}

/// Sanitize VIN strict (normalize format + validate)
///
/// Normalizes to uppercase and validates the VIN format and checksum.
/// Returns normalized 17-character VIN if valid, error otherwise.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization;
///
/// // Valid VIN lowercase
/// let sanitized = sanitization::sanitize_vin_strict("1hgbh41jxmn109186")?;
/// assert_eq!(sanitized, "1HGBH41JXMN109186");
///
/// // Invalid VIN (wrong length)
/// assert!(sanitization::sanitize_vin_strict("1234567890").is_err());
/// ```
pub fn sanitize_vin_strict(vin: &str) -> Result<String, Problem> {
    // Normalize format (uppercase, remove spaces/dashes)
    let normalized = conversion::normalize_vin(vin);

    // Validate using validation layer (includes format and checksum)
    validation::validate_vin_with_checksum(&normalized)?;

    Ok(normalized)
}

/// Sanitize driver license strict (normalize format + validate)
///
/// Normalizes to uppercase and validates the driver's license format for the given state.
/// Returns normalized license number if valid, error otherwise.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization;
///
/// // Valid California license
/// let sanitized = sanitization::sanitize_driver_license_strict("d1234567", "CA")?;
/// assert_eq!(sanitized, "D1234567");
///
/// // Invalid format for state
/// assert!(sanitization::sanitize_driver_license_strict("123", "CA").is_err());
/// ```
pub fn sanitize_driver_license_strict(license: &str, state: &str) -> Result<String, Problem> {
    // Normalize format (uppercase, remove spaces/dashes)
    let normalized = conversion::normalize_driver_license(license);

    // Validate using validation layer (state-specific format checks)
    validation::validate_driver_license(&normalized, state)?;

    Ok(normalized)
}

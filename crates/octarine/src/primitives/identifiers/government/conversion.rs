//! Government identifier format conversion (primitives layer)
//!
//! Pure conversion functions for normalizing and formatting government identifiers.
//! No observe dependencies.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns data, no side effects
//! - Used by observe/pii and security modules

use super::super::common::masking;

// ============================================================================
// SSN Conversion
// ============================================================================

/// Normalize SSN to digits only
///
/// Removes all formatting (hyphens, spaces) and returns raw digits.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(conversion::normalize_ssn("123-45-6789"), "123456789");
/// assert_eq!(conversion::normalize_ssn("123 45 6789"), "123456789");
/// assert_eq!(conversion::normalize_ssn("123456789"), "123456789");
/// ```
#[must_use]
pub fn normalize_ssn(ssn: &str) -> String {
    masking::digits_only(ssn)
}

/// Convert SSN to standard hyphenated format
///
/// Converts any SSN format to XXX-XX-XXXX.
///
/// # Returns
///
/// Formatted SSN string, or original if not 9 digits.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(conversion::to_ssn_with_hyphens("123456789"), "123-45-6789");
/// assert_eq!(conversion::to_ssn_with_hyphens("123-45-6789"), "123-45-6789");
/// assert_eq!(conversion::to_ssn_with_hyphens("123 45 6789"), "123-45-6789");
/// ```
#[must_use]
pub fn to_ssn_with_hyphens(ssn: &str) -> String {
    let digits = normalize_ssn(ssn);

    if digits.len() == 9 {
        format!("{}-{}-{}", &digits[0..3], &digits[3..5], &digits[5..9])
    } else {
        ssn.to_string()
    }
}

/// Convert SSN to space-separated format
///
/// Converts any SSN format to XXX XX XXXX.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(conversion::to_ssn_with_spaces("123456789"), "123 45 6789");
/// ```
#[must_use]
pub fn to_ssn_with_spaces(ssn: &str) -> String {
    let digits = normalize_ssn(ssn);

    if digits.len() == 9 {
        format!("{} {} {}", &digits[0..3], &digits[3..5], &digits[5..9])
    } else {
        ssn.to_string()
    }
}

/// Extract SSN area number (first 3 digits)
///
/// The area number was historically geographic-based.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(conversion::extract_ssn_area("123-45-6789"), Some("123".to_string()));
/// ```
#[must_use]
pub fn extract_ssn_area(ssn: &str) -> Option<String> {
    let digits = normalize_ssn(ssn);
    if digits.len() >= 3 {
        Some(digits[0..3].to_string())
    } else {
        None
    }
}

/// Extract SSN group number (middle 2 digits)
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(conversion::extract_ssn_group("123-45-6789"), Some("45".to_string()));
/// ```
#[must_use]
pub fn extract_ssn_group(ssn: &str) -> Option<String> {
    let digits = normalize_ssn(ssn);
    if digits.len() >= 5 {
        Some(digits[3..5].to_string())
    } else {
        None
    }
}

/// Extract SSN serial number (last 4 digits)
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(conversion::extract_ssn_serial("123-45-6789"), Some("6789".to_string()));
/// ```
#[must_use]
pub fn extract_ssn_serial(ssn: &str) -> Option<String> {
    let digits = normalize_ssn(ssn);
    if digits.len() == 9 {
        Some(digits[5..9].to_string())
    } else {
        None
    }
}

// ============================================================================
// EIN Conversion
// ============================================================================

/// Normalize EIN to digits only
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(conversion::normalize_ein("12-3456789"), "123456789");
/// ```
#[must_use]
pub fn normalize_ein(ein: &str) -> String {
    masking::digits_only(ein)
}

/// Convert EIN to standard hyphenated format
///
/// Converts to XX-XXXXXXX format.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(conversion::to_ein_with_hyphen("123456789"), "12-3456789");
/// ```
#[must_use]
pub fn to_ein_with_hyphen(ein: &str) -> String {
    let digits = normalize_ein(ein);

    if digits.len() == 9 {
        format!("{}-{}", &digits[0..2], &digits[2..9])
    } else {
        ein.to_string()
    }
}

// ============================================================================
// VIN Conversion
// ============================================================================

/// Normalize VIN to uppercase
///
/// VINs should always be uppercase for consistency.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(
///     conversion::normalize_vin("1hgbh41jxmn109186"),
///     "1HGBH41JXMN109186"
/// );
/// ```
#[must_use]
pub fn normalize_vin(vin: &str) -> String {
    vin.to_uppercase()
}

/// Extract VIN World Manufacturer Identifier (first 3 characters)
///
/// The WMI identifies the manufacturer.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(
///     conversion::extract_vin_wmi("1HGBH41JXMN109186"),
///     Some("1HG".to_string())
/// );
/// ```
#[must_use]
pub fn extract_vin_wmi(vin: &str) -> Option<String> {
    let vin_upper = normalize_vin(vin);
    if vin_upper.len() >= 3 {
        Some(vin_upper[0..3].to_string())
    } else {
        None
    }
}

/// Extract VIN Vehicle Descriptor Section (characters 4-9)
///
/// The VDS describes vehicle attributes.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(
///     conversion::extract_vin_vds("1HGBH41JXMN109186"),
///     Some("BH41JX".to_string())
/// );
/// ```
#[must_use]
pub fn extract_vin_vds(vin: &str) -> Option<String> {
    let vin_upper = normalize_vin(vin);
    if vin_upper.len() >= 9 {
        Some(vin_upper[3..9].to_string())
    } else {
        None
    }
}

/// Extract VIN Vehicle Identifier Section (characters 10-17)
///
/// The VIS includes model year and serial number.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(
///     conversion::extract_vin_vis("1HGBH41JXMN109186"),
///     Some("MN109186".to_string())
/// );
/// ```
#[must_use]
pub fn extract_vin_vis(vin: &str) -> Option<String> {
    let vin_upper = normalize_vin(vin);
    if vin_upper.len() == 17 {
        Some(vin_upper[9..17].to_string())
    } else {
        None
    }
}

/// Extract VIN model year character (10th character)
///
/// Returns the model year code character.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(
///     conversion::extract_vin_model_year("1HGBH41JXMN109186"),
///     Some('M')
/// );
/// ```
#[must_use]
pub fn extract_vin_model_year(vin: &str) -> Option<char> {
    let vin_upper = normalize_vin(vin);
    if vin_upper.len() >= 10 {
        vin_upper.chars().nth(9)
    } else {
        None
    }
}

// ============================================================================
// Driver's License Conversion
// ============================================================================

/// Normalize driver's license to alphanumeric only
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(conversion::normalize_driver_license("A-123-4567"), "A1234567");
/// ```
#[must_use]
pub fn normalize_driver_license(license: &str) -> String {
    masking::alphanumeric_only(license)
}

// ============================================================================
// Display Formatting
// ============================================================================

/// Convert SSN to safe display format (masked with last 4)
///
/// Returns a display-safe version showing only last 4 digits.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(
///     conversion::to_ssn_display("123-45-6789"),
///     "***-**-6789"
/// );
/// ```
#[must_use]
pub fn to_ssn_display(ssn: &str) -> String {
    masking::mask_digits_preserve_format(ssn, 4, '*')
}

/// Convert VIN to display format with spaces
///
/// Adds spaces for readability: WMI VDS VIS
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::conversion;
///
/// assert_eq!(
///     conversion::to_vin_display("1HGBH41JXMN109186"),
///     "1HG BH41JX MN109186"
/// );
/// ```
#[must_use]
pub fn to_vin_display(vin: &str) -> String {
    let vin_upper = normalize_vin(vin);
    if vin_upper.len() == 17 {
        format!(
            "{} {} {}",
            &vin_upper[0..3],
            &vin_upper[3..9],
            &vin_upper[9..17]
        )
    } else {
        vin_upper
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== SSN Conversion Tests =====

    #[test]
    fn test_normalize_ssn() {
        assert_eq!(normalize_ssn("123-45-6789"), "123456789");
        assert_eq!(normalize_ssn("123 45 6789"), "123456789");
        assert_eq!(normalize_ssn("123456789"), "123456789");
        assert_eq!(normalize_ssn(""), "");
    }

    #[test]
    fn test_to_ssn_with_hyphens() {
        assert_eq!(to_ssn_with_hyphens("123456789"), "123-45-6789");
        assert_eq!(to_ssn_with_hyphens("123-45-6789"), "123-45-6789");
        assert_eq!(to_ssn_with_hyphens("123 45 6789"), "123-45-6789");
        assert_eq!(to_ssn_with_hyphens("short"), "short"); // Too short
    }

    #[test]
    fn test_to_ssn_with_spaces() {
        assert_eq!(to_ssn_with_spaces("123456789"), "123 45 6789");
        assert_eq!(to_ssn_with_spaces("123-45-6789"), "123 45 6789");
    }

    #[test]
    fn test_extract_ssn_parts() {
        assert_eq!(extract_ssn_area("123-45-6789"), Some("123".to_string()));
        assert_eq!(extract_ssn_group("123-45-6789"), Some("45".to_string()));
        assert_eq!(extract_ssn_serial("123-45-6789"), Some("6789".to_string()));

        // Edge cases
        assert_eq!(extract_ssn_area("12"), None);
        assert_eq!(extract_ssn_group("1234"), None);
        assert_eq!(extract_ssn_serial("12345678"), None);
    }

    // ===== EIN Conversion Tests =====

    #[test]
    fn test_normalize_ein() {
        assert_eq!(normalize_ein("12-3456789"), "123456789");
        assert_eq!(normalize_ein("123456789"), "123456789");
    }

    #[test]
    fn test_to_ein_with_hyphen() {
        assert_eq!(to_ein_with_hyphen("123456789"), "12-3456789");
        assert_eq!(to_ein_with_hyphen("12-3456789"), "12-3456789");
        assert_eq!(to_ein_with_hyphen("short"), "short");
    }

    // ===== VIN Conversion Tests =====

    #[test]
    fn test_normalize_vin() {
        assert_eq!(normalize_vin("1hgbh41jxmn109186"), "1HGBH41JXMN109186");
        assert_eq!(normalize_vin("1HGBH41JXMN109186"), "1HGBH41JXMN109186");
    }

    #[test]
    fn test_extract_vin_parts() {
        let vin = "1HGBH41JXMN109186";
        assert_eq!(extract_vin_wmi(vin), Some("1HG".to_string()));
        assert_eq!(extract_vin_vds(vin), Some("BH41JX".to_string()));
        assert_eq!(extract_vin_vis(vin), Some("MN109186".to_string()));
        assert_eq!(extract_vin_model_year(vin), Some('M'));

        // Edge cases
        assert_eq!(extract_vin_wmi("AB"), None);
        assert_eq!(extract_vin_vis("short"), None);
    }

    // ===== Driver's License Conversion Tests =====

    #[test]
    fn test_normalize_driver_license() {
        assert_eq!(normalize_driver_license("A-123-4567"), "A1234567");
        assert_eq!(normalize_driver_license("A 123 4567"), "A1234567");
    }

    // ===== Display Formatting Tests =====

    #[test]
    fn test_to_ssn_display() {
        assert_eq!(to_ssn_display("123-45-6789"), "***-**-6789");
        assert_eq!(to_ssn_display("123 45 6789"), "*** ** 6789");
    }

    #[test]
    fn test_to_vin_display() {
        assert_eq!(to_vin_display("1HGBH41JXMN109186"), "1HG BH41JX MN109186");
        assert_eq!(to_vin_display("short"), "SHORT"); // Normalized but not formatted
    }

    // ===== Edge Cases =====

    #[test]
    fn test_empty_input() {
        assert_eq!(normalize_ssn(""), "");
        assert_eq!(normalize_ein(""), "");
        assert_eq!(normalize_vin(""), "");
        assert_eq!(normalize_driver_license(""), "");
    }
}

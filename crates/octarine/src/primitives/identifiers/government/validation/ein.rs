//! Employer Identification Number (EIN) validation
//!
//! Pure validation functions for IRS Employer Identification Numbers.
//!
//! # EIN Format
//!
//! EINs have format: XX-XXXXXXX (9 digits with dash after 2nd)
//!
//! # IRS Campus Codes
//!
//! EIN prefixes correspond to IRS campus locations:
//! - 01-06, 10-16: Brookhaven
//! - 20-27: Austin
//! - 30-39: Cincinnati (former campus)
//! - 40-48: Kansas City (former campus)
//! - 50-59: Fresno
//! - 60-68: Ogden
//! - 70-79: Atlanta (former campus)
//! - 80-88: Philadelphia
//! - 90-99: Internet/Online EINs (since 2001)
//!
//! Invalid prefixes: 00, 07-09, 17-19, 28-29, 69, 89

use crate::primitives::Problem;

// ============================================================================
// EIN Validation
// ============================================================================

/// Check if an EIN prefix (first 2 digits) is a valid IRS campus code
///
/// EIN prefixes correspond to IRS campus locations:
/// - 01-06, 10-16: Brookhaven
/// - 20-27: Austin
/// - 30-39: Cincinnati (former campus)
/// - 40-48: Kansas City (former campus)
/// - 50-59: Fresno
/// - 60-68: Ogden
/// - 70-79: Atlanta (former campus)
/// - 80-88: Philadelphia
/// - 90-99: Internet/Online EINs (since 2001)
///
/// Invalid prefixes: 00, 07-09, 17-19, 28-29, 69, 89
#[must_use]
pub fn is_valid_ein_prefix(prefix: u8) -> bool {
    matches!(
        prefix,
        1..=6       // Brookhaven
        | 10..=16   // Brookhaven
        | 20..=27   // Austin
        | 30..=39   // Cincinnati
        | 40..=48   // Kansas City
        | 50..=59   // Fresno
        | 60..=68   // Ogden
        | 70..=79   // Atlanta
        | 80..=88   // Philadelphia
        | 90..=99   // Internet
    )
}

/// Validate EIN format
///
/// Employer Identification Numbers have format: XX-XXXXXXX
/// Validates both format and IRS campus code prefix.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::validate_ein("12-3456789").is_ok());
/// assert!(validation::validate_ein("00-0000001").is_err()); // Invalid prefix
/// assert!(validation::validate_ein("07-1234567").is_err()); // Invalid prefix
/// ```
pub fn validate_ein(ein: &str) -> Result<(), Problem> {
    // EIN format: XX-XXXXXXX (9 digits with dash after 2nd)
    let cleaned: String = ein.chars().filter(|c| c.is_numeric()).collect();

    if cleaned.len() != 9 {
        return Err(Problem::Validation("EIN must be 9 digits".into()));
    }

    // EIN must have the dash in the correct position
    if !ein.contains('-') {
        return Err(Problem::Validation("EIN format must be XX-XXXXXXX".into()));
    }

    let parts: Vec<&str> = ein.split('-').collect();
    let valid_format = parts.len() == 2
        && parts.first().is_some_and(|p| p.len() == 2)
        && parts.get(1).is_some_and(|p| p.len() == 7);
    if !valid_format {
        return Err(Problem::Validation("EIN format must be XX-XXXXXXX".into()));
    }

    // Validate IRS campus code prefix
    let prefix: u8 = cleaned[0..2]
        .parse()
        .map_err(|_| Problem::Validation("Invalid EIN prefix".into()))?;

    if !is_valid_ein_prefix(prefix) {
        return Err(Problem::Validation(format!(
            "Invalid EIN campus code prefix: {:02}",
            prefix
        )));
    }

    Ok(())
}

/// Check if an EIN is a known test/sample EIN
///
/// Test EINs are commonly used in documentation and testing.
/// These should not be treated as real employer identifiers.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::is_test_ein("12-3456789"));
/// assert!(validation::is_test_ein("00-0000000"));
/// assert!(!validation::is_test_ein("46-1234567")); // Real format
/// ```
#[must_use]
pub fn is_test_ein(ein: &str) -> bool {
    let cleaned = ein.replace(['-', ' '], "");

    // Must be 9 digits
    if cleaned.len() != 9 || !cleaned.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    // Well-known test EINs
    let test_eins = [
        "000000000", // All zeros
        "123456789", // Sequential
        "111111111", // All ones
        "999999999", // All nines
        "121234567", // Example in many docs (12-3456789)
        "000000001", // Placeholder
        "012345678", // Sequential from 0
    ];

    if test_eins.contains(&cleaned.as_str()) {
        return true;
    }

    // Check for repetitive patterns (all same digit)
    if cleaned
        .chars()
        .all(|c| c == cleaned.chars().next().unwrap_or('0'))
    {
        return true;
    }

    // Check for simple sequential patterns
    if cleaned == "246813579" || cleaned == "135792468" {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_ein_validation() {
        // Valid EINs with valid campus codes
        assert!(validate_ein("12-3456789").is_ok()); // Brookhaven
        assert!(validate_ein("20-1234567").is_ok()); // Austin
        assert!(validate_ein("95-1234567").is_ok()); // Internet

        // Invalid formats
        assert!(validate_ein("123456789").is_err()); // Missing dash format
        assert!(validate_ein("1-23456789").is_err()); // Wrong dash position
    }

    #[test]
    fn test_ein_campus_code_validation() {
        // Valid campus codes
        assert!(validate_ein("01-0000001").is_ok()); // Brookhaven
        assert!(validate_ein("06-0000001").is_ok()); // Brookhaven
        assert!(validate_ein("10-0000001").is_ok()); // Brookhaven
        assert!(validate_ein("16-0000001").is_ok()); // Brookhaven
        assert!(validate_ein("20-0000001").is_ok()); // Austin
        assert!(validate_ein("27-0000001").is_ok()); // Austin
        assert!(validate_ein("30-0000001").is_ok()); // Cincinnati
        assert!(validate_ein("50-0000001").is_ok()); // Fresno
        assert!(validate_ein("60-0000001").is_ok()); // Ogden
        assert!(validate_ein("70-0000001").is_ok()); // Atlanta
        assert!(validate_ein("80-0000001").is_ok()); // Philadelphia
        assert!(validate_ein("90-0000001").is_ok()); // Internet
        assert!(validate_ein("99-0000001").is_ok()); // Internet

        // Invalid campus codes
        assert!(validate_ein("00-0000001").is_err()); // Invalid
        assert!(validate_ein("07-0000001").is_err()); // Invalid (gap after 06)
        assert!(validate_ein("08-0000001").is_err()); // Invalid
        assert!(validate_ein("09-0000001").is_err()); // Invalid
        assert!(validate_ein("17-0000001").is_err()); // Invalid (gap after 16)
        assert!(validate_ein("18-0000001").is_err()); // Invalid
        assert!(validate_ein("19-0000001").is_err()); // Invalid
        assert!(validate_ein("28-0000001").is_err()); // Invalid (gap after 27)
        assert!(validate_ein("29-0000001").is_err()); // Invalid
        assert!(validate_ein("69-0000001").is_err()); // Invalid (gap after 68)
        assert!(validate_ein("89-0000001").is_err()); // Invalid (gap after 88)
    }

    #[test]
    fn test_ein_prefix_helper() {
        // Test the prefix helper directly
        assert!(is_valid_ein_prefix(1));
        assert!(is_valid_ein_prefix(12));
        assert!(is_valid_ein_prefix(99));
        assert!(!is_valid_ein_prefix(0));
        assert!(!is_valid_ein_prefix(7));
        assert!(!is_valid_ein_prefix(69));
    }

    #[test]
    fn test_empty_input() {
        assert!(validate_ein("").is_err());
    }

    #[test]
    fn test_ein_edge_cases() {
        // Empty and whitespace
        assert!(validate_ein("").is_err());
        assert!(validate_ein("   ").is_err());

        // Unicode dashes
        assert!(validate_ein("12\u{2013}3456789").is_err()); // En dash
        assert!(validate_ein("12\u{2014}3456789").is_err()); // Em dash

        // Null bytes
        assert!(validate_ein("12-345\x006789").is_err());
    }

    #[test]
    fn test_is_test_ein() {
        // Known test EINs
        assert!(is_test_ein("12-3456789"));
        assert!(is_test_ein("00-0000000"));
        assert!(is_test_ein("11-1111111"));
        assert!(is_test_ein("99-9999999"));

        // Real-looking EINs (not test patterns)
        assert!(!is_test_ein("46-1234567"));
        assert!(!is_test_ein("83-0512345"));

        // Invalid format (not 9 digits)
        assert!(!is_test_ein("12-345"));
    }
}

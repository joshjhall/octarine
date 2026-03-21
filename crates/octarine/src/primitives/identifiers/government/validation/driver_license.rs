//! Driver's License validation
//!
//! Pure validation functions for US state driver's licenses.
//!
//! # State-Specific Formats
//!
//! Each US state has different driver's license formats:
//! - **California**: 1 letter + 7 digits
//! - **Texas**: 8 digits
//! - **New York**: 8-9 characters
//! - **Florida**: 13 characters (1 letter + 12 digits)

use crate::primitives::Problem;

// ============================================================================
// Driver's License Validation
// ============================================================================

/// Validate driver's license format for a specific state
///
/// Each state has different DL formats. This validates basic format constraints
/// and returns detailed error messages.
///
/// # Arguments
///
/// * `license` - The license number
/// * `state` - Two-letter state code (e.g., "CA", "TX")
///
/// # Returns
///
/// * `Ok(())` - If the license format is valid for the specified state
/// * `Err(Problem)` - If the format is invalid with details
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// // California: 1 letter + 7 digits
/// assert!(validation::validate_driver_license("A1234567", "CA").is_ok());
///
/// // Texas: 8 digits
/// assert!(validation::validate_driver_license("12345678", "TX").is_ok());
///
/// // Invalid format
/// assert!(validation::validate_driver_license("invalid", "CA").is_err());
/// ```
pub fn validate_driver_license(license: &str, state: &str) -> Result<(), Problem> {
    let state_upper = state.to_uppercase();

    match state_upper.as_str() {
        "CA" => {
            // California: 1 letter + 7 digits
            if license.len() != 8 {
                return Err(Problem::Validation(
                    "California driver's license must be 8 characters (1 letter + 7 digits)".into(),
                ));
            }
            if !license
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
            {
                return Err(Problem::Validation(
                    "California driver's license must start with a letter".into(),
                ));
            }
            if !license.chars().skip(1).all(|c| c.is_ascii_digit()) {
                return Err(Problem::Validation(
                    "California driver's license must have 7 digits after the first letter".into(),
                ));
            }
            Ok(())
        }
        "TX" => {
            // Texas: 8 digits
            if license.len() != 8 {
                return Err(Problem::Validation(
                    "Texas driver's license must be 8 digits".into(),
                ));
            }
            if !license.chars().all(|c| c.is_ascii_digit()) {
                return Err(Problem::Validation(
                    "Texas driver's license must contain only digits".into(),
                ));
            }
            Ok(())
        }
        "NY" => {
            // New York: Various formats, commonly 9 digits or letter + digits
            if license.len() < 8 || license.len() > 9 {
                return Err(Problem::Validation(
                    "New York driver's license must be 8-9 characters".into(),
                ));
            }
            Ok(())
        }
        "FL" => {
            // Florida: 13 characters (letter + 12 digits)
            if license.len() != 13 {
                return Err(Problem::Validation(
                    "Florida driver's license must be 13 characters (1 letter + 12 digits)".into(),
                ));
            }
            if !license
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
            {
                return Err(Problem::Validation(
                    "Florida driver's license must start with a letter".into(),
                ));
            }
            Ok(())
        }
        _ => {
            // Generic validation: 6-13 alphanumeric characters
            if license.len() < 6 || license.len() > 13 {
                return Err(Problem::Validation(
                    "Driver's license must be 6-13 characters".into(),
                ));
            }
            if !license.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err(Problem::Validation(
                    "Driver's license must contain only alphanumeric characters".into(),
                ));
            }
            Ok(())
        }
    }
}

/// Check if a driver's license number appears to be a test pattern
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::is_test_driver_license("A0000000"));
/// assert!(validation::is_test_driver_license("TEST1234"));
/// assert!(!validation::is_test_driver_license("D1234567"));
/// ```
#[must_use]
pub fn is_test_driver_license(license: &str) -> bool {
    let license_upper = license.to_uppercase().replace([' ', '-'], "");

    // Common test patterns
    if license_upper.starts_with("TEST")
        || license_upper.starts_with("DEMO")
        || license_upper.starts_with("SAMPLE")
        || license_upper.starts_with("FAKE")
    {
        return true;
    }

    // All zeros after letter
    if license_upper.len() >= 2
        && license_upper
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        && license_upper.chars().skip(1).all(|c| c == '0')
    {
        return true;
    }

    // Sequential patterns
    if license_upper.contains("12345678") || license_upper.contains("87654321") {
        return true;
    }

    // All same digit
    let digits: String = license_upper
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    if digits.len() >= 4
        && digits
            .chars()
            .all(|c| c == digits.chars().next().unwrap_or('0'))
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_driver_license_validation() {
        // California
        assert!(validate_driver_license("A1234567", "CA").is_ok());
        assert!(validate_driver_license("12345678", "CA").is_err()); // No letter

        // Texas
        assert!(validate_driver_license("12345678", "TX").is_ok());
        assert!(validate_driver_license("A1234567", "TX").is_err()); // Has letter
    }

    #[test]
    fn test_validate_driver_license_success() {
        // Valid California license
        assert!(validate_driver_license("A1234567", "CA").is_ok());

        // Valid Texas license
        assert!(validate_driver_license("12345678", "TX").is_ok());

        // Valid New York license
        assert!(validate_driver_license("123456789", "NY").is_ok());

        // Valid Florida license
        assert!(validate_driver_license("A123456789012", "FL").is_ok());
    }

    #[test]
    fn test_validate_driver_license_errors() {
        // California: wrong length
        let result = validate_driver_license("A123", "CA");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("8 characters")
        );

        // California: no letter at start
        let result = validate_driver_license("12345678", "CA");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("start with a letter")
        );

        // Texas: contains non-digits
        let result = validate_driver_license("A1234567", "TX");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("only digits")
        );

        // Florida: wrong length
        let result = validate_driver_license("A123", "FL");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("13 characters")
        );

        // Generic: too short
        let result = validate_driver_license("ABC", "XX");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("6-13 characters")
        );

        // Generic: special characters
        let result = validate_driver_license("ABC-123", "XX");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("alphanumeric")
        );
    }

    #[test]
    fn test_driver_license_edge_cases() {
        // Empty
        assert!(validate_driver_license("", "CA").is_err());

        // Very long
        let long = "A".repeat(1000);
        assert!(validate_driver_license(&long, "CA").is_err());

        // Null bytes
        assert!(validate_driver_license("A1234\x00567", "CA").is_err());
    }

    #[test]
    fn test_is_test_driver_license() {
        // Test patterns
        assert!(is_test_driver_license("TEST1234"));
        assert!(is_test_driver_license("DEMO5678"));
        assert!(is_test_driver_license("A0000000"));
        assert!(is_test_driver_license("B12345678"));

        // All same digit
        assert!(is_test_driver_license("A1111111"));

        // Real-looking licenses (not test patterns)
        assert!(!is_test_driver_license("D1234567"));
        assert!(!is_test_driver_license("B9876543"));
        assert!(!is_test_driver_license("X5839201"));
    }
}

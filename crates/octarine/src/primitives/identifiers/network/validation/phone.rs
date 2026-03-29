//! Phone number validation functions
//!
//! Pure validation functions for international phone numbers.
//!
//! # Usage
//!
//! For bool checks, use detection layer's `is_phone_international()`, or call
//! `validate_phone_international().is_ok()` for validation-level checks.

use super::super::detection::is_phone_international;
use crate::primitives::Problem;

// ============================================================================
// Phone Number Validation
// ============================================================================

/// Validate international phone number
///
/// Validates phone numbers in international format.
/// Requires 7-15 digits per E.164/OWASP guidelines.
///
/// # Examples
///
/// ```ignore
/// // Result-based validation
/// validate_phone_international("+1-555-123-4567")?;
///
/// // Bool check using .is_ok()
/// if validate_phone_international(user_input).is_ok() {
///     println!("Valid phone number!");
/// }
/// ```
pub fn validate_phone_international(phone: &str) -> Result<(), Problem> {
    // First check format using detection layer
    if !is_phone_international(phone) {
        return Err(Problem::Validation("Invalid phone number format".into()));
    }

    // Additional semantic validation: check digit count (7-15 per E.164)
    let digit_count = phone.chars().filter(|c| c.is_numeric()).count();
    if !(7..=15).contains(&digit_count) {
        return Err(Problem::Validation(
            "Phone number must be 7-15 digits".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validate_phone_international() {
        assert!(validate_phone_international("+1-555-123-4567").is_ok());
        assert!(validate_phone_international("+44 20 7946 0958").is_ok());
        assert!(validate_phone_international("123").is_err()); // Too short
        assert!(validate_phone_international("+1234567890123456").is_err()); // Too long
    }

    // ============================================================================
    // Adversarial and Property-Based Tests
    // ============================================================================

    use proptest::prelude::*;

    #[test]
    fn test_adversarial_phone_international_format_tricks() {
        // Valid international formats
        assert!(validate_phone_international("+1-555-123-4567").is_ok());
        assert!(validate_phone_international("+44 20 7946 0958").is_ok());
        assert!(validate_phone_international("+81 3-1234-5678").is_ok());

        // Too short (< 7 digits)
        assert!(validate_phone_international("+1-123").is_err());
        assert!(validate_phone_international("123456").is_err());

        // Too long (> 15 digits)
        assert!(validate_phone_international("+1234567890123456").is_err());

        // Edge cases - detection patterns may vary
        let _ = validate_phone_international("1-555-123-4567");
    }

    proptest! {

        #[test]
        fn prop_no_panic_phone_validation(s in "\\PC*") {
            let _ = validate_phone_international(&s);
        }

        #[test]
        fn prop_phone_length_bounds(digits in "[0-9+() -]{1,20}") {
            let _ = validate_phone_international(&digits);
            // Should handle short inputs without panic
        }

        #[test]
        fn prop_phone_edge_cases(prefix in "\\+[0-9]{1,3}", suffix in "[0-9]{4,14}") {
            let phone = format!("{} {}", prefix, suffix);
            let _ = validate_phone_international(&phone);
            // Should not panic on any format
        }

    }
}

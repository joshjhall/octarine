//! Phone number validation functions
//!
//! Validates phone numbers according to E.164 international format.

use super::super::super::types::PhoneRegion;
use crate::primitives::Problem;

use super::super::detection;

// Re-export find_phone_region from detection module for convenience
pub use super::super::detection::find_phone_region;

// ============================================================================
// Phone Validation
// ============================================================================

/// Validate phone number format (returns Result with region)
///
/// Validates phone numbers according to E.164 international format
/// and returns the detected region.
/// Requires 7-15 digits, no special characters except leading +
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::validation;
///
/// let region = validation::validate_phone("+14155552671")?;
/// assert_eq!(region, PhoneRegion::NorthAmerica);
///
/// let region = validation::validate_phone("14155552671")?;
/// assert_eq!(region, PhoneRegion::Unknown); // No country code
///
/// assert!(validation::validate_phone("123").is_err()); // Too short
/// ```
///
/// # Errors
///
/// Returns `Problem::validation` if:
/// - Phone has fewer than 7 or more than 15 digits
/// - Phone starts with 0 (invalid for E.164)
/// - Phone has invalid format after cleaning
pub fn validate_phone(phone: &str) -> Result<PhoneRegion, Problem> {
    // Use detection first to check format (now handles 7-15 digits, E.164 standard)
    if !detection::is_phone_number(phone) {
        return Err(Problem::Validation("Invalid phone number format".into()));
    }

    // Detect and return region
    let region = find_phone_region(phone)
        .ok_or_else(|| Problem::Validation("Unable to detect phone region".into()))?;

    Ok(region)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_phone_validation() {
        // Valid formats
        assert!(validate_phone("+14155552671").is_ok());
        assert!(validate_phone("14155552671").is_ok());
        assert!(validate_phone("+442071234567").is_ok());

        // Too short (less than 7 digits)
        assert!(validate_phone("+141555").is_err()); // 6 digits
        assert!(validate_phone("123456").is_err()); // 6 digits

        // Too long (more than 15 digits)
        assert!(validate_phone("+12345678901234567").is_err());

        // Invalid format
        assert!(validate_phone("invalid").is_err());
        assert!(validate_phone("").is_err());
    }

    #[test]
    fn test_phone_validation_errors() {
        let err = validate_phone("123").expect_err("should fail for short phone");
        assert!(err.to_string().contains("Invalid phone number format"));

        let err = validate_phone("").expect_err("should fail for empty phone");
        assert!(err.to_string().contains("Invalid phone number format"));
    }

    #[test]
    fn test_phone_edge_cases() {
        // Empty and whitespace
        assert!(validate_phone("").is_err());
        assert!(validate_phone("   ").is_err());

        // Starting with 0 (invalid for E.164)
        assert!(validate_phone("0123456789").is_err());

        // Exactly at boundaries
        assert!(validate_phone("1234567").is_ok()); // 7 digits - minimum
        assert!(validate_phone("123456789012345").is_ok()); // 15 digits - maximum
        assert!(validate_phone("1234567890123456").is_err()); // 16 digits - too long

        // With various separators
        assert!(validate_phone("123-456-7890").is_ok());
        assert!(validate_phone("(123) 456-7890").is_ok());
        assert!(validate_phone("123.456.7890").is_ok());
    }

    #[test]
    fn test_find_phone_region() {
        // North America (+1)
        assert_eq!(
            find_phone_region("+14155552671"),
            Some(PhoneRegion::NorthAmerica)
        );
        assert_eq!(
            find_phone_region("+1-555-123-4567"),
            Some(PhoneRegion::NorthAmerica)
        );

        // UK (+44)
        assert_eq!(find_phone_region("+442071234567"), Some(PhoneRegion::Uk));

        // Germany (+49)
        assert_eq!(find_phone_region("+4930123456"), Some(PhoneRegion::Germany));

        // France (+33)
        assert_eq!(find_phone_region("+33123456789"), Some(PhoneRegion::France));

        // Spain (+34)
        assert_eq!(find_phone_region("+34912345678"), Some(PhoneRegion::Spain));

        // Italy (+39)
        assert_eq!(find_phone_region("+390612345678"), Some(PhoneRegion::Italy));

        // Australia (+61)
        assert_eq!(
            find_phone_region("+61212345678"),
            Some(PhoneRegion::Australia)
        );

        // Japan (+81)
        assert_eq!(find_phone_region("+81312345678"), Some(PhoneRegion::Japan));

        // China (+86)
        assert_eq!(
            find_phone_region("+8613812345678"),
            Some(PhoneRegion::China)
        );

        // India (+91)
        assert_eq!(find_phone_region("+919876543210"), Some(PhoneRegion::India));

        // Brazil (+55)
        assert_eq!(
            find_phone_region("+5511987654321"),
            Some(PhoneRegion::Brazil)
        );

        // Russia (+7)
        assert_eq!(find_phone_region("+74951234567"), Some(PhoneRegion::Russia));

        // Unknown - no country code
        assert_eq!(find_phone_region("4155552671"), Some(PhoneRegion::Unknown));
        assert_eq!(
            find_phone_region("555-123-4567"),
            Some(PhoneRegion::Unknown)
        );

        // Unknown - unrecognized country code
        assert_eq!(
            find_phone_region("+99912345678"),
            Some(PhoneRegion::Unknown)
        );
    }

    #[test]
    fn test_validate_phone_returns_region() {
        // Valid phone with North America region
        let region = validate_phone("+14155552671").expect("should validate");
        assert_eq!(region, PhoneRegion::NorthAmerica);

        // Valid phone with UK region
        let region = validate_phone("+442071234567").expect("should validate");
        assert_eq!(region, PhoneRegion::Uk);

        // Valid phone without country code (Unknown region)
        let region = validate_phone("14155552671").expect("should validate");
        assert_eq!(region, PhoneRegion::Unknown);

        // Invalid phone should still fail
        assert!(validate_phone("123").is_err()); // Too short
    }

    #[test]
    fn test_phone_region_display() {
        assert_eq!(PhoneRegion::NorthAmerica.to_string(), "North America (+1)");
        assert_eq!(PhoneRegion::Uk.to_string(), "United Kingdom (+44)");
        assert_eq!(PhoneRegion::Germany.to_string(), "Germany (+49)");
        assert_eq!(PhoneRegion::France.to_string(), "France (+33)");
        assert_eq!(PhoneRegion::Unknown.to_string(), "Unknown region");
    }
}

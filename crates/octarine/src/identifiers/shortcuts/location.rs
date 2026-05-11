//! Location identifier shortcuts (GPS, street address, postal code).
//!
//! Convenience functions over [`LocationBuilder`](super::super::LocationBuilder).

use crate::observe::Problem;

use super::super::LocationBuilder;
use super::super::types::{GpsFormat, IdentifierMatch, LocationTextPolicy, PostalCodeType};

/// Check if value is a GPS coordinate
#[must_use]
pub fn is_gps_coordinate(value: &str) -> bool {
    LocationBuilder::new().is_gps_coordinate(value)
}

/// Validate a GPS coordinate and detect its format
pub fn validate_gps_coordinate(coordinate: &str) -> Result<GpsFormat, Problem> {
    LocationBuilder::new().validate_gps_coordinate(coordinate)
}

/// Check if value is a street address
#[must_use]
pub fn is_street_address(value: &str) -> bool {
    LocationBuilder::new().is_street_address(value)
}

/// Check if value is a postal code
#[must_use]
pub fn is_postal_code(value: &str) -> bool {
    LocationBuilder::new().is_postal_code(value)
}

/// Check if value is a German postal code (5 digits)
#[must_use]
pub fn is_german_postal_code(value: &str) -> bool {
    LocationBuilder::new().is_german_postal_code(value)
}

/// Check if value is a French postal code (5 digits, dept 01-98)
#[must_use]
pub fn is_french_postal_code(value: &str) -> bool {
    LocationBuilder::new().is_french_postal_code(value)
}

/// Check if value is an Australian postal code (4 digits, 0200-9999)
#[must_use]
pub fn is_australian_postal_code(value: &str) -> bool {
    LocationBuilder::new().is_australian_postal_code(value)
}

/// Check if value is a Japanese postal code (NNN-NNNN)
#[must_use]
pub fn is_japanese_postal_code(value: &str) -> bool {
    LocationBuilder::new().is_japanese_postal_code(value)
}

/// Check if value is an Indian PIN code (6 digits, first digit 1-8)
#[must_use]
pub fn is_indian_postal_code(value: &str) -> bool {
    LocationBuilder::new().is_indian_postal_code(value)
}

/// Check if value is a Dutch postal code (NNNN AA)
#[must_use]
pub fn is_dutch_postal_code(value: &str) -> bool {
    LocationBuilder::new().is_dutch_postal_code(value)
}

/// Check if value is a Brazilian CEP (NNNNN-NNN)
#[must_use]
pub fn is_brazilian_postal_code(value: &str) -> bool {
    LocationBuilder::new().is_brazilian_postal_code(value)
}

/// Validate a postal code and detect its type
pub fn validate_postal_code(postal_code: &str) -> Result<PostalCodeType, Problem> {
    LocationBuilder::new().validate_postal_code(postal_code)
}

/// Find all location identifiers in text
#[must_use]
pub fn find_locations(text: &str) -> Vec<IdentifierMatch> {
    LocationBuilder::new().find_all_in_text(text)
}

/// Redact all location identifiers in text
#[must_use]
pub fn redact_locations(text: &str) -> String {
    LocationBuilder::new().redact_all_in_text_with_strategy(text, LocationTextPolicy::Complete)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_gps_coordinate_shortcut() {
        assert!(is_gps_coordinate("40.7128, -74.0060"));
        assert!(!is_gps_coordinate("not-a-coordinate"));
    }

    #[test]
    fn test_validate_gps_coordinate_shortcut() {
        assert!(validate_gps_coordinate("40.7128, -74.0060").is_ok());
        assert!(validate_gps_coordinate("not-a-coordinate").is_err());
    }

    #[test]
    fn test_street_address_shortcut() {
        assert!(is_street_address("123 Main Street"));
        assert!(!is_street_address("hello"));
    }

    #[test]
    fn test_postal_code_shortcut() {
        assert!(is_postal_code("90210"));
        assert!(!is_postal_code("abc"));
    }

    #[test]
    fn test_validate_postal_code_shortcut() {
        assert!(validate_postal_code("90210").is_ok());
        assert!(validate_postal_code("abc").is_err());
    }

    #[test]
    fn test_international_postal_shortcuts() {
        // Each country shortcut should return true for a canonical example
        // and false for an obvious non-match.
        assert!(is_german_postal_code("10115"));
        assert!(!is_german_postal_code("abcde"));

        assert!(is_french_postal_code("75001"));
        assert!(!is_french_postal_code("99000"));

        assert!(is_australian_postal_code("2000"));
        assert!(!is_australian_postal_code("0100"));

        assert!(is_japanese_postal_code("100-0001"));
        assert!(!is_japanese_postal_code("1000001"));

        assert!(is_indian_postal_code("110001"));
        assert!(!is_indian_postal_code("010001"));

        assert!(is_dutch_postal_code("1011 AB"));
        assert!(!is_dutch_postal_code("0123 AB"));

        assert!(is_brazilian_postal_code("01001-000"));
        assert!(!is_brazilian_postal_code("01001000"));
    }
}

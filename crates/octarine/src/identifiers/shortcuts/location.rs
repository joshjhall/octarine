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
}

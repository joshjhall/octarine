//! Detection method implementations for LocationIdentifierBuilder
//!
//! Implements detection methods that delegate to the detection module.

use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::super::detection;

use super::LocationIdentifierBuilder;

impl LocationIdentifierBuilder {
    // =========================================================================
    // Detection Methods
    // =========================================================================

    /// Detect location identifier type from input string
    ///
    /// Returns the type of location identifier detected, or None if not recognized.
    #[must_use]
    pub fn detect(&self, value: &str) -> Option<IdentifierType> {
        detection::detect_location_identifier(value)
    }

    /// Check if value is a location identifier
    #[must_use]
    pub fn is_location_identifier(&self, value: &str) -> bool {
        detection::is_location_identifier(value)
    }

    /// Check if value is a GPS coordinate
    #[must_use]
    pub fn is_gps_coordinate(&self, value: &str) -> bool {
        detection::is_gps_coordinate(value)
    }

    /// Check if value is a street address
    #[must_use]
    pub fn is_street_address(&self, value: &str) -> bool {
        detection::is_street_address(value)
    }

    /// Check if value is a postal code
    #[must_use]
    pub fn is_postal_code(&self, value: &str) -> bool {
        detection::is_postal_code(value)
    }

    /// Find all GPS coordinates in text
    #[must_use]
    pub fn find_gps_coordinates_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_gps_coordinates_in_text(text)
    }

    /// Find all street addresses in text
    #[must_use]
    pub fn find_addresses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_addresses_in_text(text)
    }

    /// Find all postal codes in text
    #[must_use]
    pub fn find_postal_codes_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_postal_codes_in_text(text)
    }

    /// Find all location identifiers in text
    #[must_use]
    pub fn find_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_all_locations_in_text(text)
    }

    // =========================================================================
    // Test Data Detection Methods
    // =========================================================================

    /// Check if GPS coordinate is likely test/dummy data
    ///
    /// Detects common test patterns like Null Island (0,0), simple patterns (1,1),
    /// extreme values (90,180), and repeated digits (11.1111, 22.2222).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let builder = LocationIdentifierBuilder::new();
    ///
    /// // Test patterns
    /// assert!(builder.is_test_gps_coordinate("0, 0"));
    /// assert!(builder.is_test_gps_coordinate("1, 1"));
    ///
    /// // Real coordinates
    /// assert!(!builder.is_test_gps_coordinate("40.7128, -74.0060")); // NYC
    /// ```
    #[must_use]
    pub fn is_test_gps_coordinate(&self, coordinate: &str) -> bool {
        detection::is_test_gps_coordinate(coordinate)
    }

    /// Check if postal code is likely test/dummy data
    ///
    /// Detects common test patterns like all zeros (00000), all nines (99999),
    /// sequential (12345), repeated (11111), and TEST/DUMMY keywords.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let builder = LocationIdentifierBuilder::new();
    ///
    /// // Test patterns
    /// assert!(builder.is_test_postal_code("00000"));
    /// assert!(builder.is_test_postal_code("99999"));
    ///
    /// // Real postal codes
    /// assert!(!builder.is_test_postal_code("10001")); // NYC
    /// ```
    #[must_use]
    pub fn is_test_postal_code(&self, postal_code: &str) -> bool {
        detection::is_test_postal_code(postal_code)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_detection_methods() {
        let builder = LocationIdentifierBuilder::new();

        // GPS
        assert!(builder.is_gps_coordinate("40.7128, -74.0060"));
        assert!(!builder.is_gps_coordinate("invalid"));

        // Address
        assert!(builder.is_street_address("123 Main Street"));
        assert!(!builder.is_street_address("invalid"));

        // Postal code
        assert!(builder.is_postal_code("10001"));
        assert!(!builder.is_postal_code("invalid"));

        // Generic
        assert!(builder.is_location_identifier("40.7128, -74.0060"));
        assert!(builder.is_location_identifier("10001"));
    }

    #[test]
    fn test_find_in_text_methods() {
        let builder = LocationIdentifierBuilder::new();

        let text = "Ship to: 123 Main Street, ZIP: 10001, Coordinates: 40.7128, -74.0060";

        let addresses = builder.find_addresses_in_text(text);
        assert!(!addresses.is_empty());

        let postal = builder.find_postal_codes_in_text(text);
        assert!(!postal.is_empty());

        let coords = builder.find_gps_coordinates_in_text(text);
        assert!(!coords.is_empty());

        let all = builder.find_all_in_text(text);
        assert!(all.len() >= 3);
    }

    #[test]
    fn test_is_test_gps_coordinate() {
        let builder = LocationIdentifierBuilder::new();

        // Test patterns
        assert!(builder.is_test_gps_coordinate("0, 0")); // Null Island
        assert!(builder.is_test_gps_coordinate("1, 1"));
        assert!(builder.is_test_gps_coordinate("90, 180"));
        assert!(builder.is_test_gps_coordinate("11.1111, 22.2222"));

        // Real coordinates
        assert!(!builder.is_test_gps_coordinate("40.7128, -74.0060")); // NYC
        assert!(!builder.is_test_gps_coordinate("51.5074, -0.1278")); // London
    }

    #[test]
    fn test_is_test_postal_code() {
        let builder = LocationIdentifierBuilder::new();

        // Test patterns
        assert!(builder.is_test_postal_code("00000"));
        assert!(builder.is_test_postal_code("99999"));
        assert!(builder.is_test_postal_code("12345"));
        assert!(builder.is_test_postal_code("11111"));
        assert!(builder.is_test_postal_code("TEST"));

        // Real postal codes
        assert!(!builder.is_test_postal_code("10001")); // NYC
        assert!(!builder.is_test_postal_code("90210")); // Beverly Hills
    }
}

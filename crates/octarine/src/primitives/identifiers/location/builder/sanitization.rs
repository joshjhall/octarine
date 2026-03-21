//! Sanitization method implementations for LocationIdentifierBuilder
//!
//! Implements sanitization methods that delegate to the sanitization module.

use super::super::redaction::{
    AddressRedactionStrategy, GpsRedactionStrategy, PostalCodeRedactionStrategy,
    TextRedactionPolicy,
};
use super::super::sanitization;
use crate::primitives::Problem;

use super::LocationIdentifierBuilder;

impl LocationIdentifierBuilder {
    // =========================================================================
    // Sanitization Methods - Individual Redaction (Strategy Required)
    // =========================================================================

    /// Redact GPS coordinate with explicit strategy
    ///
    /// For precision levels (city/neighborhood/street), use specific precision strategies.
    #[must_use]
    pub fn redact_gps_coordinate_with_strategy(
        &self,
        coord: &str,
        strategy: GpsRedactionStrategy,
    ) -> String {
        sanitization::redact_gps_coordinate_with_strategy(coord, strategy)
    }

    /// Redact street address with explicit strategy
    #[must_use]
    pub fn redact_street_address_with_strategy(
        &self,
        address: &str,
        strategy: AddressRedactionStrategy,
    ) -> String {
        sanitization::redact_street_address_with_strategy(address, strategy)
    }

    /// Redact postal code with explicit strategy
    ///
    /// For partial visibility (ZIP-3), use `PostalCodeRedactionStrategy::ShowPrefix`.
    #[must_use]
    pub fn redact_postal_code_with_strategy(
        &self,
        code: &str,
        strategy: PostalCodeRedactionStrategy,
    ) -> String {
        sanitization::redact_postal_code_with_strategy(code, strategy)
    }

    // =========================================================================
    // Sanitization Methods - Text Redaction (Strategy Required)
    // =========================================================================

    /// Redact all GPS coordinates in text with explicit strategy
    ///
    /// Use `TextRedactionPolicy::Complete` for full redaction (default),
    /// or `TextRedactionPolicy::Partial` for regional anonymization.
    #[must_use]
    pub fn redact_gps_coordinates_in_text_with_strategy<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> std::borrow::Cow<'a, str> {
        sanitization::redact_gps_coordinates_in_text_with_strategy(text, policy)
    }

    /// Redact all street addresses in text with explicit strategy
    #[must_use]
    pub fn redact_addresses_in_text_with_strategy<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> std::borrow::Cow<'a, str> {
        sanitization::redact_addresses_in_text_with_strategy(text, policy)
    }

    /// Redact all postal codes in text with explicit strategy
    #[must_use]
    pub fn redact_postal_codes_in_text_with_strategy<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> std::borrow::Cow<'a, str> {
        sanitization::redact_postal_codes_in_text_with_strategy(text, policy)
    }

    /// Redact all location data with explicit strategy
    ///
    /// Use `TextRedactionPolicy::Complete` for full redaction,
    /// or `TextRedactionPolicy::Partial` for regional anonymization.
    #[must_use]
    pub fn redact_all_in_text_with_strategy(
        &self,
        text: &str,
        policy: TextRedactionPolicy,
    ) -> String {
        sanitization::redact_all_location_data_with_strategy(text, policy)
    }

    // =========================================================================
    // Strict Sanitization (Normalize + Validate)
    // =========================================================================

    /// Sanitize GPS coordinate strict (normalize format + validate)
    ///
    /// Combines normalization and validation in one step.
    /// Returns normalized decimal degrees format if valid, error otherwise.
    ///
    /// # Errors
    ///
    /// Returns `Problem` if GPS coordinate is invalid or out of range
    pub fn sanitize_gps_coordinate(&self, coord: &str) -> Result<String, Problem> {
        sanitization::sanitize_gps_coordinate_strict(coord)
    }

    /// Sanitize postal code strict (normalize format + validate)
    ///
    /// Combines normalization and validation in one step.
    /// Returns normalized postal code if valid, error otherwise.
    ///
    /// # Errors
    ///
    /// Returns `Problem` if postal code format is invalid
    pub fn sanitize_postal_code(&self, code: &str) -> Result<String, Problem> {
        sanitization::sanitize_postal_code_strict(code)
    }

    /// Sanitize street address strict (normalize format + validate)
    ///
    /// Validates address format and returns trimmed address.
    ///
    /// # Errors
    ///
    /// Returns `Problem` if address format is invalid
    pub fn sanitize_street_address(&self, address: &str) -> Result<String, Problem> {
        sanitization::sanitize_street_address_strict(address)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_sanitization_methods() {
        let builder = LocationIdentifierBuilder::new();

        // GPS coordinate redaction with explicit strategy
        assert_eq!(
            builder.redact_gps_coordinate_with_strategy(
                "40.7128, -74.0060",
                GpsRedactionStrategy::Token
            ),
            "[GPS_COORDINATE]"
        );
        assert_eq!(
            builder.redact_gps_coordinate_with_strategy(
                "40.7128, -74.0060",
                GpsRedactionStrategy::CityLevel
            ),
            "40.7, -74.0"
        );

        // Street address redaction with explicit strategy
        assert_eq!(
            builder.redact_street_address_with_strategy(
                "123 Main Street",
                AddressRedactionStrategy::Token
            ),
            "[ADDRESS]"
        );

        // Postal code redaction with explicit strategy
        assert_eq!(
            builder.redact_postal_code_with_strategy("10001", PostalCodeRedactionStrategy::Token),
            "[POSTAL_CODE]"
        );
        assert_eq!(
            builder
                .redact_postal_code_with_strategy("10001", PostalCodeRedactionStrategy::ShowPrefix),
            "100**"
        );

        // Text redaction with explicit strategy
        let text = "Meet at 123 Main St, ZIP 10001 (40.7128, -74.0060)";
        let result = builder.redact_all_in_text_with_strategy(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[ADDRESS]"));
        assert!(result.contains("[POSTAL_CODE]"));
        assert!(result.contains("[GPS_COORDINATE]"));
    }

    #[test]
    fn test_sanitize_strict_methods() {
        let builder = LocationIdentifierBuilder::new();

        // GPS coordinate
        assert!(builder.sanitize_gps_coordinate("40.7128, -74.0060").is_ok());
        assert!(builder.sanitize_gps_coordinate("invalid").is_err());

        // Postal code
        assert!(builder.sanitize_postal_code("10001").is_ok());
        assert!(builder.sanitize_postal_code("invalid").is_err());

        // Street address
        assert!(builder.sanitize_street_address("123 Main Street").is_ok());
        assert!(builder.sanitize_street_address("").is_err());
    }

    #[test]
    fn test_text_redaction_strategies() {
        let builder = LocationIdentifierBuilder::new();
        let text = "123 Main St, New York, NY 10001 (40.7128, -74.0060)";

        // Complete redaction (explicit strategy)
        let result = builder.redact_all_in_text_with_strategy(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[ADDRESS]"));
        assert!(result.contains("[POSTAL_CODE]"));
        assert!(result.contains("[GPS_COORDINATE]"));

        // Partial redaction (regional anonymization)
        let result = builder.redact_all_in_text_with_strategy(text, TextRedactionPolicy::Partial);
        assert!(result.contains("[ADDRESS]")); // Addresses still fully redacted
        assert!(result.contains("100**")); // Postal shows ZIP-3
        assert!(result.contains("40.7, -74.0")); // GPS shows city-level

        // Anonymous redaction
        let result = builder.redact_all_in_text_with_strategy(text, TextRedactionPolicy::Anonymous);
        assert!(result.contains("[REDACTED]"));
    }
}

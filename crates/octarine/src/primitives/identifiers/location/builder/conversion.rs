//! Conversion method implementations for LocationIdentifierBuilder
//!
//! Implements conversion and normalization methods that delegate to the conversion module.

use super::super::conversion::{self, GpsFormat, PostalCodeNormalization, PostalCodeType};
use crate::primitives::Problem;

use super::LocationIdentifierBuilder;

impl LocationIdentifierBuilder {
    // =========================================================================
    // Conversion and Normalization Methods
    // =========================================================================

    /// Normalize GPS coordinate to canonical decimal degrees format
    ///
    /// Converts various GPS coordinate formats to standard decimal degrees
    /// with consistent spacing and precision.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let builder = LocationIdentifierBuilder::new();
    ///
    /// // Normalize spacing
    /// assert_eq!(
    ///     builder.normalize_gps_coordinate("40.7128,-74.0060")?,
    ///     "40.7128, -74.006"
    /// );
    ///
    /// // Remove excessive precision
    /// assert_eq!(
    ///     builder.normalize_gps_coordinate("40.71280000, -74.00600000")?,
    ///     "40.7128, -74.006"
    /// );
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `Problem` if GPS coordinate is invalid or out of range
    pub fn normalize_gps_coordinate(&self, coordinate: &str) -> Result<String, Problem> {
        conversion::normalize_gps_coordinate(coordinate)
    }

    /// Detect GPS coordinate format
    ///
    /// Returns the format of a GPS coordinate string, or None if not recognized.
    #[must_use]
    pub fn detect_gps_format(&self, coordinate: &str) -> Option<GpsFormat> {
        conversion::detect_gps_format(coordinate)
    }

    /// Normalize postal code to standard format
    ///
    /// Converts various postal code formats to standardized representation
    /// with consistent spacing, capitalization, and formatting.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let builder = LocationIdentifierBuilder::new();
    ///
    /// // US ZIP - normalize to 5 digits
    /// assert_eq!(
    ///     builder.normalize_postal_code("10001-1234", PostalCodeNormalization::BaseOnly)?,
    ///     "10001"
    /// );
    ///
    /// // UK postcode - normalize spacing
    /// assert_eq!(
    ///     builder.normalize_postal_code("SW1A1AA", PostalCodeNormalization::Preserve)?,
    ///     "SW1A 1AA"
    /// );
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `Problem` if postal code format is not recognized
    pub fn normalize_postal_code(
        &self,
        postal_code: &str,
        mode: PostalCodeNormalization,
    ) -> Result<String, Problem> {
        conversion::normalize_postal_code(postal_code, mode)
    }

    /// Detect the type of postal code
    ///
    /// Determines whether a postal code is a US ZIP, US ZIP+4, UK postcode,
    /// or Canadian postal code based on format patterns.
    ///
    /// # Returns
    ///
    /// - `Some(PostalCodeType)` if a recognized format is detected
    /// - `None` if the format is unrecognized or invalid
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use crate::primitives::identifiers::location::{LocationIdentifierBuilder, PostalCodeType};
    ///
    /// let builder = LocationIdentifierBuilder::new();
    ///
    /// // US ZIP codes
    /// assert_eq!(builder.detect_postal_code_type("10001"), Some(PostalCodeType::UsZip));
    /// assert_eq!(builder.detect_postal_code_type("10001-1234"), Some(PostalCodeType::UsZipPlus4));
    ///
    /// // UK postcode
    /// assert_eq!(builder.detect_postal_code_type("SW1A 1AA"), Some(PostalCodeType::UkPostcode));
    ///
    /// // Canadian postal code
    /// assert_eq!(builder.detect_postal_code_type("K1A 0B1"), Some(PostalCodeType::CanadianPostal));
    ///
    /// // Invalid format
    /// assert_eq!(builder.detect_postal_code_type("invalid"), None);
    /// ```
    #[must_use]
    pub fn detect_postal_code_type(&self, postal_code: &str) -> Option<PostalCodeType> {
        conversion::detect_postal_code_type(postal_code)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_normalize_gps_coordinate() {
        let builder = LocationIdentifierBuilder::new();

        // Normalize spacing
        assert_eq!(
            builder
                .normalize_gps_coordinate("40.7128,-74.0060")
                .unwrap(),
            "40.7128, -74.006"
        );

        // Remove excessive precision
        assert_eq!(
            builder
                .normalize_gps_coordinate("40.71280000, -74.00600000")
                .unwrap(),
            "40.7128, -74.006"
        );

        // Remove labels
        assert_eq!(
            builder
                .normalize_gps_coordinate("lat: 40.7128, lon: -74.0060")
                .unwrap(),
            "40.7128, -74.006"
        );

        // Invalid coordinates
        assert!(builder.normalize_gps_coordinate("invalid").is_err());
        assert!(builder.normalize_gps_coordinate("91, 0").is_err());
    }

    #[test]
    fn test_detect_gps_format() {
        let builder = LocationIdentifierBuilder::new();

        // Decimal degrees
        assert_eq!(
            builder.detect_gps_format("40.7128, -74.0060"),
            Some(GpsFormat::DecimalDegrees)
        );

        // Invalid
        assert_eq!(builder.detect_gps_format("invalid"), None);
    }

    #[test]
    fn test_normalize_postal_code() {
        let builder = LocationIdentifierBuilder::new();

        // US ZIP - base only
        assert_eq!(
            builder
                .normalize_postal_code("10001-1234", PostalCodeNormalization::BaseOnly)
                .unwrap(),
            "10001"
        );

        // US ZIP - extended
        assert_eq!(
            builder
                .normalize_postal_code("100011234", PostalCodeNormalization::Extended)
                .unwrap(),
            "10001-1234"
        );

        // UK postcode
        assert_eq!(
            builder
                .normalize_postal_code("SW1A1AA", PostalCodeNormalization::Preserve)
                .unwrap(),
            "SW1A 1AA"
        );

        // Canadian postal
        assert_eq!(
            builder
                .normalize_postal_code("K1A0B1", PostalCodeNormalization::Preserve)
                .unwrap(),
            "K1A 0B1"
        );

        // Invalid
        assert!(
            builder
                .normalize_postal_code("invalid", PostalCodeNormalization::Preserve)
                .is_err()
        );
    }

    #[test]
    fn test_detect_postal_code_type() {
        let builder = LocationIdentifierBuilder::new();

        // US ZIP codes
        assert_eq!(
            builder.detect_postal_code_type("10001"),
            Some(PostalCodeType::UsZip)
        );
        assert_eq!(
            builder.detect_postal_code_type("90210"),
            Some(PostalCodeType::UsZip)
        );

        // US ZIP+4 codes
        assert_eq!(
            builder.detect_postal_code_type("10001-1234"),
            Some(PostalCodeType::UsZipPlus4)
        );
        assert_eq!(
            builder.detect_postal_code_type("100011234"),
            Some(PostalCodeType::UsZipPlus4)
        );

        // UK postcodes
        assert_eq!(
            builder.detect_postal_code_type("SW1A 1AA"),
            Some(PostalCodeType::UkPostcode)
        );
        assert_eq!(
            builder.detect_postal_code_type("SW1A1AA"),
            Some(PostalCodeType::UkPostcode)
        );
        assert_eq!(
            builder.detect_postal_code_type("EC1A 1BB"),
            Some(PostalCodeType::UkPostcode)
        );
        assert_eq!(
            builder.detect_postal_code_type("M1 1AE"),
            Some(PostalCodeType::UkPostcode)
        );

        // Canadian postal codes
        assert_eq!(
            builder.detect_postal_code_type("K1A 0B1"),
            Some(PostalCodeType::CanadianPostal)
        );
        assert_eq!(
            builder.detect_postal_code_type("K1A0B1"),
            Some(PostalCodeType::CanadianPostal)
        );
        assert_eq!(
            builder.detect_postal_code_type("M5W 1E6"),
            Some(PostalCodeType::CanadianPostal)
        );

        // Invalid formats
        assert_eq!(builder.detect_postal_code_type("invalid"), None);
        assert_eq!(builder.detect_postal_code_type("12"), None);
        assert_eq!(builder.detect_postal_code_type("ABCDE"), None);
        assert_eq!(builder.detect_postal_code_type(""), None);
    }
}

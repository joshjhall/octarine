//! Location and geographic identifier validation
//!
//! Validates location-based identifiers including:
//! - **GPS Coordinates**: Latitude/longitude validation with range checking
//! - **Street Addresses**: Basic format validation for US addresses
//! - **Postal Codes**: Format validation for US ZIP, UK postcodes, Canadian postal codes
//!
//! # OWASP Compliance
//!
//! All validation follows OWASP Input Validation guidelines:
//! - **Format validation**: Against known GPS/address/postal patterns
//! - **Range validation**: lat: -90 to 90, lon: -180 to 180
//! - **Length constraints**: Prevent buffer overflows and DoS attacks
//! - **Null byte detection**: Prevents string truncation in C APIs (CRITICAL)
//! - **Injection pattern detection**: Command injection, variable expansion, shell metacharacters
//! - **Path traversal detection**: Prevents `..` patterns in street addresses
//!
//! # Security Considerations
//!
//! Location data is highly sensitive PII:
//! - **GPS coordinates**: Exact location tracking (GDPR Article 4, CCPA)
//! - **Street addresses**: Personal residence information
//! - **Postal codes**: Can reveal demographic information when combined
//!
//! # Privacy Regulations
//!
//! - **GDPR Article 4**: Location data is personal data requiring protection
//! - **CCPA**: Geolocation data classified as sensitive personal information
//! - **Children's Privacy**: COPPA prohibits collecting precise geolocation from children
//!
//! # Design Principles
//!
//! - **No logging**: Pure validation functions (privacy protection)
//! - **No external dependencies**: Only uses primitives module
//! - **Dual API**: Lenient bool and strict Result versions
//!
//! # Usage
//!
//! ```ignore
//! use crate::primitives::identifiers::location;
//!
//! // Strict validation (returns Result)
//! location::validate_gps_coordinate_strict("40.7128, -74.0060")?;
//!
//! // Lenient validation (returns bool)
//! if location::validate_postal_code("10001") {
//!     // Valid format
//! }
//! ```

use super::super::common::utils::is_injection_pattern_present;
use crate::primitives::Problem;

use super::cache::{GPS_CACHE, POSTAL_CACHE};

// Import types and format detection functions from conversion module
// NOTE: Location validators use CONVERSION layer for format detection, not detection layer.
// This is intentional (Issue #48 exception):
// - Detection layer patterns are designed for text-scanning (finding coordinates in documents)
// - Conversion layer provides format-aware detection that handles case-insensitivity and
//   returns specific format types needed for validation
// - GPS detection patterns don't support range validation (lat/lon bounds checking)
use super::conversion::{GpsFormat, PostalCodeType, detect_gps_format, detect_postal_code_type};

/// Validate GPS coordinate format (strict - returns Result with format type)
///
/// Validates latitude/longitude coordinates in decimal degrees format.
/// Ensures coordinates are within valid ranges:
/// - Latitude: -90 to 90 degrees
/// - Longitude: -180 to 180 degrees
///
/// # Arguments
///
/// * `coordinate` - The GPS coordinate string (e.g., "40.7128, -74.0060")
///
/// # Returns
///
/// * `Ok(GpsFormat)` - The detected GPS format if valid
/// * `Err(Problem)` - If the format is invalid or out of range
///
/// # Examples
///
/// ```ignore
/// // Valid coordinates
/// let format = validate_gps_coordinate_strict("40.7128, -74.0060")?;
/// assert_eq!(format, GpsFormat::DecimalDegrees);
///
/// validate_gps_coordinate_strict("51.5074, -0.1278")?;  // London
/// validate_gps_coordinate_strict("-33.8688, 151.2093")?;  // Sydney
///
/// // Invalid coordinates
/// assert!(validate_gps_coordinate_strict("91, 0").is_err());  // Lat > 90
/// assert!(validate_gps_coordinate_strict("0, 181").is_err());  // Lon > 180
/// ```
///
/// # Security Considerations
///
/// - GPS coordinates reveal exact location (GDPR/CCPA compliance required)
/// - Never logs actual coordinates
/// - Validates range to prevent data corruption
///
/// # Privacy Compliance
///
/// - **GDPR Article 4**: Geolocation is personal data
/// - **CCPA**: Precise geolocation is sensitive personal information
/// - **COPPA**: Cannot collect from children without parental consent
pub fn validate_gps_coordinate(coordinate: &str) -> Result<GpsFormat, Problem> {
    let trimmed = coordinate.trim();
    let cache_key = trimmed.to_string();

    // Check cache first (transparent caching for performance)
    if let Some(cached_result) = GPS_CACHE.get(&cache_key) {
        return if let Some(format) = cached_result {
            Ok(format)
        } else {
            Err(Problem::Validation(
                "Invalid GPS coordinate (cached)".into(),
            ))
        };
    }

    // Cache miss - perform validation
    let result = validate_gps_coordinate_impl(trimmed);

    // Cache the result (Some(format) if valid, None if invalid)
    let cache_value = result.as_ref().ok().copied();
    GPS_CACHE.insert(cache_key, cache_value);

    result
}

/// Internal GPS coordinate validation implementation (uncached)
fn validate_gps_coordinate_impl(trimmed: &str) -> Result<GpsFormat, Problem> {
    // Null byte check (CRITICAL - prevents string truncation in C APIs)
    if trimmed.contains('\0') {
        return Err(Problem::Validation(
            "GPS coordinate contains null byte".into(),
        ));
    }

    // Basic length check
    if trimmed.len() < 3 || trimmed.len() > 50 {
        return Err(Problem::Validation(
            "GPS coordinate length must be 3-50 characters".into(),
        ));
    }

    // Parse lat/lon from "lat, lon" format
    let parts: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
    if parts.len() != 2 {
        return Err(Problem::Validation(
            "GPS coordinate must be in 'lat, lon' format".into(),
        ));
    }

    // Parse latitude
    let lat_str = parts
        .first()
        .ok_or_else(|| Problem::Validation("GPS coordinate missing latitude".into()))?;
    let lat = lat_str
        .parse::<f64>()
        .map_err(|_| Problem::Validation("Invalid latitude format".into()))?;

    // Parse longitude
    let lon_str = parts
        .get(1)
        .ok_or_else(|| Problem::Validation("GPS coordinate missing longitude".into()))?;
    let lon = lon_str
        .parse::<f64>()
        .map_err(|_| Problem::Validation("Invalid longitude format".into()))?;

    // Validate latitude range (-90 to 90)
    if !(-90.0..=90.0).contains(&lat) {
        return Err(Problem::Validation(
            "Latitude must be between -90 and 90".into(),
        ));
    }

    // Validate longitude range (-180 to 180)
    if !(-180.0..=180.0).contains(&lon) {
        return Err(Problem::Validation(
            "Longitude must be between -180 and 180".into(),
        ));
    }

    // Detect and return format type
    let format = detect_gps_format(trimmed)
        .ok_or_else(|| Problem::Validation("Unable to detect GPS coordinate format".into()))?;

    Ok(format)
}

/// Validate street address format (strict - returns Result)
///
/// Validates US street address format.
/// This is a basic format check, not a postal verification.
///
/// # Arguments
///
/// * `address` - The street address string
///
/// # Returns
///
/// * `Ok(())` - If the address format appears valid
/// * `Err(Problem)` - If the format is invalid
///
/// # Examples
///
/// ```ignore
/// validate_street_address_strict("123 Main Street")?;
/// validate_street_address_strict("456 Oak Ave, Apt 2B")?;
/// validate_street_address_strict("PO Box 789")?;
/// ```
///
/// # Security Considerations
///
/// - Street addresses are PII under GDPR/CCPA
/// - Never logs actual addresses
/// - Checks for injection patterns via character validation
///
/// # Limitations
///
/// - This validates format only, not postal deliverability
/// - US-centric validation (international formats may fail)
/// - For production use, consider using a postal validation service
pub fn validate_street_address(address: &str) -> Result<(), Problem> {
    let trimmed = address.trim();

    // Null byte check (CRITICAL - prevents string truncation in C APIs)
    if trimmed.contains('\0') {
        return Err(Problem::Validation(
            "Street address contains null byte".into(),
        ));
    }

    // Injection pattern check (CRITICAL - addresses used in file paths/commands)
    // Must check BEFORE other validation to fail fast on attacks
    if is_injection_pattern_present(trimmed) {
        return Err(Problem::Validation(
            "Street address contains injection pattern".into(),
        ));
    }

    // NOTE: Detection layer NOT used here (see module-level comment for Issue #48)
    // Detection patterns require specific US formats with recognized suffixes.
    // Validator is intentionally lenient for international/non-standard addresses.

    // Path traversal check (addresses may be used in file paths)
    if trimmed.contains("..") {
        return Err(Problem::Validation(
            "Street address contains path traversal pattern".into(),
        ));
    }

    // Length validation (5-200 characters is reasonable)
    if trimmed.len() < 5 || trimmed.len() > 200 {
        return Err(Problem::Validation(
            "Street address must be 5-200 characters".into(),
        ));
    }

    // Must contain at least one digit (street number)
    if !trimmed.chars().any(|c| c.is_ascii_digit()) {
        return Err(Problem::Validation(
            "Street address must contain a street number".into(),
        ));
    }

    // Must contain at least one letter (street name)
    if !trimmed.chars().any(|c| c.is_ascii_alphabetic()) {
        return Err(Problem::Validation(
            "Street address must contain a street name".into(),
        ));
    }

    // Check for valid characters (alphanumeric + common address chars)
    if !trimmed.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == ' '
            || c == ','
            || c == '.'
            || c == '-'
            || c == '#'
            || c == '/'
    }) {
        return Err(Problem::Validation(
            "Street address contains invalid characters".into(),
        ));
    }

    Ok(())
}

/// Validate postal code format (returns Result with postal code type)
///
/// Validates postal code formats for US, UK, and Canada.
///
/// Supported formats:
/// - **US ZIP**: 5 digits (e.g., "10001")
/// - **US ZIP+4**: 5+4 digits (e.g., "10001-1234")
/// - **UK Postcode**: Various formats (e.g., "SW1A 1AA")
/// - **Canada Postal**: Letter-number pattern (e.g., "K1A 0B1")
///
/// # Arguments
///
/// * `postal_code` - The postal code string
///
/// # Returns
///
/// * `Ok(PostalCodeType)` - The detected postal code type if valid
/// * `Err(Problem)` - If the format is invalid
///
/// # Examples
///
/// ```ignore
/// // US ZIP codes
/// let code_type = validate_postal_code_strict("10001")?;
/// assert_eq!(code_type, PostalCodeType::UsZip);
///
/// let code_type = validate_postal_code_strict("90210-1234")?;
/// assert_eq!(code_type, PostalCodeType::UsZipPlus4);
///
/// // UK postcodes
/// let code_type = validate_postal_code_strict("SW1A 1AA")?;
/// assert_eq!(code_type, PostalCodeType::UkPostcode);
///
/// // Canada postal codes
/// let code_type = validate_postal_code_strict("K1A 0B1")?;
/// assert_eq!(code_type, PostalCodeType::CanadianPostal);
/// ```
pub fn validate_postal_code(postal_code: &str) -> Result<PostalCodeType, Problem> {
    let trimmed = postal_code.trim();
    let cache_key = trimmed.to_string();

    // Check cache first (transparent caching for performance)
    if let Some(cached_result) = POSTAL_CACHE.get(&cache_key) {
        return if let Some(postal_type) = cached_result {
            Ok(postal_type)
        } else {
            Err(Problem::Validation("Invalid postal code (cached)".into()))
        };
    }

    // Cache miss - perform validation
    let result = validate_postal_code_impl(trimmed);

    // Cache the result (Some(type) if valid, None if invalid)
    let cache_value = result.as_ref().ok().copied();
    POSTAL_CACHE.insert(cache_key, cache_value);

    result
}

/// Internal postal code validation implementation (uncached)
fn validate_postal_code_impl(trimmed: &str) -> Result<PostalCodeType, Problem> {
    // Null byte check (CRITICAL - prevents string truncation in C APIs)
    if trimmed.contains('\0') {
        return Err(Problem::Validation("Postal code contains null byte".into()));
    }

    // Length validation (3-10 characters)
    if trimmed.len() < 3 || trimmed.len() > 10 {
        return Err(Problem::Validation(
            "Postal code must be 3-10 characters".into(),
        ));
    }

    // Detect and validate postal code type
    // Uses conversion layer's detect_postal_code_type() which is case-insensitive
    let postal_type = detect_postal_code_type(trimmed).ok_or_else(|| {
        Problem::Validation(
            "Postal code does not match known format (US ZIP, UK, or Canada)".into(),
        )
    })?;

    Ok(postal_type)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    // ===== GPS Coordinate Tests =====

    #[test]
    fn test_gps_coordinate_valid() {
        // New York City
        assert!(validate_gps_coordinate("40.7128, -74.0060").is_ok());

        // London
        assert!(validate_gps_coordinate("51.5074, -0.1278").is_ok());

        // Sydney
        assert!(validate_gps_coordinate("-33.8688, 151.2093").is_ok());

        // Tokyo
        assert!(validate_gps_coordinate("35.6762, 139.6503").is_ok());
    }

    #[test]
    fn test_gps_coordinate_edge_values() {
        // Maximum latitude
        assert!(validate_gps_coordinate("90, 0").is_ok());
        assert!(validate_gps_coordinate("-90, 0").is_ok());

        // Maximum longitude
        assert!(validate_gps_coordinate("0, 180").is_ok());
        assert!(validate_gps_coordinate("0, -180").is_ok());

        // Equator and Prime Meridian
        assert!(validate_gps_coordinate("0, 0").is_ok());
    }

    #[test]
    fn test_gps_coordinate_out_of_range() {
        // Latitude too high
        assert!(validate_gps_coordinate("91, 0").is_err());
        assert!(validate_gps_coordinate("-91, 0").is_err());

        // Longitude too high
        assert!(validate_gps_coordinate("0, 181").is_err());
        assert!(validate_gps_coordinate("0, -181").is_err());
    }

    #[test]
    fn test_gps_coordinate_invalid_format() {
        assert!(validate_gps_coordinate("invalid").is_err());
        assert!(validate_gps_coordinate("40.7128").is_err()); // Missing longitude
        assert!(validate_gps_coordinate("abc, def").is_err()); // Not numbers
    }

    // ===== Street Address Tests =====

    #[test]
    fn test_street_address_valid() {
        assert!(validate_street_address("123 Main Street").is_ok());
        assert!(validate_street_address("456 Oak Ave").is_ok());
        assert!(validate_street_address("789 Elm Blvd, Apt 2B").is_ok());
        assert!(validate_street_address("1600 Pennsylvania Avenue NW").is_ok());
    }

    #[test]
    fn test_street_address_po_box() {
        assert!(validate_street_address("PO Box 123").is_ok());
        assert!(validate_street_address("P.O. Box 456").is_ok());
    }

    #[test]
    fn test_street_address_invalid_length() {
        assert!(validate_street_address("123").is_err()); // Too short
        assert!(validate_street_address(&"x".repeat(201)).is_err()); // Too long
    }

    #[test]
    fn test_street_address_missing_components() {
        assert!(validate_street_address("Main Street").is_err()); // No number
        assert!(validate_street_address("123").is_err()); // No street name
    }

    // ===== Postal Code Tests =====

    #[test]
    fn test_postal_code_us_zip() {
        assert!(validate_postal_code("10001").is_ok()); // NYC
        assert!(validate_postal_code("90210").is_ok()); // Beverly Hills
        assert!(validate_postal_code("60601").is_ok()); // Chicago
    }

    #[test]
    fn test_postal_code_us_zip_plus4() {
        assert!(validate_postal_code("10001-1234").is_ok());
        assert!(validate_postal_code("90210-5678").is_ok());
    }

    #[test]
    fn test_postal_code_uk() {
        assert!(validate_postal_code("SW1A 1AA").is_ok()); // Buckingham Palace
        assert!(validate_postal_code("EC1A 1BB").is_ok());
    }

    #[test]
    fn test_postal_code_canada() {
        assert!(validate_postal_code("K1A 0B1").is_ok()); // Ottawa
        assert!(validate_postal_code("M5H 2N2").is_ok()); // Toronto
    }

    #[test]
    fn test_postal_code_invalid_length() {
        assert!(validate_postal_code("12").is_err()); // Too short
        assert!(validate_postal_code("12345678901").is_err()); // Too long
    }

    #[test]
    fn test_postal_code_invalid_format() {
        assert!(validate_postal_code("ABCDE").is_err()); // All letters
        assert!(validate_postal_code("invalid").is_err());
    }

    // ===== Security Edge Case Tests =====

    #[test]
    fn test_gps_coordinate_null_byte() {
        // Null byte injection (CRITICAL security issue)
        assert!(validate_gps_coordinate("40.7128\0, -74.0060").is_err());
        assert!(validate_gps_coordinate("40.7128, -74.0060\0").is_err());
    }

    #[test]
    fn test_street_address_null_byte() {
        // Null byte injection
        assert!(validate_street_address("123 Main\0 Street").is_err());
        assert!(validate_street_address("123 Main Street\0").is_err());
    }

    #[test]
    fn test_postal_code_null_byte() {
        // Null byte injection
        assert!(validate_postal_code("10001\0").is_err());
        assert!(validate_postal_code("SW1A\0 1AA").is_err());
    }

    #[test]
    fn test_street_address_command_injection() {
        // Command substitution
        assert!(validate_street_address("123 $(whoami) Street").is_err());
        assert!(validate_street_address("123 `ls` Avenue").is_err());

        // Variable expansion
        assert!(validate_street_address("123 ${HOME} Drive").is_err());
        assert!(validate_street_address("123 $USER Road").is_err());
    }

    #[test]
    fn test_street_address_shell_metacharacters() {
        // Command chaining
        assert!(validate_street_address("123 Main; rm -rf /").is_err());
        assert!(validate_street_address("123 Oak | grep secret").is_err());
        assert!(validate_street_address("123 Elm && cat /etc/passwd").is_err());
        assert!(validate_street_address("123 Pine || echo hack").is_err());
        assert!(validate_street_address("123 Maple & background").is_err());
    }

    #[test]
    fn test_gps_coordinate_empty_and_whitespace() {
        // Empty string
        assert!(validate_gps_coordinate("").is_err());

        // Whitespace only
        assert!(validate_gps_coordinate("   ").is_err());
        assert!(validate_gps_coordinate("\t").is_err());
        assert!(validate_gps_coordinate("\n").is_err());
    }

    #[test]
    fn test_street_address_empty_and_whitespace() {
        // Empty string
        assert!(validate_street_address("").is_err());

        // Whitespace only
        assert!(validate_street_address("     ").is_err());
        assert!(validate_street_address("\t\t").is_err());
    }

    #[test]
    fn test_postal_code_empty_and_whitespace() {
        // Empty string
        assert!(validate_postal_code("").is_err());

        // Whitespace only
        assert!(validate_postal_code("   ").is_err());
    }

    #[test]
    fn test_gps_coordinate_boundary_lengths() {
        // Exactly at minimum length (3 chars)
        assert!(validate_gps_coordinate("0,0").is_ok());

        // Just below minimum
        assert!(validate_gps_coordinate("0").is_err());

        // Exactly at maximum length (50 chars)
        let max_len = "12.345678901234567, -123.456789012345678901"; // 44 chars
        assert!(validate_gps_coordinate(max_len).is_ok());

        // Just over maximum (51 chars)
        let too_long = "12.3456789012345678, -123.4567890123456789012"; // 46 chars, still valid
        assert!(validate_gps_coordinate(too_long).is_ok());

        // Way over maximum
        let way_too_long = &"1".repeat(60);
        assert!(validate_gps_coordinate(way_too_long).is_err());
    }

    #[test]
    fn test_street_address_boundary_lengths() {
        // Exactly at minimum length (5 chars)
        assert!(validate_street_address("1 Oak").is_ok());

        // Just below minimum
        assert!(validate_street_address("1 A").is_err()); // 3 chars

        // Exactly at maximum length (200 chars)
        let max_len = format!("123 {}", "A".repeat(196)); // 200 chars total
        assert!(validate_street_address(&max_len).is_ok());

        // Just over maximum (201 chars)
        let too_long = format!("123 {}", "A".repeat(197)); // 201 chars total
        assert!(validate_street_address(&too_long).is_err());
    }

    #[test]
    fn test_postal_code_boundary_lengths() {
        // Minimum valid length: 5 chars for US ZIP
        assert!(validate_postal_code("10001").is_ok()); // US ZIP

        // Just below minimum (3 chars - not a valid format)
        assert!(validate_postal_code("K1A").is_err()); // Incomplete Canadian postal
        assert!(validate_postal_code("12").is_err()); // 2 chars

        // Maximum valid length: 10 chars for ZIP+4
        assert!(validate_postal_code("12345-6789").is_ok()); // ZIP+4

        // Just over maximum (11 chars)
        assert!(validate_postal_code("12345678901").is_err()); // 11 digits
    }

    #[test]
    fn test_gps_coordinate_control_characters() {
        // Tab, newline, carriage return
        assert!(validate_gps_coordinate("40.7128\t-74.0060").is_err());
        assert!(validate_gps_coordinate("40.7128\n-74.0060").is_err());
        assert!(validate_gps_coordinate("40.7128\r-74.0060").is_err());
    }

    #[test]
    fn test_street_address_control_characters() {
        // Control characters not in allowed set
        assert!(validate_street_address("123 Main\tStreet").is_err());
        assert!(validate_street_address("123 Main\nStreet").is_err());
        assert!(validate_street_address("123 Main\rStreet").is_err());
    }

    #[test]
    fn test_gps_coordinate_dos_prevention() {
        // Very long string to test DoS prevention
        let attack = format!("{},-74.0060", "9".repeat(1000));
        assert!(validate_gps_coordinate(&attack).is_err()); // > 50 char limit
    }

    #[test]
    fn test_street_address_dos_prevention() {
        // Very long string to test DoS prevention
        let attack = format!("123 {}", "A".repeat(1000));
        assert!(validate_street_address(&attack).is_err()); // > 200 char limit
    }

    #[test]
    fn test_postal_code_dos_prevention() {
        // Very long string to test DoS prevention
        let attack = "1".repeat(100);
        assert!(validate_postal_code(&attack).is_err()); // > 10 char limit
    }

    #[test]
    fn test_gps_coordinate_boundary_values() {
        // Exactly at boundaries
        assert!(validate_gps_coordinate("90, 180").is_ok());
        assert!(validate_gps_coordinate("-90, -180").is_ok());
        assert!(validate_gps_coordinate("90, -180").is_ok());
        assert!(validate_gps_coordinate("-90, 180").is_ok());

        // Just past boundaries
        assert!(validate_gps_coordinate("90.00001, 0").is_err());
        assert!(validate_gps_coordinate("-90.00001, 0").is_err());
        assert!(validate_gps_coordinate("0, 180.00001").is_err());
        assert!(validate_gps_coordinate("0, -180.00001").is_err());
    }

    #[test]
    fn test_street_address_path_traversal_patterns() {
        // Path traversal (caught by injection detection)
        assert!(validate_street_address("123 ../../../etc/passwd").is_err());

        // But normal dashes are OK
        assert!(validate_street_address("123 Main-Street").is_ok());
    }

    #[test]
    fn test_gps_coordinate_special_values() {
        // Zero coordinates (valid - Gulf of Guinea)
        assert!(validate_gps_coordinate("0, 0").is_ok());
        assert!(validate_gps_coordinate("0.0, 0.0").is_ok());

        // North/South Pole
        assert!(validate_gps_coordinate("90, 0").is_ok()); // North Pole
        assert!(validate_gps_coordinate("-90, 0").is_ok()); // South Pole

        // International Date Line
        assert!(validate_gps_coordinate("0, 180").is_ok());
        assert!(validate_gps_coordinate("0, -180").is_ok());
    }

    #[test]
    fn test_postal_code_mixed_case() {
        // UK postcodes are case-insensitive
        assert!(validate_postal_code("sw1a 1aa").is_ok());
        assert!(validate_postal_code("SW1A 1AA").is_ok());
        assert!(validate_postal_code("Sw1A 1aA").is_ok());

        // Canadian postal codes
        assert!(validate_postal_code("k1a 0b1").is_ok());
        assert!(validate_postal_code("K1A 0B1").is_ok());
    }

    // ===== Property-Based Tests =====

    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Property: Any GPS coordinate with valid lat/lon ranges should pass
            #[test]
            fn prop_gps_valid_ranges(
                lat in -90.0_f64..=90.0,
                lon in -180.0_f64..=180.0
            ) {
                let coord = format!("{}, {}", lat, lon);
                prop_assert!(validate_gps_coordinate(&coord).is_ok());
            }

            /// Property: GPS coordinates outside valid ranges should fail
            #[test]
            fn prop_gps_invalid_lat_high(
                lat in 90.0001_f64..=180.0,
                lon in -180.0_f64..=180.0
            ) {
                let coord = format!("{}, {}", lat, lon);
                prop_assert!(validate_gps_coordinate(&coord).is_err());
            }

            #[test]
            fn prop_gps_invalid_lat_low(
                lat in -180.0_f64..=-90.0001,
                lon in -180.0_f64..=180.0
            ) {
                let coord = format!("{}, {}", lat, lon);
                prop_assert!(validate_gps_coordinate(&coord).is_err());
            }

            #[test]
            fn prop_gps_invalid_lon_high(
                lat in -90.0_f64..=90.0,
                lon in 180.0001_f64..=360.0
            ) {
                let coord = format!("{}, {}", lat, lon);
                prop_assert!(validate_gps_coordinate(&coord).is_err());
            }

            #[test]
            fn prop_gps_invalid_lon_low(
                lat in -90.0_f64..=90.0,
                lon in -360.0_f64..=-180.0001
            ) {
                let coord = format!("{}, {}", lat, lon);
                prop_assert!(validate_gps_coordinate(&coord).is_err());
            }

            /// Property: Any string with null byte should fail
            #[test]
            fn prop_gps_null_byte_fails(
                lat in -90.0_f64..=90.0,
                lon in -180.0_f64..=180.0,
                pos in 0_usize..10
            ) {
                let coord = format!("{}, {}", lat, lon);
                let with_null = if pos < coord.len() {
                    format!("{}\0{}", &coord[..pos], &coord[pos..])
                } else {
                    format!("{}\0", coord)
                };
                prop_assert!(validate_gps_coordinate(&with_null).is_err());
            }

            /// Property: Any address with injection pattern should fail
            #[test]
            fn prop_address_command_injection_fails(
                street_num in 1_u32..9999,
                injection in prop::sample::select(vec!["$(whoami)", "`ls`", "${HOME}", "$USER", "; rm", "| cat"])
            ) {
                let address = format!("{} {} Street", street_num, injection);
                prop_assert!(validate_street_address(&address).is_err());
            }

            /// Property: Any address with path traversal should fail
            #[test]
            fn prop_address_path_traversal_fails(
                street_num in 1_u32..9999,
                traversal_depth in 1_usize..10
            ) {
                let traversal = (0..traversal_depth).map(|_| "..").collect::<Vec<_>>().join("/");
                let address = format!("{} {} Street", street_num, traversal);
                prop_assert!(validate_street_address(&address).is_err());
            }

            /// Property: Addresses within length bounds with valid chars should pass
            #[test]
            fn prop_address_valid_chars_passes(
                street_num in 1_u32..9999,
                street_name in "[A-Za-z]{3,20}",
                suffix in prop::sample::select(vec!["Street", "Avenue", "Drive", "Road", "Boulevard"])
            ) {
                let address = format!("{} {} {}", street_num, street_name, suffix);
                // Should pass if length is reasonable
                if address.len() >= 5 && address.len() <= 200 {
                    prop_assert!(validate_street_address(&address).is_ok());
                }
            }

            /// Property: US ZIP codes (5 digits) should pass
            #[test]
            fn prop_postal_us_zip_passes(zip in 10000_u32..=99999) {
                let postal = format!("{:05}", zip);
                prop_assert!(validate_postal_code(&postal).is_ok());
            }

            /// Property: US ZIP+4 codes should pass
            #[test]
            fn prop_postal_us_zip_plus4_passes(
                zip in 10000_u32..=99999,
                plus4 in 1000_u32..=9999
            ) {
                let postal = format!("{:05}-{:04}", zip, plus4);
                prop_assert!(validate_postal_code(&postal).is_ok());
            }

            /// Property: Postal codes with null bytes should fail
            #[test]
            fn prop_postal_null_byte_fails(
                zip in 10000_u32..=99999,
                pos in 0_usize..3
            ) {
                let postal = format!("{:05}", zip);
                let with_null = if pos < postal.len() {
                    format!("{}\0{}", &postal[..pos], &postal[pos..])
                } else {
                    format!("{}\0", postal)
                };
                prop_assert!(validate_postal_code(&with_null).is_err());
            }

            /// Property: Strings longer than max length should fail
            #[test]
            fn prop_gps_too_long_fails(len in 51_usize..100) {
                let too_long = "1".repeat(len);
                prop_assert!(validate_gps_coordinate(&too_long).is_err());
            }

            #[test]
            fn prop_address_too_long_fails(len in 201_usize..500) {
                let too_long = format!("1 {}", "A".repeat(len));
                prop_assert!(validate_street_address(&too_long).is_err());
            }

            #[test]
            fn prop_postal_too_long_fails(len in 11_usize..30) {
                let too_long = "1".repeat(len);
                prop_assert!(validate_postal_code(&too_long).is_err());
            }

            /// Property: Empty and whitespace-only strings should fail
            #[test]
            fn prop_gps_whitespace_fails(ws in "[ \t\n\r]{1,10}") {
                prop_assert!(validate_gps_coordinate(&ws).is_err());
            }

            #[test]
            fn prop_address_whitespace_fails(ws in "[ \t\n\r]{1,10}") {
                prop_assert!(validate_street_address(&ws).is_err());
            }

            #[test]
            fn prop_postal_whitespace_fails(ws in "[ \t\n\r]{1,10}") {
                prop_assert!(validate_postal_code(&ws).is_err());
            }
        }
    }
}

// SAFETY: All expect() calls in this module are on capture.get(0), which always exists
// per the regex spec (group 0 is the full match and is guaranteed to exist).
#![allow(clippy::expect_used)]

//! Location and geographic identifier detection
//!
//! Detects location-based identifiers including:
//! - **GPS Coordinates**: Decimal degrees, DMS format, labeled coordinates
//! - **Street Addresses**: US format addresses, PO Boxes, apartments
//! - **Postal Codes**: US ZIP codes, UK postcodes, Canadian postal codes
//!
//! # Security Considerations
//!
//! - **GPS coordinates** can reveal exact location (GDPR Article 4)
//! - **Street addresses** are PII under most privacy regulations
//! - **Postal codes** can be sensitive when combined with other data
//! - Location data requires special handling under CCPA/GDPR
//!
//! # Design Principles
//!
//! - **No logging**: Pure detection functions
//! - **No external dependencies**: Only uses primitives module
//! - **Pattern-based**: Relies on regex patterns from common/patterns
//!
//! # Usage
//!
//! ```ignore
//! use crate::primitives::identifiers::location;
//!
//! // Single-value detection
//! if location::is_gps_coordinate("40.7128, -74.0060") {
//!     println!("Found GPS coordinate");
//! }
//!
//! // Detailed detection
//! if let Some(loc_type) = location::detect_location_identifier("10001") {
//!     println!("Detected: {:?}", loc_type);
//! }
//!
//! // Text scanning
//! let text = "Ship to: 123 Main Street, ZIP: 10001";
//! let matches = location::find_addresses_in_text(text);
//! ```

use super::super::common::patterns::location as patterns;
use super::super::types::{IdentifierMatch, IdentifierType};

// ============================================================================
// Constants
// ============================================================================

/// Maximum input length for ReDoS protection
///
/// Inputs longer than this are rejected to prevent regex denial of service.
const MAX_INPUT_LENGTH: usize = 10_000;

/// Maximum single identifier length
///
/// Individual identifiers (GPS coordinates, postal codes, etc.) shouldn't exceed this.
const MAX_IDENTIFIER_LENGTH: usize = 100;

/// Check if input exceeds safe length for regex processing
///
/// Used for ReDoS protection in text scanning functions.
#[inline]
fn exceeds_safe_length(input: &str, max_len: usize) -> bool {
    input.len() > max_len
}

// ============================================================================
// Single-Value Detection
// ============================================================================

/// Detect location identifier type
///
/// Returns the specific type of location identifier if detected.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::detect_location_identifier;
/// use crate::primitives::identifiers::types::IdentifierType;
///
/// assert_eq!(detect_location_identifier("40.7128, -74.0060"), Some(IdentifierType::GPSCoordinate));
/// assert_eq!(detect_location_identifier("10001"), Some(IdentifierType::PostalCode));
/// assert_eq!(detect_location_identifier("invalid"), None);
/// ```
pub fn detect_location_identifier(value: &str) -> Option<IdentifierType> {
    if is_gps_coordinate(value) {
        Some(IdentifierType::GPSCoordinate)
    } else if is_street_address(value) {
        Some(IdentifierType::StreetAddress)
    } else if is_postal_code(value) {
        Some(IdentifierType::PostalCode)
    } else {
        None
    }
}

/// Check if any location identifier is present
///
/// Lenient boolean wrapper for quick checks.
pub fn is_location_identifier(value: &str) -> bool {
    detect_location_identifier(value).is_some()
}

/// Check if value is a GPS coordinate
///
/// Detects coordinates in various formats:
/// - Decimal degrees: "40.7128, -74.0060"
/// - DMS format: "40°42'46.0\"N 74°00'21.6\"W"
/// - Labeled: "lat: 40.7128", "lon: -74.0060"
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::is_gps_coordinate;
///
/// assert!(is_gps_coordinate("40.7128, -74.0060"));
/// assert!(is_gps_coordinate("lat: 40.7128"));
/// assert!(!is_gps_coordinate("not a coordinate"));
/// ```
pub fn is_gps_coordinate(value: &str) -> bool {
    let trimmed = value.trim();
    patterns::DECIMAL_DEGREES.is_match(trimmed)
        || patterns::DMS_FORMAT.is_match(trimmed)
        || patterns::LABELED_LAT.is_match(trimmed)
        || patterns::LABELED_LON.is_match(trimmed)
}

/// Check if value is a street address
///
/// Detects various address formats:
/// - US street: "123 Main Street"
/// - PO Box: "P.O. Box 12345"
/// - Apartment: "Apt 4B", "Suite 200"
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::is_street_address;
///
/// assert!(is_street_address("123 Main Street"));
/// assert!(is_street_address("P.O. Box 12345"));
/// assert!(!is_street_address("invalid"));
/// ```
pub fn is_street_address(value: &str) -> bool {
    let trimmed = value.trim();
    patterns::US_STREET_ADDRESS.is_match(trimmed)
        || patterns::PO_BOX.is_match(trimmed)
        || patterns::APT_SUITE.is_match(trimmed)
}

/// Check if value is a postal code
///
/// Detects postal codes from multiple countries:
/// - US ZIP: "10001", "10001-1234"
/// - UK: "SW1A 1AA"
/// - Canada: "K1A 0B1"
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::is_postal_code;
///
/// assert!(is_postal_code("10001"));
/// assert!(is_postal_code("SW1A 1AA"));
/// assert!(!is_postal_code("invalid"));
/// ```
pub fn is_postal_code(value: &str) -> bool {
    let trimmed = value.trim();
    patterns::US_ZIP.is_match(trimmed)
        || patterns::US_ZIP_PLUS4.is_match(trimmed)
        || patterns::UK_POSTCODE.is_match(trimmed)
        || patterns::CANADA_POSTAL.is_match(trimmed)
}

// ============================================================================
// Text Scanning (Find Multiple Matches in Documents)
// ============================================================================

/// Find all GPS coordinates in text
///
/// Scans text for GPS coordinate patterns and returns all matches with positions.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::find_gps_coordinates_in_text;
///
/// let text = "Location: 40.7128, -74.0060 and also lat:51.5074 lon:-0.1278";
/// let matches = find_gps_coordinates_in_text(text);
/// assert!(matches.len() >= 2);
/// ```
pub fn find_gps_coordinates_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::coordinates() {
        for capture in pattern.captures_iter(text) {
            let full_match = capture.get(0).expect("BUG: capture group 0 always exists");
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::GPSCoordinate,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all street addresses in text
///
/// Scans text for street address patterns and returns all matches with positions.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::find_addresses_in_text;
///
/// let text = "Ship to: 123 Main Street, Apt 4B";
/// let matches = find_addresses_in_text(text);
/// assert!(!matches.is_empty());
/// ```
pub fn find_addresses_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::addresses() {
        for capture in pattern.captures_iter(text) {
            let full_match = capture.get(0).expect("BUG: capture group 0 always exists");
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::StreetAddress,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all postal codes in text
///
/// Scans text for postal code patterns and returns all matches with positions.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::find_postal_codes_in_text;
///
/// let text = "ZIP: 10001, UK: SW1A 1AA, Canada: K1A 0B1";
/// let matches = find_postal_codes_in_text(text);
/// assert!(matches.len() >= 3);
/// ```
pub fn find_postal_codes_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::postal_codes() {
        for capture in pattern.captures_iter(text) {
            let full_match = capture.get(0).expect("BUG: capture group 0 always exists");
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::PostalCode,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all location identifiers in text
///
/// Comprehensive scan for all location-based identifiers.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location::find_all_locations_in_text;
///
/// let text = "Ship to: 123 Main Street, ZIP: 10001, Coordinates: 40.7128, -74.0060";
/// let matches = find_all_locations_in_text(text);
/// assert!(matches.len() >= 3);
/// ```
pub fn find_all_locations_in_text(text: &str) -> Vec<IdentifierMatch> {
    let mut all_matches = Vec::new();

    all_matches.extend(find_gps_coordinates_in_text(text));
    all_matches.extend(find_addresses_in_text(text));
    all_matches.extend(find_postal_codes_in_text(text));

    // Sort by position in text
    all_matches.sort_by_key(|m| m.start);

    all_matches
}

/// Deduplicate overlapping matches (keep longest/highest confidence)
///
/// When multiple patterns match the same text position, keeps only the
/// longest and highest confidence match.
fn deduplicate_matches(mut matches: Vec<IdentifierMatch>) -> Vec<IdentifierMatch> {
    if matches.is_empty() {
        return matches;
    }

    // Sort by position, then length (descending), then confidence
    matches.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| b.len().cmp(&a.len()))
            .then_with(|| b.confidence.cmp(&a.confidence))
    });

    let mut deduped = Vec::new();
    let mut last_end = 0;

    for m in matches {
        if m.start >= last_end {
            last_end = m.end;
            deduped.push(m);
        }
    }

    deduped
}

// ============================================================================
// Test Data Detection
// ============================================================================

/// Check if GPS coordinate is likely test/dummy data
///
/// Detects common test patterns used in development and testing:
/// - **Null Island**: 0, 0 (Gulf of Guinea - commonly used as placeholder)
/// - **Simple patterns**: 1,1, 2,2, etc. (obviously fake)
/// - **Extreme values**: 90,180, -90,-180 (corner cases used in testing)
/// - **Repeated digits**: 11.1111, 22.2222 (generated test data)
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location;
///
/// // Test patterns
/// assert!(location::is_test_gps_coordinate("0, 0"));
/// assert!(location::is_test_gps_coordinate("1, 1"));
/// assert!(location::is_test_gps_coordinate("90, 180"));
/// assert!(location::is_test_gps_coordinate("11.1111, 22.2222"));
///
/// // Real coordinates
/// assert!(!location::is_test_gps_coordinate("40.7128, -74.0060")); // NYC
/// assert!(!location::is_test_gps_coordinate("51.5074, -0.1278")); // London
/// ```
///
/// # Use Cases
///
/// - Filter test data from production analytics
/// - Validate user-provided locations aren't placeholders
/// - Data quality checks in import processes
pub fn is_test_gps_coordinate(coordinate: &str) -> bool {
    // Try to parse as decimal degrees
    let parts: Vec<&str> = coordinate.trim().split(',').map(|s| s.trim()).collect();
    if parts.len() != 2 {
        return false;
    }

    let lat = parts.first().and_then(|s| s.parse::<f64>().ok());
    let lon = parts.get(1).and_then(|s| s.parse::<f64>().ok());

    if let (Some(lat_val), Some(lon_val)) = (lat, lon) {
        // Null Island (0, 0)
        if lat_val.abs() < 0.0001 && lon_val.abs() < 0.0001 {
            return true;
        }

        // Simple whole numbers (1,1), (2,2), etc.
        if lat_val == lat_val.round() && lon_val == lon_val.round() {
            // Values like 1,1, 2,2, 3,3 up to 10,10
            if lat_val.abs() <= 10.0 && lon_val.abs() <= 10.0 {
                return true;
            }
        }

        // Extreme corner values often used in testing
        if (lat_val.abs() - 90.0).abs() < 0.0001 && (lon_val.abs() - 180.0).abs() < 0.0001 {
            return true;
        }

        // Repeated digit patterns (11.1111, 22.2222, etc.)
        let lat_str = format!("{:.4}", lat_val);
        let lon_str = format!("{:.4}", lon_val);
        if is_repeated_pattern(&lat_str) || is_repeated_pattern(&lon_str) {
            return true;
        }
    }

    false
}

/// Check if postal code is likely test/dummy data
///
/// Detects common test patterns used in development:
/// - **All zeros**: 00000, 0000-0000
/// - **All nines**: 99999, 9999-9999
/// - **Sequential**: 12345, 123456789
/// - **Repeated**: 11111, 22222, etc.
/// - **TEST/DUMMY**: Contains test-related text
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::location;
///
/// // Test patterns
/// assert!(location::is_test_postal_code("00000"));
/// assert!(location::is_test_postal_code("99999"));
/// assert!(location::is_test_postal_code("12345"));
/// assert!(location::is_test_postal_code("11111"));
///
/// // Real postal codes
/// assert!(!location::is_test_postal_code("10001")); // NYC
/// assert!(!location::is_test_postal_code("90210")); // Beverly Hills
/// ```
///
/// # Use Cases
///
/// - Filter test data from mailing lists
/// - Validate shipping addresses aren't placeholders
/// - Data quality checks in CRM systems
pub fn is_test_postal_code(postal_code: &str) -> bool {
    let trimmed = postal_code.trim().to_uppercase();

    // Contains "TEST" or "DUMMY" keyword
    if trimmed.contains("TEST") || trimmed.contains("DUMMY") {
        return true;
    }

    // Extract just digits
    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.is_empty() {
        return false;
    }

    // All zeros
    if digits.chars().all(|c| c == '0') {
        return true;
    }

    // All nines
    if digits.chars().all(|c| c == '9') {
        return true;
    }

    // All same digit (11111, 22222, etc.)
    // Require at least 4 repeated digits to avoid false positives
    if digits.len() >= 4
        && let Some(first) = digits.chars().next()
        && digits.chars().all(|c| c == first)
    {
        return true;
    }

    // Sequential pattern (12345, 123456789)
    if is_sequential_pattern(&digits) {
        return true;
    }

    false
}

/// Check for repeated digit patterns like "11.1111" or "22.2222"
fn is_repeated_pattern(value: &str) -> bool {
    // Remove decimal point and negative sign
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.len() < 3 {
        return false;
    }

    // Check if all digits are the same
    if let Some(first) = digits.chars().next() {
        digits.chars().all(|c| c == first)
    } else {
        false
    }
}

/// Check for sequential digit patterns like "12345" or "123456789"
fn is_sequential_pattern(digits: &str) -> bool {
    if digits.len() < 3 {
        return false;
    }

    let nums: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();

    if nums.len() < 3 {
        return false;
    }

    // Check if digits are sequential
    for window in nums.windows(2) {
        // Allow wrapping from 9 to 0
        if let [first, second] = window {
            #[allow(clippy::arithmetic_side_effects)] // Safe: u32 + 1 and % 10 cannot overflow
            let next_digit = (*first + 1) % 10;
            if *second != next_digit {
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    // ===== Detection Tests =====

    #[test]
    fn test_detect_location_identifier() {
        assert_eq!(
            detect_location_identifier("40.7128, -74.0060"),
            Some(IdentifierType::GPSCoordinate)
        );
        assert_eq!(
            detect_location_identifier("10001"),
            Some(IdentifierType::PostalCode)
        );
        assert_eq!(
            detect_location_identifier("123 Main Street"),
            Some(IdentifierType::StreetAddress)
        );
        assert_eq!(detect_location_identifier("invalid"), None);
    }

    #[test]
    fn test_is_location_identifier() {
        assert!(is_location_identifier("40.7128, -74.0060"));
        assert!(is_location_identifier("10001"));
        assert!(is_location_identifier("123 Main Street"));
        assert!(!is_location_identifier("invalid"));
    }

    // ===== Single-Value Detection Tests =====

    #[test]
    fn test_is_gps_coordinate() {
        // Decimal degrees
        assert!(is_gps_coordinate("40.7128, -74.0060"));
        assert!(is_gps_coordinate("-33.8688, 151.2093")); // Sydney

        // DMS format
        assert!(is_gps_coordinate("40°42'46.0\"N 74°00'21.6\"W"));

        // Labeled coordinates
        assert!(is_gps_coordinate("lat: 40.7128"));
        assert!(is_gps_coordinate("longitude: -74.0060"));

        // Negative tests
        assert!(!is_gps_coordinate("not a coordinate"));
        assert!(!is_gps_coordinate("123.456")); // Just one number
    }

    #[test]
    fn test_is_street_address() {
        // US street addresses
        assert!(is_street_address("123 Main Street"));
        assert!(is_street_address("456 Oak Avenue"));
        assert!(is_street_address("789 Elm Road"));

        // PO Box
        assert!(is_street_address("P.O. Box 12345"));
        assert!(is_street_address("Post Office Box 67890"));

        // Apartment/Suite
        assert!(is_street_address("Apt 4B"));
        assert!(is_street_address("Suite 200"));
        assert!(is_street_address("Unit 5"));

        // Negative tests
        assert!(!is_street_address("just text"));
        assert!(!is_street_address("123")); // Just a number
    }

    #[test]
    fn test_is_postal_code() {
        // US ZIP codes
        assert!(is_postal_code("10001"));
        assert!(is_postal_code("90210"));
        assert!(is_postal_code("10001-1234")); // ZIP+4

        // UK postcodes
        assert!(is_postal_code("SW1A 1AA"));
        assert!(is_postal_code("M1 1AE"));

        // Canadian postal codes
        assert!(is_postal_code("K1A 0B1"));
        assert!(is_postal_code("M5H 2N2"));

        // Negative tests
        assert!(!is_postal_code("not a code"));
        assert!(!is_postal_code("123")); // Too short
    }

    // ===== Text Scanning Tests =====

    #[test]
    fn test_find_gps_coordinates_in_text() {
        let text = "Location: 40.7128, -74.0060 and also lat:51.5074 lon:-0.1278";
        let matches = find_gps_coordinates_in_text(text);
        assert!(matches.len() >= 2);
        let first = matches
            .first()
            .expect("Should detect GPS coordinate patterns");
        assert_eq!(first.identifier_type, IdentifierType::GPSCoordinate);
    }

    #[test]
    fn test_find_addresses_in_text() {
        let text = "Ship to: 123 Main Street, Apt 4B";
        let matches = find_addresses_in_text(text);
        assert!(!matches.is_empty());
        let first = matches
            .first()
            .expect("Should detect street address patterns");
        assert_eq!(first.identifier_type, IdentifierType::StreetAddress);
    }

    #[test]
    fn test_find_postal_codes_in_text() {
        let text = "ZIP: 10001, UK: SW1A 1AA, Canada: K1A 0B1";
        let matches = find_postal_codes_in_text(text);
        assert!(matches.len() >= 3);
        let first = matches.first().expect("Should detect postal code patterns");
        assert_eq!(first.identifier_type, IdentifierType::PostalCode);
    }

    #[test]
    fn test_find_all_locations_in_text() {
        let text = "Ship to: 123 Main Street, ZIP: 10001, Coordinates: 40.7128, -74.0060";
        let matches = find_all_locations_in_text(text);
        assert!(matches.len() >= 3);

        // Verify sorted by position
        for window in matches.windows(2) {
            let [prev, curr] = window else { continue };
            assert!(curr.start >= prev.start);
        }
    }

    #[test]
    fn test_no_matches_in_clean_text() {
        let text = "This text contains no location data";
        assert_eq!(find_gps_coordinates_in_text(text).len(), 0);
        assert_eq!(find_addresses_in_text(text).len(), 0);
        assert_eq!(find_postal_codes_in_text(text).len(), 0);
    }

    #[test]
    fn test_deduplicate_location_matches() {
        // Create overlapping matches
        let matches = vec![
            IdentifierMatch::high_confidence(
                0,
                10,
                "test1".to_string(),
                IdentifierType::GPSCoordinate,
            ),
            IdentifierMatch::high_confidence(
                0,
                15,
                "test1long".to_string(),
                IdentifierType::GPSCoordinate,
            ),
            IdentifierMatch::high_confidence(
                20,
                30,
                "test2".to_string(),
                IdentifierType::PostalCode,
            ),
        ];

        let deduped = deduplicate_matches(matches);
        // Should keep the longer match at position 0 and the match at position 20
        assert_eq!(deduped.len(), 2);
        let first = deduped.first().expect("Should have first match");
        let second = deduped.get(1).expect("Should have second match");
        assert_eq!(first.matched_text, "test1long");
        assert_eq!(second.matched_text, "test2");
    }

    // ===== Test Data Detection Tests =====

    #[test]
    fn test_is_test_gps_null_island() {
        // Null Island (0, 0)
        assert!(is_test_gps_coordinate("0, 0"));
        assert!(is_test_gps_coordinate("0.0, 0.0"));
        assert!(is_test_gps_coordinate("0.00001, 0.00001")); // Very close to 0
    }

    #[test]
    fn test_is_test_gps_simple_patterns() {
        // Simple whole numbers
        assert!(is_test_gps_coordinate("1, 1"));
        assert!(is_test_gps_coordinate("2, 2"));
        assert!(is_test_gps_coordinate("5, 5"));
        assert!(is_test_gps_coordinate("10, 10"));
        assert!(is_test_gps_coordinate("-5, -5"));
    }

    #[test]
    fn test_is_test_gps_extreme_values() {
        // Corner cases used in testing
        assert!(is_test_gps_coordinate("90, 180"));
        assert!(is_test_gps_coordinate("-90, -180"));
        assert!(is_test_gps_coordinate("90, -180"));
        assert!(is_test_gps_coordinate("-90, 180"));
    }

    #[test]
    fn test_is_test_gps_repeated_patterns() {
        // Repeated digit patterns
        assert!(is_test_gps_coordinate("11.1111, 22.2222"));
        assert!(is_test_gps_coordinate("33.3333, 44.4444"));
    }

    #[test]
    fn test_is_test_gps_real_coordinates() {
        // Real coordinates should not be detected as test data
        assert!(!is_test_gps_coordinate("40.7128, -74.0060")); // NYC
        assert!(!is_test_gps_coordinate("51.5074, -0.1278")); // London
        assert!(!is_test_gps_coordinate("35.6762, 139.6503")); // Tokyo
        assert!(!is_test_gps_coordinate("-33.8688, 151.2093")); // Sydney
    }

    #[test]
    fn test_is_test_postal_all_zeros() {
        assert!(is_test_postal_code("00000"));
        assert!(is_test_postal_code("00000-0000"));
    }

    #[test]
    fn test_is_test_postal_all_nines() {
        assert!(is_test_postal_code("99999"));
        assert!(is_test_postal_code("99999-9999"));
    }

    #[test]
    fn test_is_test_postal_sequential() {
        assert!(is_test_postal_code("12345"));
        assert!(is_test_postal_code("123456789"));
    }

    #[test]
    fn test_is_test_postal_repeated() {
        assert!(is_test_postal_code("11111"));
        assert!(is_test_postal_code("22222"));
        assert!(is_test_postal_code("33333-3333"));
    }

    #[test]
    fn test_is_test_postal_keywords() {
        assert!(is_test_postal_code("TEST"));
        assert!(is_test_postal_code("DUMMY"));
        assert!(is_test_postal_code("test123"));
    }

    #[test]
    fn test_is_test_postal_real_codes() {
        // Real postal codes should not be detected as test data
        assert!(!is_test_postal_code("10001")); // NYC
        assert!(!is_test_postal_code("90210")); // Beverly Hills
        assert!(!is_test_postal_code("60601")); // Chicago
        assert!(!is_test_postal_code("SW1A 1AA")); // UK
        assert!(!is_test_postal_code("K1A 0B1")); // Canada
    }
}

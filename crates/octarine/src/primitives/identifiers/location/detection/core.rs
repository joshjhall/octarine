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

use super::super::super::common::patterns::location as patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};

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
/// - Germany: "10115"
/// - France: "75001" (dept 01-98)
/// - Australia: "2000" (range 0200-9999)
/// - Japan: "100-0001"
/// - India: "110001" (first digit 1-8)
/// - Netherlands: "1011 AB"
/// - Brazil: "01001-000"
///
/// Per-value detection — does not require surrounding address context. For
/// text-scanning behavior with context disambiguation, see
/// [`find_postal_codes_in_text`].
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
        || is_german_postal_code(trimmed)
        || is_french_postal_code(trimmed)
        || is_australian_postal_code(trimmed)
        || is_japanese_postal_code(trimmed)
        || is_indian_postal_code(trimmed)
        || is_dutch_postal_code(trimmed)
        || is_brazilian_postal_code(trimmed)
}

/// Check if value is a German postal code (5 digits, all 00000-99999).
///
/// Germany's `Postleitzahl` is a 5-digit code with no internal punctuation.
/// Identical regex to US ZIP — callers needing country precision must rely on
/// context (address keywords, country fields).
///
/// # Examples
///
/// ```ignore
/// assert!(is_german_postal_code("10115"));  // Berlin
/// assert!(!is_german_postal_code("1011"));  // Too short
/// ```
pub fn is_german_postal_code(value: &str) -> bool {
    let trimmed = value.trim();
    patterns::GERMAN_POSTAL.is_match(trimmed)
}

/// Check if value is a French postal code (5 digits with department code 01-98).
///
/// Range 01-98 is enforced both by the regex and re-validated post-trim for safety.
/// 00xxx, 99xxx are rejected (no French department uses them).
///
/// # Examples
///
/// ```ignore
/// assert!(is_french_postal_code("75001"));   // Paris (dept 75)
/// assert!(is_french_postal_code("01000"));   // Ain (dept 01)
/// assert!(!is_french_postal_code("00500"));  // dept 00 invalid
/// assert!(!is_french_postal_code("99000"));  // dept 99 invalid
/// ```
pub fn is_french_postal_code(value: &str) -> bool {
    let trimmed = value.trim();
    if !patterns::FRENCH_POSTAL.is_match(trimmed) {
        return false;
    }
    let dept: u32 = trimmed.get(..2).and_then(|s| s.parse().ok()).unwrap_or(0);
    (1..=98).contains(&dept)
}

/// Check if value is an Australian postal code (4 digits, range 0200-9999).
///
/// The leading 02xx-09xx range covers ACT and NT; 1xxx-9xxx covers the states.
/// 0000-0199 are not assigned.
///
/// # Examples
///
/// ```ignore
/// assert!(is_australian_postal_code("2000"));   // Sydney
/// assert!(is_australian_postal_code("0200"));   // ANU (minimum)
/// assert!(!is_australian_postal_code("0199"));  // Below minimum
/// ```
pub fn is_australian_postal_code(value: &str) -> bool {
    let trimmed = value.trim();
    if !patterns::AUSTRALIAN_POSTAL.is_match(trimmed) {
        return false;
    }
    let n: u32 = trimmed.parse().unwrap_or(0);
    (200..=9999).contains(&n)
}

/// Check if value is a Japanese postal code (NNN-NNNN, 7 digits with hyphen).
///
/// Japan's postal code is canonically formatted with a hyphen after the first 3
/// digits. The unhyphenated 7-digit form is accepted via normalization; see
/// `conversion::postal::normalize_postal_code`.
///
/// # Examples
///
/// ```ignore
/// assert!(is_japanese_postal_code("100-0001"));   // Tokyo
/// assert!(!is_japanese_postal_code("1000001"));   // Missing hyphen
/// ```
pub fn is_japanese_postal_code(value: &str) -> bool {
    let trimmed = value.trim();
    patterns::JAPANESE_POSTAL.is_match(trimmed)
}

/// Check if value is an Indian PIN code (6 digits, first digit 1-8).
///
/// India Post divides the country into 8 postal zones, encoded in the first
/// digit. 0 is unused; 9 is reserved for the Army Postal Service.
///
/// # Examples
///
/// ```ignore
/// assert!(is_indian_postal_code("110001"));   // New Delhi
/// assert!(!is_indian_postal_code("010001"));  // Zone 0 invalid
/// assert!(!is_indian_postal_code("910001"));  // Zone 9 reserved
/// ```
pub fn is_indian_postal_code(value: &str) -> bool {
    let trimmed = value.trim();
    patterns::INDIAN_POSTAL.is_match(trimmed)
}

/// Check if value is a Dutch postal code (NNNN AA, first digit 1-9).
///
/// Netherlands postal codes are 4 digits followed by 2 uppercase letters,
/// optionally separated by a space. Leading 0 is invalid.
///
/// # Examples
///
/// ```ignore
/// assert!(is_dutch_postal_code("1011 AB"));   // Amsterdam
/// assert!(is_dutch_postal_code("1011AB"));    // No space — accepted
/// assert!(!is_dutch_postal_code("0123 AB"));  // Leading 0 invalid
/// ```
pub fn is_dutch_postal_code(value: &str) -> bool {
    let trimmed = value.trim();
    patterns::DUTCH_POSTAL.is_match(trimmed)
}

/// Check if value is a Brazilian CEP (NNNNN-NNN, 8 digits with hyphen).
///
/// CEP (Código de Endereçamento Postal) is canonically formatted with a hyphen
/// after the first 5 digits.
///
/// # Examples
///
/// ```ignore
/// assert!(is_brazilian_postal_code("01001-000"));   // São Paulo
/// assert!(!is_brazilian_postal_code("01001000"));   // Missing hyphen
/// ```
pub fn is_brazilian_postal_code(value: &str) -> bool {
    let trimmed = value.trim();
    patterns::BRAZILIAN_POSTAL.is_match(trimmed)
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
/// **Context disambiguation**: short-numeric international codes (German 5-digit,
/// French 5-digit, Australian 4-digit, Indian 6-digit) collide with phone numbers,
/// prices, years, and other unrelated numerics. Matches against these patterns are
/// only reported when an address-context keyword (zip, postal, PLZ, CEP, etc.)
/// appears within a ±50-character window. Structurally distinctive codes (JP
/// `NNN-NNNN`, NL `NNNN AA`, BR `NNNNN-NNN`) and the historical US/UK/Canada
/// patterns are reported unconditionally.
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

    // Phase 1: context-free patterns (current behavior; structurally distinctive)
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

    // Phase 2: short-numeric patterns gated by address context. We additionally
    // re-validate range constraints (e.g., French dept 01-98) by routing through
    // the per-value `is_*_postal_code` functions so 99000-style regex matches
    // that fail the country's range are dropped.
    for pattern in patterns::postal_codes_requiring_context() {
        for capture in pattern.captures_iter(text) {
            let full_match = capture.get(0).expect("BUG: capture group 0 always exists");
            let matched = full_match.as_str();
            if !is_address_context_present(text, full_match.start(), full_match.end()) {
                continue;
            }
            // Range re-validation for short numerics. Regex already enforces
            // structural format; this drops out-of-range numerics that share
            // the format (e.g., AU "0100" is 4 digits but below the 0200 floor).
            let in_range = is_german_postal_code(matched)
                || is_french_postal_code(matched)
                || is_australian_postal_code(matched)
                || is_indian_postal_code(matched);
            if !in_range {
                continue;
            }
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                matched.to_string(),
                IdentifierType::PostalCode,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Width (in chars/bytes; postal context keywords are ASCII) of the address-context
/// window scanned around a short-numeric postal code match.
const POSTAL_CONTEXT_WINDOW: usize = 50;

/// Returns true iff an address-context keyword appears within
/// `POSTAL_CONTEXT_WINDOW` characters of the given match span.
///
/// Slicing uses [`str::get`] (saturating bounds), so non-ASCII boundary
/// failures degrade to "no context found" rather than panic.
fn is_address_context_present(text: &str, match_start: usize, match_end: usize) -> bool {
    let before_start = match_start.saturating_sub(POSTAL_CONTEXT_WINDOW);
    let after_end = match_end
        .saturating_add(POSTAL_CONTEXT_WINDOW)
        .min(text.len());
    let window = text.get(before_start..after_end).unwrap_or("");
    patterns::POSTAL_CONTEXT_KEYWORD.is_match(window)
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

        // International — shares postal_code umbrella
        assert!(is_postal_code("100-0001")); // Japan
        assert!(is_postal_code("1011 AB")); // Netherlands
        assert!(is_postal_code("01001-000")); // Brazil
        assert!(is_postal_code("75001")); // France (also matches US ZIP shape)
        assert!(is_postal_code("110001")); // India

        // Negative tests
        assert!(!is_postal_code("not a code"));
        assert!(!is_postal_code("123")); // Too short
    }

    #[test]
    fn test_is_german_postal_code() {
        assert!(is_german_postal_code("10115")); // Berlin
        assert!(is_german_postal_code("80331")); // Munich
        assert!(is_german_postal_code("01067")); // Dresden
        assert!(!is_german_postal_code("1011")); // Too short
        assert!(!is_german_postal_code("101150")); // Too long
        assert!(!is_german_postal_code("ABCDE")); // Not digits
    }

    #[test]
    fn test_is_french_postal_code() {
        // Valid dept codes 01-98
        assert!(is_french_postal_code("75001")); // Paris (75)
        assert!(is_french_postal_code("01000")); // Ain (01, minimum)
        assert!(is_french_postal_code("98000")); // Monaco (98, maximum)
        assert!(is_french_postal_code("13001")); // Marseille (13)

        // Invalid dept codes
        assert!(!is_french_postal_code("00500")); // dept 00
        assert!(!is_french_postal_code("99000")); // dept 99
        assert!(!is_french_postal_code("7500")); // Too short
        assert!(!is_french_postal_code("750010")); // Too long
    }

    #[test]
    fn test_is_australian_postal_code() {
        assert!(is_australian_postal_code("2000")); // Sydney
        assert!(is_australian_postal_code("0200")); // ANU (minimum)
        assert!(is_australian_postal_code("9999")); // Maximum
        assert!(is_australian_postal_code("3000")); // Melbourne

        // Below minimum
        assert!(!is_australian_postal_code("0199"));
        assert!(!is_australian_postal_code("0000"));
        assert!(!is_australian_postal_code("0100"));
        // Wrong length
        assert!(!is_australian_postal_code("200"));
        assert!(!is_australian_postal_code("20000"));
    }

    #[test]
    fn test_is_japanese_postal_code() {
        assert!(is_japanese_postal_code("100-0001")); // Tokyo
        assert!(is_japanese_postal_code("530-0001")); // Osaka
        assert!(!is_japanese_postal_code("1000001")); // Missing hyphen
        assert!(!is_japanese_postal_code("100-001")); // Wrong second group length
        assert!(!is_japanese_postal_code("10-00001")); // Wrong first group length
    }

    #[test]
    fn test_is_indian_postal_code() {
        assert!(is_indian_postal_code("110001")); // New Delhi (zone 1)
        assert!(is_indian_postal_code("400001")); // Mumbai (zone 4)
        assert!(is_indian_postal_code("800001")); // Patna (zone 8, max)

        assert!(!is_indian_postal_code("010001")); // Zone 0 invalid
        assert!(!is_indian_postal_code("910001")); // Zone 9 reserved (army)
        assert!(!is_indian_postal_code("11000")); // Too short
        assert!(!is_indian_postal_code("1100001")); // Too long
    }

    #[test]
    fn test_is_dutch_postal_code() {
        assert!(is_dutch_postal_code("1011 AB")); // Amsterdam with space
        assert!(is_dutch_postal_code("1011AB")); // Without space
        assert!(is_dutch_postal_code("9999 ZZ")); // Maximum-ish

        assert!(!is_dutch_postal_code("0123 AB")); // Leading 0 invalid
        assert!(!is_dutch_postal_code("1011 ab")); // Lowercase letters
        assert!(!is_dutch_postal_code("1011 A")); // Missing letter
    }

    #[test]
    fn test_is_brazilian_postal_code() {
        assert!(is_brazilian_postal_code("01001-000")); // São Paulo
        assert!(is_brazilian_postal_code("20040-002")); // Rio de Janeiro

        assert!(!is_brazilian_postal_code("01001000")); // Missing hyphen
        assert!(!is_brazilian_postal_code("01001-00")); // Short suffix
        assert!(!is_brazilian_postal_code("0100-000")); // Short prefix
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
    fn test_find_postal_codes_skips_short_numeric_without_context() {
        // Test 4-digit (Australian) and 6-digit (Indian) short numerics without
        // address context. These shapes are NOT matched by the pre-existing
        // US/UK/Canada/JP/NL/BR patterns, so a hit here would mean our new
        // DE/FR/AU/IN scanners fired without context — which they must not.
        //
        // Note: 5-digit numerics (DE/FR shape) are unavoidably captured by the
        // pre-existing US_ZIP regex; we intentionally keep that behavior.
        let text = "Code 2000 here and 110001 there. Year 9999 also.";
        let matches = find_postal_codes_in_text(text);
        let short_matches: Vec<&str> = matches
            .iter()
            .map(|m| m.matched_text.as_str())
            .filter(|t| ["2000", "9999", "110001"].contains(t))
            .collect();
        assert!(
            short_matches.is_empty(),
            "context-less short numerics should not match (AU/IN have no fallback regex), got: {:?}",
            short_matches
        );
    }

    #[test]
    fn test_find_postal_codes_reports_short_numeric_with_context() {
        // "PLZ" → German keyword
        let de = "Postanschrift: PLZ 10115 Berlin";
        let m_de = find_postal_codes_in_text(de);
        assert!(
            m_de.iter().any(|m| m.matched_text == "10115"),
            "expected 10115 with German context, got: {:?}",
            m_de
        );

        // "postal code" → English keyword (covers French 75001)
        let fr = "Send to postal code 75001 in Paris";
        let m_fr = find_postal_codes_in_text(fr);
        assert!(
            m_fr.iter().any(|m| m.matched_text == "75001"),
            "expected 75001 with English context, got: {:?}",
            m_fr
        );

        // "PIN code" → Indian keyword
        let in_ = "Office PIN code 110001, New Delhi";
        let m_in = find_postal_codes_in_text(in_);
        assert!(
            m_in.iter().any(|m| m.matched_text == "110001"),
            "expected 110001 with Indian context, got: {:?}",
            m_in
        );
    }

    #[test]
    fn test_find_postal_codes_reports_structural_formats_without_context() {
        // Japanese, Dutch, Brazilian — distinctive enough to skip context gate.
        let jp = "Tokyo HQ 100-0001";
        assert!(
            find_postal_codes_in_text(jp)
                .iter()
                .any(|m| m.matched_text == "100-0001"),
            "expected Japanese match without context"
        );

        let nl = "Office at 1011 AB during business hours";
        assert!(
            find_postal_codes_in_text(nl)
                .iter()
                .any(|m| m.matched_text == "1011 AB"),
            "expected Dutch match without context"
        );

        let br = "Endereço 01001-000 São Paulo";
        assert!(
            find_postal_codes_in_text(br)
                .iter()
                .any(|m| m.matched_text == "01001-000"),
            "expected Brazilian match without context"
        );
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

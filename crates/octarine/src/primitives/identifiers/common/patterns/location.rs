//! Location and address patterns
//!
//! Regex patterns for geographic locations, coordinates, addresses, and postal codes.

// SAFETY: All regex patterns in this module are hardcoded and verified at compile time.

#![allow(clippy::expect_used)]
use once_cell::sync::Lazy;
use regex::Regex;

// ===== GPS Coordinates =====

/// Decimal degrees format
/// Example: "40.7128, -74.0060"
/// Matches: lat (-90 to 90), lon (-180 to 180)
pub static DECIMAL_DEGREES: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
        \b
        [-+]?([1-8]?\d(\.\d+)?|90(\.0+)?)  # Latitude: -90 to 90
        \s*,\s*
        [-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)  # Longitude: -180 to 180
        \b
        ",
    )
    .expect("BUG: Invalid regex pattern")
});

/// Degrees Minutes Seconds (DMS) format
/// Example: "40°42'46.0\"N 74°00'21.6\"W"
pub static DMS_FORMAT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b\d{1,2}°\d{1,2}'[\d.]+"[NS]\s+\d{1,3}°\d{1,2}'[\d.]+"[EW]\b"#)
        .expect("BUG: Invalid regex pattern")
});

/// Labeled latitude
/// Example: "lat: 40.7128", "latitude: 40.7128"
pub static LABELED_LAT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?i:lat|latitude)[\s:=]+[-+]?\d+\.?\d*\b").expect("BUG: Invalid regex pattern")
});

/// Labeled longitude
/// Example: "lon: -74.0060", "lng: -74.0060", "longitude: -74.0060"
pub static LABELED_LON: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?i:lon|lng|longitude)[\s:=]+[-+]?\d+\.?\d*\b")
        .expect("BUG: Invalid regex pattern")
});

// ===== Physical Addresses =====

/// US street address
/// Example: "123 Main Street", "456 Oak Avenue"
pub static US_STREET_ADDRESS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?x)
        \b\d+\s+                                  # Street number
        [A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+        # Street name
        (?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|
           Dr|Drive|Ln|Lane|Way|Ct|Court|Pl|Place)\.?  # Street type
        \b
        ",
    )
    .expect("BUG: Invalid regex pattern")
});

/// PO Box
/// Example: "P.O. Box 12345", "Post Office Box 12345"
pub static PO_BOX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:P\.?O\.?\s*Box|Post\s*Office\s*Box)\s*\d+\b")
        .expect("BUG: Invalid regex pattern")
});

/// Apartment/Suite
/// Example: "Apt 4B", "Suite 200", "Unit #5"
pub static APT_SUITE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:Apt|Apartment|Suite|Ste|Unit|#)\s*[A-Z0-9]+\b")
        .expect("BUG: Invalid regex pattern")
});

// ===== Postal Codes =====

/// US ZIP code (5 digits)
/// Example: "10001"
pub static US_ZIP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{5}\b").expect("BUG: Invalid regex pattern"));

/// US ZIP+4 code
/// Example: "10001-1234"
pub static US_ZIP_PLUS4: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{5}-\d{4}\b").expect("BUG: Invalid regex pattern"));

/// UK postcode
/// Example: "SW1A 1AA", "M1 1AE"
pub static UK_POSTCODE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b").expect("BUG: Invalid regex pattern")
});

/// Canadian postal code
/// Example: "K1A 0B1"
pub static CANADA_POSTAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[A-Z]\d[A-Z]\s*\d[A-Z]\d\b").expect("BUG: Invalid regex pattern"));

pub fn coordinates() -> Vec<&'static Regex> {
    vec![
        &*DECIMAL_DEGREES,
        &*DMS_FORMAT,
        &*LABELED_LAT,
        &*LABELED_LON,
    ]
}

pub fn addresses() -> Vec<&'static Regex> {
    vec![&*US_STREET_ADDRESS, &*PO_BOX, &*APT_SUITE]
}

pub fn postal_codes() -> Vec<&'static Regex> {
    vec![&*US_ZIP_PLUS4, &*US_ZIP, &*UK_POSTCODE, &*CANADA_POSTAL]
}

pub fn all() -> Vec<&'static Regex> {
    let mut patterns = Vec::new();
    patterns.extend(coordinates());
    patterns.extend(addresses());
    patterns.extend(postal_codes());
    patterns
}

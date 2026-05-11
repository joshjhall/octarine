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

/// German postal code (5 digits, full 00000-99999 range allowed by format).
/// Example: "10115" (Berlin)
pub static GERMAN_POSTAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{5}\b").expect("BUG: Invalid regex pattern"));

/// French postal code (5 digits with department code 01-98 in first two positions).
/// Example: "75001" (Paris), "01000" (Bourg-en-Bresse)
pub static FRENCH_POSTAL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:0[1-9]|[1-8]\d|9[0-8])\d{3}\b").expect("BUG: Invalid regex pattern")
});

/// Australian postal code (4 digits). Valid range 0200-9999 enforced in detection.
/// Example: "2000" (Sydney)
pub static AUSTRALIAN_POSTAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{4}\b").expect("BUG: Invalid regex pattern"));

/// Japanese postal code (NNN-NNNN).
/// Example: "100-0001" (Tokyo)
pub static JAPANESE_POSTAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{3}-\d{4}\b").expect("BUG: Invalid regex pattern"));

/// Indian PIN code (6 digits, first digit 1-8 indicates postal zone).
/// Example: "110001" (New Delhi)
pub static INDIAN_POSTAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[1-8]\d{5}\b").expect("BUG: Invalid regex pattern"));

/// Dutch postal code (NNNN AA, space optional, first digit 1-9).
/// Example: "1011 AB" (Amsterdam), "1011AB"
pub static DUTCH_POSTAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[1-9]\d{3}\s?[A-Z]{2}\b").expect("BUG: Invalid regex pattern"));

/// Brazilian CEP (NNNNN-NNN).
/// Example: "01001-000" (São Paulo)
pub static BRAZILIAN_POSTAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{5}-\d{3}\b").expect("BUG: Invalid regex pattern"));

/// Address-context keywords used to disambiguate short numeric postal codes
/// (DE/FR/AU/IN) from phone numbers, prices, years, etc. when scanning free text.
///
/// Matches English ("zip", "postal code", "postcode"), German ("PLZ", "Postleitzahl"),
/// French ("code postal"), Brazilian Portuguese ("CEP"), Indian ("PIN code").
pub static POSTAL_CONTEXT_KEYWORD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(zip|postal[\s_-]?code|postcode|post\s?code|plz|postleitzahl|cep|pin\s?code|code\s?postal)\b",
    )
    .expect("BUG: Invalid regex pattern")
});

/// Patterns matching GPS coordinates (decimal degrees, DMS, and labeled latitude/longitude).
pub fn coordinates() -> Vec<&'static Regex> {
    vec![
        &*DECIMAL_DEGREES,
        &*DMS_FORMAT,
        &*LABELED_LAT,
        &*LABELED_LON,
    ]
}

/// Patterns matching physical addresses (US street addresses, PO boxes, apartment/suite numbers).
pub fn addresses() -> Vec<&'static Regex> {
    vec![&*US_STREET_ADDRESS, &*PO_BOX, &*APT_SUITE]
}

/// Patterns matching postal codes (US ZIP and ZIP+4, UK postcode, Canadian postal code).
///
/// ZIP+4 is matched first so the more specific pattern wins over plain US ZIP.
/// Structurally distinct international codes (JP, NL, BR) are included for direct scanning;
/// short numeric formats (DE, FR, AU, IN) are excluded here and added separately by the
/// detection scanner with context disambiguation to avoid false positives.
pub fn postal_codes() -> Vec<&'static Regex> {
    vec![
        &*US_ZIP_PLUS4,
        &*US_ZIP,
        &*UK_POSTCODE,
        &*CANADA_POSTAL,
        &*JAPANESE_POSTAL,
        &*DUTCH_POSTAL,
        &*BRAZILIAN_POSTAL,
    ]
}

/// Short-numeric international postal code patterns that require address-context
/// keywords nearby to count as a match in free-text scanning. Used by the detection
/// layer's context-aware scanner.
pub fn postal_codes_requiring_context() -> Vec<&'static Regex> {
    vec![
        &*GERMAN_POSTAL,
        &*FRENCH_POSTAL,
        &*AUSTRALIAN_POSTAL,
        &*INDIAN_POSTAL,
    ]
}

/// All location patterns from this module (coordinates, addresses, postal codes).
pub fn all() -> Vec<&'static Regex> {
    let mut patterns = Vec::new();
    patterns.extend(coordinates());
    patterns.extend(addresses());
    patterns.extend(postal_codes());
    patterns.extend(postal_codes_requiring_context());
    patterns
}

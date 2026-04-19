//! Vehicle identification patterns
//!
//! Regex patterns for vehicle identifiers including VIN and license plates.

// SAFETY: All regex patterns in this module are hardcoded and verified at compile time.

#![allow(clippy::expect_used)]
use once_cell::sync::Lazy;
use regex::Regex;

/// VIN (Vehicle Identification Number) with label
/// Captures: prefix + VIN
/// Example: "VIN: 1HGBH41JXMN109186" → groups: ("VIN: ", "1HGBH41JXMN109186")
pub static VIN_LABELED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"((?i:VIN)[\s:#-]*)([A-HJ-NPR-Z0-9]{17})\b").expect("BUG: Invalid regex pattern")
});

/// Explicit VIN mention
/// Example: "VIN 1HGBH41JXMN109186"
pub static VIN_EXPLICIT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:VIN)[\s#:-]*[A-HJ-NPR-Z0-9]{17}\b").expect("BUG: Invalid regex pattern")
});

/// Standalone VIN (17 characters, no prefix)
/// Example: "1HGBH41JXMN109186"
/// Note: Excludes I, O, Q to avoid confusion with 1, 0
pub static VIN_STANDALONE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[A-HJ-NPR-Z0-9]{17}\b").expect("BUG: Invalid regex pattern"));

/// US license plate formats
/// Example: "ABC-1234", "XYZ 5678"
pub static LICENSE_PLATE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Z]{2,3}[-\s]?\d{3,4}[-\s]?[A-Z0-9]{0,2}\b")
        .expect("BUG: Invalid regex pattern")
});

/// All vehicle patterns from this module — labeled, explicit, and standalone
/// 17-character VINs, plus US license plate formats.
pub fn all() -> Vec<&'static Regex> {
    vec![
        &*VIN_LABELED,
        &*VIN_EXPLICIT,
        &*VIN_STANDALONE,
        &*LICENSE_PLATE,
    ]
}

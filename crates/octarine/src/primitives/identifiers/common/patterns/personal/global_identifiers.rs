//! Global / Asia-Pacific personal identifier patterns
//!
//! UK NI / Canada SIN (under `national_id`), Korea RRN, Australia TFN / ABN,
//! and India identifiers (Aadhaar, PAN, GSTIN, vehicle registration, voter ID,
//! passport).

#![allow(clippy::expect_used)]
// SAFETY: All regex patterns in this module are hardcoded and verified at compile time.
// Regex::new() only fails on invalid syntax, which would be caught during development/testing.
// Using expect() here is safe because these patterns are static and never change at runtime.

use once_cell::sync::Lazy;
use regex::Regex;

/// National ID patterns (international)
pub(crate) mod national_id {
    use super::*;

    /// UK National Insurance Number
    /// Example: "AB123456C"
    pub static UK_NI: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b[A-Z]{2}\d{6}[A-Z]\b").expect("BUG: Invalid regex pattern"));

    /// Canadian Social Insurance Number (SIN)
    /// Example: "123-456-789" or "123 456 789"
    pub static CANADA_SIN: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b").expect("BUG: Invalid regex pattern")
    });

    /// Generic national ID with label
    /// Example: "NATIONAL ID: ABC123456789"
    pub static GENERIC: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(?:NATIONAL[\s-]?ID|NID)[\s#:-]*[A-Z0-9]{8,15}\b")
            .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*UK_NI, &*CANADA_SIN, &*GENERIC]
    }
}
/// South Korea Resident Registration Number patterns
pub(crate) mod korea_rrn {
    use super::*;

    /// Korea RRN with dash: YYMMDD-GNNNNNN (13 digits total)
    /// Gender digit 1-8 follows the dash
    pub static WITH_DASH: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b\d{6}-[1-8]\d{6}\b").expect("BUG: Invalid regex pattern"));

    /// Korea RRN with explicit label (with or without dash)
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:RRN|주민등록번호|resident[\s-]?registration)[\s:#-]*(\d{6}-?[1-8]\d{6})\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*WITH_DASH]
    }
}

/// Australian Tax File Number patterns
pub(crate) mod australia_tfn {
    use super::*;

    /// TFN with spaces: NNN NNN NNN (9 digits)
    pub static WITH_SPACES: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b\d{3}\s\d{3}\s\d{3}\b").expect("BUG: Invalid regex pattern"));

    /// TFN with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)\b(?:TFN|tax[\s-]?file[\s-]?number)[\s:#-]*(\d{3}\s?\d{3}\s?\d{3})\b")
            .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*WITH_SPACES]
    }
}

/// Australian Business Number patterns
pub(crate) mod australia_abn {
    use super::*;

    /// ABN with spaces: NN NNN NNN NNN (11 digits)
    pub static WITH_SPACES: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b\d{2}\s\d{3}\s\d{3}\s\d{3}\b").expect("BUG: Invalid regex pattern")
    });

    /// ABN with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:ABN|australian[\s-]?business[\s-]?number)[\s:#-]*(\d{2}\s?\d{3}\s?\d{3}\s?\d{3})\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*WITH_SPACES]
    }
}

/// India Aadhaar number patterns (12 digits, starts with 2-9)
pub(crate) mod india_aadhaar {
    use super::*;

    /// Aadhaar with spaces: NNNN NNNN NNNN (starts with 2-9)
    pub static WITH_SPACES: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b").expect("BUG: Invalid regex pattern")
    });

    /// Aadhaar with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)\b(?:aadhaar|aadhar|UIDAI)[\s:#-]*([2-9]\d{3}\s?\d{4}\s?\d{4})\b")
            .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*WITH_SPACES]
    }
}

/// India PAN (Permanent Account Number) patterns
pub(crate) mod india_pan {
    use super::*;

    /// PAN format: AAAAA9999A (5 letters + 4 digits + 1 letter)
    pub static STANDARD: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b[A-Z]{5}\d{4}[A-Z]\b").expect("BUG: Invalid regex pattern"));

    /// PAN with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:PAN|permanent[\s-]?account[\s-]?number)[\s:#-]*([A-Z]{5}\d{4}[A-Z])\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*STANDARD]
    }
}

/// India GSTIN (Goods and Services Tax Identification Number) patterns
///
/// Format: 15 chars = 2-digit state code + 10-char PAN + entity number (1-9 or A-Z)
/// + literal 'Z' + check character (alphanumeric)
pub(crate) mod india_gstin {
    use super::*;

    /// GSTIN standard format: NN AAAAA NNNN A [1-9A-Z] Z [0-9A-Z]
    pub static STANDARD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// GSTIN with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:GSTIN|GST[\s-]?(?:identification)?[\s-]?(?:number|no\.?))[\s:#-]*(\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z])\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*STANDARD]
    }
}

/// India Vehicle Registration (license plate) patterns
///
/// Format: state code (2 letters) + district code (1-2 digits) + optional series
/// (0-3 letters) + number (1-4 digits). Examples: MH02AB1234, DL1C1234, KA01MA1234.
pub(crate) mod india_vehicle_reg {
    use super::*;

    /// Vehicle registration standard format (no spaces)
    pub static STANDARD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b[A-Z]{2}\d{1,2}[A-Z]{1,3}\d{1,4}\b").expect("BUG: Invalid regex pattern")
    });

    /// Vehicle registration with spaces or hyphens between segments
    pub static WITH_SEPARATORS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b[A-Z]{2}[\s-]\d{1,2}[\s-][A-Z]{1,3}[\s-]\d{1,4}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Vehicle registration with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:vehicle[\s-]?(?:registration|number)|license[\s-]?plate|reg[\s-]?no\.?)[\s:#-]*([A-Z]{2}[\s-]?\d{1,2}[\s-]?[A-Z]{1,3}[\s-]?\d{1,4})\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*WITH_SEPARATORS, &*STANDARD]
    }
}

/// India Voter ID (EPIC - Electors Photo Identity Card) patterns
///
/// Format: 3 letters (state/constituency code) + 7 digits
pub(crate) mod india_voter_id {
    use super::*;

    /// Voter ID standard format
    pub static STANDARD: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b[A-Z]{3}\d{7}\b").expect("BUG: Invalid regex pattern"));

    /// Voter ID with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:voter[\s-]?(?:ID|card|EPIC)?|EPIC|elector(?:'?s)?[\s-]?photo[\s-]?identity[\s-]?card)[\s:#-]*([A-Z]{3}\d{7})\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*STANDARD]
    }
}

/// Indian Passport patterns
///
/// Format: 1 letter (type indicator: P=personal, S=service, D=diplomatic) + 7 digits.
/// STANDARD pattern is short and prone to false positives — finders use LABELED
/// only, while direct `is_india_passport()` checks accept STANDARD.
pub(crate) mod india_passport {
    use super::*;

    /// Indian Passport standard format
    pub static STANDARD: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b[A-Z]\d{7}\b").expect("BUG: Invalid regex pattern"));

    /// Indian Passport with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:indian[\s-]?passport|passport[\s-]?(?:no\.?|number)?|IN[\s-]?passport)[\s:#-]*([A-Z]\d{7})\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    /// Returns patterns used for text scanning (LABELED only — STANDARD is
    /// `[A-Z]\d{7}` which would match many non-passport strings).
    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED]
    }
}

//! Shared regex patterns for identifier detection in text
//!
//! This module provides reusable regex patterns for scanning text documents
//! to find various identifier types. These patterns are used by both detection
//! and sanitization layers.
//!
#![allow(clippy::expect_used)]
//! # Pattern Categories
//!
//! - **SSN**: Social Security Numbers (US)
//! - **Tax IDs**: EIN, TIN, ITIN (US)
//! - **Driver Licenses**: State-specific and generic patterns
//! - **Passports**: International passport numbers
//! - **Employee IDs**: Corporate identification
//! - **Student IDs**: Educational identification
//! - **National IDs**: International identification numbers
//! - **Vehicle IDs**: VIN and license plates
//!
//! # Design Principles
//!
//! - **Conservative matching**: Prefer false negatives over false positives
//! - **Context aware**: Use capture groups to preserve surrounding text
//! - **Performance**: Use lazy_static for one-time compilation
//! - **Extensibility**: Easy to add new patterns per identifier type

// SAFETY: All regex patterns in this module are hardcoded and verified at compile time.
// Regex::new() only fails on invalid syntax, which would be caught during development/testing.
// Using expect() here is safe because these patterns are static and never change at runtime.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

/// SSN (Social Security Number) patterns
pub mod ssn {
    use super::*;

    /// SSN with explicit label (highest confidence)
    /// Captures: prefix (label) + number
    /// Example: "SSN: 123-45-6789" → groups: ("SSN: ", "123-45-6789")
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(\b(?i:SSN|Social[\s-]?Security)[\s:#-]*)(\d{3}-?\d{2}-?\d{4}\b)")
            .expect("BUG: Invalid regex pattern")
    });

    /// SSN with dashes (high confidence)
    /// Example: "123-45-6789"
    pub static WITH_DASHES: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("BUG: Invalid regex pattern"));

    /// SSN with spaces (high confidence)
    /// Example: "123 45 6789"
    pub static WITH_SPACES: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b\d{3}\s\d{2}\s\d{4}\b").expect("BUG: Invalid regex pattern"));

    /// SSN exact match pattern (for validation)
    /// Example: "123-45-6789" or "123456789"
    pub static EXACT: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\d{3}-?\d{2}-?\d{4}$").expect("BUG: Invalid regex pattern"));

    /// Returns all SSN patterns in priority order
    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*WITH_DASHES, &*WITH_SPACES]
    }
}

/// Tax ID patterns (EIN, TIN, ITIN)
pub mod tax_id {
    use super::*;

    /// Tax ID with explicit label (highest confidence)
    /// Captures: prefix (label) + number
    /// Example: "EIN: 12-3456789" → groups: ("EIN: ", "12-3456789")
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(\b(?:Company |)(?:TIN|EIN|ITIN)[\s#:-]+)(\d{2}-?\d{7}|\d{9})\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// EIN with dash format (high confidence)
    /// Example: "12-3456789"
    pub static EIN_FORMAT: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b\d{2}-\d{7}\b").expect("BUG: Invalid regex pattern"));

    /// ITIN (starts with 9)
    /// Example: "912-34-5678"
    pub static ITIN_FORMAT: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b9\d{2}-?\d{2}-?\d{4}\b").expect("BUG: Invalid regex pattern"));

    /// Generic TIN with prefix
    pub static GENERIC_TIN: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(?:TIN|EIN|ITIN)[\s#:-]*\d{2}-?\d{7}\b").expect("BUG: Invalid regex pattern")
    });

    /// Federal EIN (FEIN)
    pub static FEIN: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(?:FEIN|Federal[\s-]?EIN)[\s#:-]*\d{2}-?\d{7}\b")
            .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![
            &*LABELED,
            &*EIN_FORMAT,
            &*ITIN_FORMAT,
            &*GENERIC_TIN,
            &*FEIN,
        ]
    }
}

/// Driver's license patterns
pub mod driver_license {
    use super::*;

    /// Generic driver's license pattern with context
    /// Captures: prefix (label) + number
    /// Example: "DL# A1234567" → groups: ("DL# ", "A1234567")
    pub static GENERIC: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b((?i:DL|LICENSE|LIC)[\s#:-]*)([A-Z0-9]{6,15})\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// State-specific patterns (US)
    pub fn state_patterns() -> HashMap<&'static str, Regex> {
        let mut patterns = HashMap::new();
        patterns.insert(
            "CA",
            Regex::new(r"\b[A-Z]\d{7}\b").expect("BUG: Invalid regex pattern"),
        ); // California
        patterns.insert(
            "TX",
            Regex::new(r"\b\d{8}\b").expect("BUG: Invalid regex pattern"),
        ); // Texas
        patterns.insert(
            "NY",
            Regex::new(r"\b[A-Z]\d{7}|[A-Z]\d{18}\b").expect("BUG: Invalid regex pattern"),
        ); // New York
        patterns.insert(
            "FL",
            Regex::new(r"\b[A-Z]\d{12}\b").expect("BUG: Invalid regex pattern"),
        ); // Florida
        patterns
    }
}

/// Passport patterns
pub mod passport {
    use super::*;

    /// Explicit passport mention (highest confidence)
    /// Examples: "Passport: 123456789", "Passport number: 123456789", "Passport No: 123456789"
    pub static EXPLICIT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(?i:passport)(?:\s+(?:number|no|num|#))?[\s#:-]+\d{8,9}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Passport with PP prefix
    /// Captures: prefix + number
    /// Example: "PP# 987654321" → groups: ("PP# ", "987654321")
    pub static WITH_PREFIX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b((?i:pp)[\s#:-]*)(\d{9})\b").expect("BUG: Invalid regex pattern")
    });

    /// Generic passport format (letter + digits)
    /// Example: "C12345678"
    /// Note: Lower confidence, needs context checking
    pub static GENERIC: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b([A-Z]\d{6,9})\b").expect("BUG: Invalid regex pattern"));

    pub fn all() -> Vec<&'static Regex> {
        vec![&*EXPLICIT, &*WITH_PREFIX, &*GENERIC]
    }
}

/// Employee ID patterns
pub mod employee_id {
    use super::*;

    /// Employee ID with explicit prefix
    /// Example: "EMP00123", "Employee: 12345"
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(?:EMP|EMPLOYEE|STAFF)[\s#:-]*[A-Z0-9]{4,12}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Badge number
    /// Example: "BADGE# 98765"
    pub static BADGE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(?:BADGE|ID)[\s#:-]*\d{4,10}\b").expect("BUG: Invalid regex pattern")
    });

    /// E-number format (common in corporations)
    /// Example: "E123456"
    pub static E_NUMBER: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b[Ee]\d{5,8}\b").expect("BUG: Invalid regex pattern"));

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*BADGE, &*E_NUMBER]
    }
}

/// Student ID patterns
pub mod student_id {
    use super::*;

    /// Student ID with explicit prefix
    /// Example: "STUDENT# 1234567"
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(?:STUDENT|STU|STUD)[\s#:-]*[A-Z0-9]{6,12}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// S-number format (common in universities)
    /// Example: "S12345678"
    pub static S_NUMBER: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b[Ss]\d{7,9}\b").expect("BUG: Invalid regex pattern"));

    /// Formatted with dashes
    /// Example: "123-45-6789"
    /// Note: Overlaps with SSN format, needs context
    pub static WITH_DASHES: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("BUG: Invalid regex pattern"));

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*S_NUMBER, &*WITH_DASHES]
    }
}

/// National ID patterns (international)
pub mod national_id {
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
pub mod korea_rrn {
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
pub mod australia_tfn {
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
pub mod australia_abn {
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
pub mod india_aadhaar {
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
pub mod india_pan {
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

pub mod personal_name {
    use super::*;

    /// First Last (with optional middle initial/name)
    /// Example: "John Smith", "Mary Jane Doe", "Bob A. Wilson"
    /// **Warning**: High false positive rate - matches any capitalized words
    pub static FIRST_LAST: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b[A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]+\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Last, First (with optional middle)
    /// Example: "Smith, John", "Doe, Mary Jane"
    pub static LAST_FIRST: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b[A-Z][a-z]+,\s*[A-Z][a-z]+(?:\s+[A-Z]\.?)?\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Labeled name
    /// Example: "Name: John Smith", "Patient: Mary Doe"
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i:name|patient|client|customer)[\s:]+([A-Z][a-z]+\s+[A-Z][a-z]+)")
            .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*LAST_FIRST, &*FIRST_LAST]
    }
}

/// Birthdate and date patterns
///
/// Supports multiple date formats commonly used for birthdates.
pub mod birthdate {
    use super::*;

    /// ISO format: YYYY-MM-DD
    /// Example: "1990-05-15", "2000-12-31"
    pub static ISO_FORMAT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(19|20)\d{2}[-.](0[1-9]|1[0-2])[-.](0[1-9]|[12]\d|3[01])\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// US format: MM/DD/YYYY or MM-DD-YYYY
    /// Example: "05/15/1990", "12-31-2000"
    pub static US_FORMAT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(0[1-9]|1[0-2])[/\-](0[1-9]|[12]\d|3[01])[/\-](19|20)\d{2}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// European format: DD/MM/YYYY or DD-MM-YYYY
    /// Example: "15/05/1990", "31-12-2000"
    pub static EU_FORMAT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(0[1-9]|[12]\d|3[01])[/\-](0[1-9]|1[0-2])[/\-](19|20)\d{2}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Month name format: "Month DD, YYYY"
    /// Example: "January 15, 1990", "Dec 31, 2000"
    pub static MONTH_NAME: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?x)
            \b(January|February|March|April|May|June|July|August|September|October|November|December|
               Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)
            \s+(0?[1-9]|[12]\d|3[01]),?\s+(19|20)\d{2}\b
            ",
        )
        .expect("BUG: Invalid regex pattern")
    });

    /// Day-Month-Year with abbreviated month name
    /// Example: "15-Jan-1990", "15 Jan 1990", "1 Feb 2000"
    pub static DAY_MONTH_ABBREV: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?x)
            \b(0?[1-9]|[12]\d|3[01])[-.\s]
            (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[-.\s]?
            (19|20)\d{2}\b
            ",
        )
        .expect("BUG: Invalid regex pattern")
    });

    /// Year-first with slashes: YYYY/MM/DD
    /// Example: "1990/01/15", "2000/12/31"
    pub static YEAR_FIRST_SLASH: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(19|20)\d{2}/(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Two-digit year (US-style): MM/DD/YY or MM-DD-YY
    /// Example: "01/15/90", "12-31-00"
    pub static TWO_DIGIT_YEAR: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(0[1-9]|1[0-2])[/\-](0[1-9]|[12]\d|3[01])[/\-]\d{2}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// ISO format with time portion (date part extracted)
    /// Example: "1990-01-15T10:30:00", "2023-06-15T08:00:00Z"
    pub static ISO_WITH_TIME: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(19|20)\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T\d{2}:\d{2}")
            .expect("BUG: Invalid regex pattern")
    });

    /// Labeled birthdate
    /// Example: "DOB: 1990-05-15", "Born: May 15, 1990"
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i:dob|birthdate|born|birth)[\s:]+([0-9/\-]{8,10}|[A-Za-z]+\s+\d{1,2},?\s+\d{4})",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![
            &*LABELED,
            &*MONTH_NAME,
            &*DAY_MONTH_ABBREV,
            &*ISO_WITH_TIME,
            &*ISO_FORMAT,
            &*YEAR_FIRST_SLASH,
            &*US_FORMAT,
            &*EU_FORMAT,
            &*TWO_DIGIT_YEAR,
        ]
    }
}

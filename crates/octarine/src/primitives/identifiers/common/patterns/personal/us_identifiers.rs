//! US-centric personal identifier patterns
//!
//! SSN, tax IDs (EIN/TIN/ITIN), driver licenses (state-specific), passports,
//! employee IDs, and student IDs.

#![allow(clippy::expect_used)]
// SAFETY: All regex patterns in this module are hardcoded and verified at compile time.
// Regex::new() only fails on invalid syntax, which would be caught during development/testing.
// Using expect() here is safe because these patterns are static and never change at runtime.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

/// SSN (Social Security Number) patterns
pub(crate) mod ssn {
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
pub(crate) mod tax_id {
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

    /// ITIN — loose 9XX-XX-XXXX shape (kept for SSN-vs-tax-ID bucketing in
    /// `tax_id` detection). Does NOT enforce the IRS middle-group rule and so
    /// will match non-ITIN 9XX strings. Use [`ITIN_FORMAT_STRICT`] for
    /// identification as `IdentifierType::Itin`.
    /// Example: "912-34-5678" (matches even though group 34 is not a valid IRS middle group)
    pub static ITIN_FORMAT: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b9\d{2}-?\d{2}-?\d{4}\b").expect("BUG: Invalid regex pattern"));

    /// ITIN — strict IRS layout. Area `9XX`, middle group in `{50-65, 70-88,
    /// 90-92, 94-99}`. Per IRS Publication 1915 and 26 CFR §301.6109-1.
    /// Example: "900-70-0001" (valid), "912-34-5678" (group 34 — does NOT match)
    pub static ITIN_FORMAT_STRICT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b9\d{2}-?(?:5[0-9]|6[0-5]|7[0-9]|8[0-8]|9[02]|9[4-9])-?\d{4}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// ITIN — strict exact-match (no surrounding text). For validators.
    pub static ITIN_FORMAT_STRICT_EXACT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^9\d{2}-?(?:5[0-9]|6[0-5]|7[0-9]|8[0-8]|9[02]|9[4-9])-?\d{4}$")
            .expect("BUG: Invalid regex pattern")
    });

    /// ITIN with explicit label (highest confidence)
    /// Captures: prefix (label) + number
    /// Example: "ITIN: 900-70-0001" → groups: ("ITIN: ", "900-70-0001")
    pub static ITIN_LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(\b(?:ITIN|Individual[\s-]?Taxpayer[\s-]?Identification[\s-]?Number)[\s#:-]+)(9\d{2}-?(?:5[0-9]|6[0-5]|7[0-9]|8[0-8]|9[02]|9[4-9])-?\d{4})\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

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
pub(crate) mod driver_license {
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
pub(crate) mod passport {
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
pub(crate) mod employee_id {
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
pub(crate) mod student_id {
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

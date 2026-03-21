//! Medical identification patterns
//!
//! Regex patterns for medical identifiers including MRN, insurance numbers,
//! NPI, ICD-10, and CPT codes.

// SAFETY: All regex patterns in this module are hardcoded and verified at compile time.
#![allow(clippy::expect_used)]

use once_cell::sync::Lazy;
use regex::Regex;

/// Medical Record Number (MRN) patterns - LABELED
/// Detects: "MRN: 12345678", "Patient ID: 987654321", "Medical Record #456789"
pub static MRN_LABELED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:MRN|medical[\s-]?record|patient[\s-]?id|pt[\s-]?id)[\s:#-]*\d{6,12}\b")
        .expect("BUG: Invalid regex pattern")
});

/// Medical Record Number (MRN) patterns - UNLABELED
/// Detects raw MRN values: "PAT_789012", "MR-123456", "123456789", "ABC-123-DEF"
/// Used for validation of individual identifiers without labels
/// Lenient pattern - validation layer adds strict checks
pub static MRN_UNLABELED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Z0-9][A-Z0-9_-]{3,19}$").expect("BUG: Invalid regex pattern"));

/// Health insurance patterns - Medicare (labeled)
/// Detects Medicare format: 1-3 letters + 6 digits + optional letter/digit
pub static INSURANCE_MEDICARE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[A-Z]{1,3}\d{6}[A-Z0-9]?\b").expect("BUG: Invalid regex pattern"));

/// Policy/Member number patterns - LABELED
pub static INSURANCE_POLICY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:policy|member|subscriber)[\s-]?(?:number|id|#)[\s:#-]*[A-Z0-9]{8,20}\b")
        .expect("BUG: Invalid regex pattern")
});

/// Group number pattern - LABELED
pub static INSURANCE_GROUP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:group)[\s-]?(?:number|#)[\s:#-]*[A-Z0-9]{4,15}\b")
        .expect("BUG: Invalid regex pattern")
});

/// Insurance number - UNLABELED
/// Detects raw insurance values: "ABC123456789", "H12345678", "GRP-4567", "A12345"
/// Lenient pattern - validation layer adds strict length checks
pub static INSURANCE_UNLABELED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Z0-9][A-Z0-9-]{4,24}$").expect("BUG: Invalid regex pattern"));

/// Prescription number pattern - LABELED
/// Detects: "RX# 123456789", "Prescription Number: 987654", "rx 456789012"
pub static PRESCRIPTION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:rx|prescription)[\s-]?(?:number|#)?[\s:#-]*\d{6,12}\b")
        .expect("BUG: Invalid regex pattern")
});

/// Prescription number - UNLABELED
/// Detects raw prescription values: "RX-123456", "123456789", "CVS-123-456", "RX1234"
/// Lenient pattern - validation layer adds strict length checks
pub static PRESCRIPTION_UNLABELED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?i)(?:[A-Z]{2,4}[_-])?[A-Z0-9][A-Z0-9_-]{3,19}$")
        .expect("BUG: Invalid regex pattern")
});

/// Provider identifier (NPI) pattern - LABELED
/// NPI is exactly 10 digits starting with 1 or 2
/// Reference: https://www.cms.gov/Regulations-and-Guidance/Administrative-Simplification/NationalProvIdentStand
pub static NPI: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:NPI|national[\s-]?provider)[\s:#-]*[12]\d{9}\b")
        .expect("BUG: Invalid regex pattern")
});

/// Provider identifier (NPI) - UNLABELED
/// Raw NPI: exactly 10 digits starting with 1 or 2
pub static NPI_UNLABELED: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[12]\d{9}$").expect("BUG: Invalid regex pattern"));

/// ICD-10 medical codes (diagnosis codes)
/// Format: Letter (A-T, V-Z) + 2 digits + optional decimal + 0-4 more digits + optional letter
/// Reference: https://www.who.int/standards/classifications/classification-of-diseases
pub static ICD10: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-TV-Z]\d{2}\.?\d{0,4}[A-Z]?\b").expect("BUG: Invalid regex pattern")
});

/// CPT procedure codes (5 digits)
/// Reference: https://www.ama-assn.org/practice-management/cpt
pub static CPT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(?:CPT)[\s:#-]*\d{5}\b").expect("BUG: Invalid regex pattern"));

pub fn mrn() -> Vec<&'static Regex> {
    vec![&*MRN_LABELED]
}

pub fn insurance() -> Vec<&'static Regex> {
    vec![&*INSURANCE_MEDICARE, &*INSURANCE_POLICY, &*INSURANCE_GROUP]
}

pub fn prescriptions() -> Vec<&'static Regex> {
    vec![&*PRESCRIPTION]
}

pub fn provider_ids() -> Vec<&'static Regex> {
    vec![&*NPI]
}

pub fn medical_codes() -> Vec<&'static Regex> {
    vec![&*ICD10, &*CPT]
}

pub fn all() -> Vec<&'static Regex> {
    vec![
        &*MRN_LABELED,
        &*INSURANCE_MEDICARE,
        &*INSURANCE_POLICY,
        &*INSURANCE_GROUP,
        &*PRESCRIPTION,
        &*NPI,
        &*ICD10,
        &*CPT,
    ]
}

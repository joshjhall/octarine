//! European national-identifier detection — Spain (NIF/NIE), Italy (Codice
//! Fiscale), Finland (HETU), Poland (PESEL).
//!
//! Per-country `is_*` / `find_*_in_text` pairs only; checksum validation
//! lives in `super::super::validation`.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Check if a value matches Finland HETU format
#[must_use]
pub fn is_finland_hetu(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::finland_hetu::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Finland HETU patterns in text
#[must_use]
pub fn find_finland_hetus_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::finland_hetu::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::FinlandHetu,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Spain NIF format
#[must_use]
pub fn is_spain_nif(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::spain_nif::all().iter().any(|p| p.is_match(value))
}

/// Find all Spain NIF patterns in text
#[must_use]
pub fn find_spain_nifs_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::spain_nif::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::SpainNif,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Spain NIE format
#[must_use]
pub fn is_spain_nie(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::spain_nie::all().iter().any(|p| p.is_match(value))
}

/// Find all Spain NIE patterns in text
#[must_use]
pub fn find_spain_nies_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::spain_nie::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::SpainNie,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Italy Codice Fiscale format
#[must_use]
pub fn is_italy_fiscal_code(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::italy_fiscal_code::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Italy Codice Fiscale patterns in text
#[must_use]
pub fn find_italy_fiscal_codes_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::italy_fiscal_code::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::ItalyFiscalCode,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Poland PESEL format
#[must_use]
pub fn is_poland_pesel(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::poland_pesel::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Poland PESEL patterns in text
#[must_use]
pub fn find_poland_pesels_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::poland_pesel::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::PolandPesel,
            ));
        }
    }

    deduplicate_matches(matches)
}

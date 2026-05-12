//! Brazil CPF and CNPJ detection
//!
//! - CPF: 11 digits in `NNN.NNN.NNN-NN` or plain form (Brazilian personal tax ID).
//! - CNPJ: 14 digits in `NN.NNN.NNN/NNNN-NN` or plain form (Brazilian corporate ID).

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Check if a value matches Brazil CPF format
#[must_use]
pub fn is_brazil_cpf(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    // Accept plain 11-digit form for direct checks (only text scanning is
    // restricted to labeled/formatted to avoid false positives).
    if value.chars().filter(|c| c.is_ascii_digit()).count() == 11
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | ' '))
    {
        return true;
    }
    patterns::brazil_cpf::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Brazil CPF patterns in text
#[must_use]
pub fn find_brazil_cpfs_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::brazil_cpf::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::BrazilCpf,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Brazil CNPJ format
#[must_use]
pub fn is_brazil_cnpj(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    if value.chars().filter(|c| c.is_ascii_digit()).count() == 14
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | '/' | ' '))
    {
        return true;
    }
    patterns::brazil_cnpj::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Brazil CNPJ patterns in text
#[must_use]
pub fn find_brazil_cnpjs_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::brazil_cnpj::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::BrazilCnpj,
            ));
        }
    }

    deduplicate_matches(matches)
}

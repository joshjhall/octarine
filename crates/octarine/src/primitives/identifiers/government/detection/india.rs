//! India identifier detection — Aadhaar, PAN, GSTIN, vehicle registration,
//! voter ID (EPIC), and Indian passports.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Check if a value matches India Aadhaar format (12 digits, starts with 2-9)
#[must_use]
pub fn is_india_aadhaar(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::india_aadhaar::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Check if a value matches India PAN format (AAAAA9999A)
#[must_use]
pub fn is_india_pan(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::india_pan::all().iter().any(|p| p.is_match(value))
}

/// Find all India Aadhaar patterns in text
#[must_use]
pub fn find_india_aadhaars_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::india_aadhaar::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::IndiaAadhaar,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all India PAN patterns in text
#[must_use]
pub fn find_india_pans_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::india_pan::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::IndiaPan,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches India GSTIN format (15 chars: state + PAN + entity + Z + check)
#[must_use]
pub fn is_india_gstin(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::india_gstin::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all India GSTIN patterns in text
#[must_use]
pub fn find_india_gstins_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::india_gstin::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::IndiaGstin,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches India vehicle registration format
#[must_use]
pub fn is_india_vehicle_registration(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::india_vehicle_reg::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all India vehicle registration patterns in text
#[must_use]
pub fn find_india_vehicle_registrations_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::india_vehicle_reg::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::IndiaVehicleReg,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches India Voter ID (EPIC) format (3 letters + 7 digits)
#[must_use]
pub fn is_india_voter_id(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::india_voter_id::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all India Voter ID patterns in text
#[must_use]
pub fn find_india_voter_ids_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::india_voter_id::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::IndiaVoterId,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Indian passport format (letter + 7 digits)
///
/// Accepts STANDARD pattern `[A-Z]\d{7}` for direct value checks — text scans
/// use LABELED only (see `find_india_passports_in_text`).
#[must_use]
pub fn is_india_passport(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::india_passport::STANDARD.is_match(value)
        || patterns::india_passport::LABELED.is_match(value)
}

/// Find all Indian passport patterns in text
///
/// Uses LABELED patterns only — the STANDARD format `[A-Z]\d{7}` is too short
/// to scan safely (high false-positive rate against arbitrary strings).
#[must_use]
pub fn find_india_passports_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::india_passport::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::IndiaPassport,
            ));
        }
    }

    deduplicate_matches(matches)
}

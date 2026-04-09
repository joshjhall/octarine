//! Government-issued identifier detection (primitives layer)
//!
//! Pure detection functions for government identifiers with no observe dependencies.
//! Used by observe/pii and security modules.
//!
//! # Supported Identifiers
//!
//! - **SSN**: US Social Security Numbers (XXX-XX-XXXX format)
//! - **Tax IDs**: EIN, TIN, ITIN (IRS identifiers)
//! - **Driver's License**: State-specific formats (CA, TX, etc.)
//! - **Passport**: Federal/State Department issued
//! - **National IDs**: UK NI, Canadian SIN, etc.
//! - **Vehicle IDs**: VIN (17-character NHTSA/ISO format)
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns data, no side effects
//! - Used by observe/pii and security modules
//!
//! # Detection Types
//!
//! 1. **Single-value detection** (`is_*`): Validate one identifier format
//! 2. **Text scanning** (`find_*_in_text`): Find all matches in documents

use super::super::common::patterns;
use super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};
use super::validation::{is_itin_area, is_test_ssn};

// ============================================================================
// Constants
// ============================================================================

/// Maximum input length for ReDoS protection
///
/// Inputs longer than this are rejected to prevent regex denial of service.
const MAX_INPUT_LENGTH: usize = 10_000;

/// Maximum single identifier length
///
/// Individual identifiers (SSN, Driver License, etc.) shouldn't exceed this.
const MAX_IDENTIFIER_LENGTH: usize = 100;

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract the full match from a regex capture.
///
/// # Safety
/// Capture group 0 always exists per regex spec - it's the full match.
/// This function encapsulates the expect() call with proper justification.
#[allow(clippy::expect_used)]
fn get_full_match<'a>(capture: &'a regex::Captures<'a>) -> regex::Match<'a> {
    capture
        .get(0)
        .expect("BUG: capture group 0 always exists per regex spec")
}

/// Deduplicate overlapping matches (keep longest/highest confidence)
///
/// When multiple patterns match the same text position, keep only the best match:
/// - Prefer longer matches (more specific)
/// - Prefer higher confidence
/// - Prefer earlier position as tiebreaker
fn deduplicate_matches(mut matches: Vec<IdentifierMatch>) -> Vec<IdentifierMatch> {
    if matches.is_empty() {
        return matches;
    }

    // Sort by start position, then by length (descending), then by confidence
    matches.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| b.len().cmp(&a.len())) // Longer first
            .then_with(|| b.confidence.cmp(&a.confidence)) // Higher confidence first
    });

    let mut deduped = Vec::new();
    let mut last_end = 0;

    for m in matches {
        // If this match doesn't overlap with the previous one, keep it
        if m.start >= last_end {
            last_end = m.end;
            deduped.push(m);
        }
        // Otherwise, it overlaps and we skip it (we already kept the better match)
    }

    deduped
}

/// Check if input exceeds safe length for regex processing
///
/// Used for ReDoS protection in text scanning functions.
#[inline]
fn exceeds_safe_length(input: &str, max_len: usize) -> bool {
    input.len() > max_len
}

// ============================================================================
// SSN False Positive Filtering
// ============================================================================

/// Extract only ASCII digits from a string
fn extract_digits(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Check if an SSN candidate passes SSA structural rules
///
/// Rejects known-invalid patterns per Social Security Administration rules:
/// - Area 000 (never assigned)
/// - Area 666 (never assigned)
/// - Group 00 (never assigned)
/// - Serial 0000 (never assigned)
/// - Known test/advertising SSNs and sequential/repeating patterns
///
/// Does NOT reject area 900-999 (ITINs) — caller handles reclassification.
fn is_valid_ssn_candidate(matched_text: &str) -> bool {
    let digits = extract_digits(matched_text);
    if digits.len() != 9 {
        return false;
    }

    let area = &digits[0..3];
    let group = &digits[3..5];
    let serial = &digits[5..9];

    // SSA Rule: Area 000 is never valid
    if area == "000" {
        return false;
    }

    // SSA Rule: Area 666 is reserved/never issued
    if area == "666" {
        return false;
    }

    // SSA Rule: Group 00 is invalid
    if group == "00" {
        return false;
    }

    // SSA Rule: Serial 0000 is invalid
    if serial == "0000" {
        return false;
    }

    // Reject test/advertising/sequential/repeating patterns
    if is_test_ssn(matched_text) {
        return false;
    }

    true
}

// ============================================================================
// Single-Value Detection (Format Validation)
// ============================================================================

/// Check if a value matches SSN format and passes SSA structural rules
///
/// Validates format (XXX-XX-XXXX or variants) and rejects known-invalid
/// patterns: area 000/666, group 00, serial 0000, test SSNs, and ITINs (900-999).
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// assert!(detection::is_ssn("517-29-8346"));
/// assert!(detection::is_ssn("628 41 9053"));
/// assert!(!detection::is_ssn("000-12-3456")); // Invalid area
/// assert!(!detection::is_ssn("900-70-1234")); // ITIN, not SSN
/// ```
#[must_use]
pub fn is_ssn(value: &str) -> bool {
    if !patterns::ssn::all().iter().any(|p| p.is_match(value)) {
        return false;
    }

    let digits = extract_digits(value);
    if digits.len() != 9 {
        return false;
    }

    // Reclassify ITINs (area 900-999) — not SSNs
    if is_itin_area(value) {
        return false;
    }

    is_valid_ssn_candidate(value)
}

/// Check if a value matches tax ID format (EIN, TIN, ITIN)
#[must_use]
pub fn is_tax_id(value: &str) -> bool {
    patterns::tax_id::all().iter().any(|p| p.is_match(value))
}

/// Check if a value matches driver's license format
///
/// Supports state-specific formats and generic patterns.
#[must_use]
pub fn is_driver_license(value: &str) -> bool {
    // Check generic pattern
    if patterns::driver_license::GENERIC.is_match(value) {
        return true;
    }

    // Check state-specific patterns
    patterns::driver_license::state_patterns()
        .values()
        .any(|p| p.is_match(value))
}

/// Check if a value matches passport format
#[must_use]
pub fn is_passport(value: &str) -> bool {
    patterns::passport::all().iter().any(|p| p.is_match(value))
}

/// Check if a value matches national ID format
#[must_use]
pub fn is_national_id(value: &str) -> bool {
    patterns::national_id::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Check if a value matches VIN format
#[must_use]
pub fn is_vehicle_id(value: &str) -> bool {
    patterns::vehicle_id::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Check if a value matches South Korea RRN format
///
/// Validates the YYMMDD-GNNNNNN format where G is a gender/century digit (1-8).
/// Does NOT validate the checksum — use `validate_korea_rrn_with_checksum` for that.
#[must_use]
pub fn is_korea_rrn(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::korea_rrn::WITH_DASH.is_match(value)
}

/// Check if a value matches Australian TFN format (8-9 digits)
#[must_use]
pub fn is_australia_tfn(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::australia_tfn::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Check if a value matches Australian ABN format (11 digits)
#[must_use]
pub fn is_australia_abn(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::australia_abn::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Australian TFN patterns in text
#[must_use]
pub fn find_australia_tfns_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::australia_tfn::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::AustraliaTfn,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all Australian ABN patterns in text
#[must_use]
pub fn find_australia_abns_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::australia_abn::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::AustraliaAbn,
            ));
        }
    }

    deduplicate_matches(matches)
}

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

/// Check if a value matches Singapore NRIC/FIN format
#[must_use]
pub fn is_singapore_nric(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::singapore_nric::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Singapore NRIC/FIN patterns in text
#[must_use]
pub fn find_singapore_nrics_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::singapore_nric::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::SingaporeNric,
            ));
        }
    }

    deduplicate_matches(matches)
}

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

/// Detect which type of government identifier a value is
///
/// Returns the specific identifier type if detected, or None if not a government ID.
/// Checks in order: SSN, Tax ID, Driver License, Passport, National ID, Vehicle ID.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
/// use crate::primitives::identifiers::types::IdentifierType;
///
/// assert_eq!(detection::detect_government_identifier("517-29-8346"), Some(IdentifierType::Ssn));
/// assert_eq!(detection::detect_government_identifier("00-0000001"), Some(IdentifierType::TaxId));
/// assert_eq!(detection::detect_government_identifier("not an id"), None);
/// ```
#[must_use]
pub fn detect_government_identifier(value: &str) -> Option<IdentifierType> {
    if is_ssn(value) {
        Some(IdentifierType::Ssn)
    } else if is_tax_id(value) {
        Some(IdentifierType::TaxId)
    } else if is_driver_license(value) {
        Some(IdentifierType::DriverLicense)
    } else if is_passport(value) {
        Some(IdentifierType::Passport)
    } else if is_korea_rrn(value) {
        Some(IdentifierType::KoreaRrn)
    } else if is_australia_tfn(value) {
        Some(IdentifierType::AustraliaTfn)
    } else if is_australia_abn(value) {
        Some(IdentifierType::AustraliaAbn)
    } else if is_india_aadhaar(value) {
        Some(IdentifierType::IndiaAadhaar)
    } else if is_india_pan(value) {
        Some(IdentifierType::IndiaPan)
    } else if is_singapore_nric(value) {
        Some(IdentifierType::SingaporeNric)
    } else if is_finland_hetu(value) {
        Some(IdentifierType::FinlandHetu)
    } else if is_poland_pesel(value) {
        Some(IdentifierType::PolandPesel)
    } else if is_italy_fiscal_code(value) {
        Some(IdentifierType::ItalyFiscalCode)
    } else if is_spain_nif(value) {
        Some(IdentifierType::SpainNif)
    } else if is_spain_nie(value) {
        Some(IdentifierType::SpainNie)
    } else if is_national_id(value) {
        Some(IdentifierType::NationalId)
    } else if is_vehicle_id(value) {
        Some(IdentifierType::VehicleId)
    } else {
        None
    }
}

/// Check if value is any government identifier
#[must_use]
pub fn is_government_identifier(value: &str) -> bool {
    detect_government_identifier(value).is_some()
}

/// Check if text contains any government identifier
#[must_use]
pub fn is_government_present(text: &str) -> bool {
    !find_all_government_ids_in_text(text).is_empty()
}

// ============================================================================
// Text Scanning (Find All Matches in Documents)
// ============================================================================

/// Find all SSN patterns in text with false positive filtering
///
/// Scans text for Social Security Number patterns and filters out:
/// - Invalid SSA patterns (area 000/666, group 00, serial 0000)
/// - Known test/advertising SSNs (078-05-1120, 123-45-6789, etc.)
/// - Sequential and repeating digit patterns
/// - ITINs (area 900-999) — reclassified as `IdentifierType::TaxId`
///
/// Labeled patterns ("SSN: ...") get High confidence; bare patterns get Medium.
///
/// # Returns
///
/// Vector of matches with position, text, and confidence level.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "Employee SSN: 517-29-8346";
/// let matches = detection::find_ssns_in_text(text);
/// assert_eq!(matches.len(), 1);
/// ```
#[must_use]
pub fn find_ssns_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for (pattern_idx, pattern) in patterns::ssn::all().iter().enumerate() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            let matched_text = full_match.as_str();

            // Reclassify ITINs (area 900-999) as TaxId
            if is_itin_area(matched_text) {
                matches.push(IdentifierMatch::high_confidence(
                    full_match.start(),
                    full_match.end(),
                    matched_text.to_string(),
                    IdentifierType::TaxId,
                ));
                continue;
            }

            // Filter out false positives using SSA structural rules
            if !is_valid_ssn_candidate(matched_text) {
                continue;
            }

            // Labeled patterns (index 0) get High confidence; bare patterns get Medium
            let confidence = if pattern_idx == 0 {
                DetectionConfidence::High
            } else {
                DetectionConfidence::Medium
            };

            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                matched_text.to_string(),
                IdentifierType::Ssn,
                confidence,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all tax ID patterns in text (EIN, TIN, ITIN)
///
/// Scans for:
/// - EIN (Employer Identification Number): "00-0000001"
/// - TIN (Taxpayer Identification Number)
/// - ITIN (Individual Taxpayer ID): "9XX-XX-XXXX"
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "Company EIN: 00-0000001";
/// let matches = detection::find_tax_ids_in_text(text);
/// assert_eq!(matches.len(), 1);
/// ```
#[must_use]
pub fn find_tax_ids_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::tax_id::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::TaxId,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all driver's license patterns in text
///
/// Detects both state-specific and generic patterns:
/// - California: "A1234567"
/// - Texas: "12345678"
/// - Generic: "DL# A1234567", "LICENSE: B9876543"
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "Driver License: CA A1234567";
/// let matches = detection::find_driver_licenses_in_text(text);
/// assert!(!matches.is_empty());
/// ```
#[must_use]
pub fn find_driver_licenses_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    // Check state-specific patterns
    for (_state, pattern) in patterns::driver_license::state_patterns() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::DriverLicense,
            ));
        }
    }

    // Check generic pattern
    for capture in patterns::driver_license::GENERIC.captures_iter(text) {
        let full_match = get_full_match(&capture);
        matches.push(IdentifierMatch::high_confidence(
            full_match.start(),
            full_match.end(),
            full_match.as_str().to_string(),
            IdentifierType::DriverLicense,
        ));
    }

    deduplicate_matches(matches)
}

/// Find all passport patterns in text
///
/// Detects:
/// - Explicit mentions: "Passport: 123456789", "Passport number: 123456789"
/// - With prefix: "PP# 987654321"
/// - Generic format: "C12345678" (with context checking)
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "Passport number: 123456789";
/// let matches = detection::find_passports_in_text(text);
/// assert_eq!(matches.len(), 1);
/// ```
#[must_use]
pub fn find_passports_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for (i, pattern) in patterns::passport::all().iter().enumerate() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);

            // For generic pattern (index 2), check context
            let confidence = if i == 2 {
                // Generic pattern needs context checking
                if is_likely_passport_context(text, full_match.as_str()) {
                    DetectionConfidence::High
                } else {
                    DetectionConfidence::Medium
                }
            } else {
                DetectionConfidence::High
            };

            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::Passport,
                confidence,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a match is likely a passport based on surrounding context
fn is_likely_passport_context(text: &str, potential_passport: &str) -> bool {
    let context_keywords = ["passport", "pp", "travel", "document", "identification"];

    // Look for keywords near the potential passport (within ~20 chars)
    let passport_pos = text.find(potential_passport).unwrap_or(0);
    let start = passport_pos.saturating_sub(20);
    let end = passport_pos
        .saturating_add(potential_passport.len())
        .saturating_add(20)
        .min(text.len());
    let context = &text[start..end].to_lowercase();

    context_keywords
        .iter()
        .any(|&keyword| context.contains(keyword))
}

/// Find all South Korea RRN patterns in text
///
/// Detects Korean Resident Registration Numbers in YYMMDD-GNNNNNN format.
///
/// # Returns
///
/// Vector of matches with position, text, and confidence level.
#[must_use]
pub fn find_korea_rrns_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::korea_rrn::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::KoreaRrn,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all national ID patterns in text
///
/// Detects international national identification numbers:
/// - UK National Insurance: "AB123456C"
/// - Canadian SIN: "123-456-789"
/// - Generic national IDs
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "UK NI: AB123456C";
/// let matches = detection::find_national_ids_in_text(text);
/// assert!(!matches.is_empty());
/// ```
#[must_use]
pub fn find_national_ids_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::national_id::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::NationalId,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all vehicle ID patterns in text (VIN, license plates)
///
/// Detects:
/// - VIN (Vehicle Identification Number): 17-character regulated format
/// - License plates: Various US formats
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "VIN: 1HGBH41JXMN109186";
/// let matches = detection::find_vehicle_ids_in_text(text);
/// assert_eq!(matches.len(), 1);
/// ```
#[must_use]
pub fn find_vehicle_ids_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::vehicle_id::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::VehicleId,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all government-issued ID patterns in text
///
/// Comprehensive scan for all government ID types:
/// - SSN, tax IDs, driver's licenses, passports, national IDs, vehicle IDs
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "SSN: 517-29-8346, VIN: 1HGBH41JXMN109186";
/// let matches = detection::find_all_government_ids_in_text(text);
/// assert!(matches.len() >= 2);
/// ```
#[must_use]
pub fn find_all_government_ids_in_text(text: &str) -> Vec<IdentifierMatch> {
    let mut all_matches = Vec::new();

    all_matches.extend(find_ssns_in_text(text));
    all_matches.extend(find_tax_ids_in_text(text));
    all_matches.extend(find_driver_licenses_in_text(text));
    all_matches.extend(find_passports_in_text(text));
    all_matches.extend(find_korea_rrns_in_text(text));
    all_matches.extend(find_australia_tfns_in_text(text));
    all_matches.extend(find_australia_abns_in_text(text));
    all_matches.extend(find_india_aadhaars_in_text(text));
    all_matches.extend(find_india_pans_in_text(text));
    all_matches.extend(find_singapore_nrics_in_text(text));
    all_matches.extend(find_finland_hetus_in_text(text));
    all_matches.extend(find_poland_pesels_in_text(text));
    all_matches.extend(find_italy_fiscal_codes_in_text(text));
    all_matches.extend(find_spain_nifs_in_text(text));
    all_matches.extend(find_spain_nies_in_text(text));
    all_matches.extend(find_national_ids_in_text(text));
    all_matches.extend(find_vehicle_ids_in_text(text));

    // Sort by position in text
    all_matches.sort_by_key(|m| m.start);

    all_matches
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== Single-Value Detection Tests =====

    #[test]
    fn test_is_ssn() {
        // Valid SSNs
        assert!(is_ssn("517-29-8346"));
        assert!(is_ssn("628 41 9053"));

        // Invalid: no separators
        assert!(!is_ssn("234567890"));
        assert!(!is_ssn("invalid"));
    }

    #[test]
    fn test_is_ssn_rejects_invalid_area() {
        assert!(!is_ssn("000-12-3456")); // Area 000 never assigned
        assert!(!is_ssn("666-12-3456")); // Area 666 never assigned
    }

    #[test]
    fn test_is_ssn_rejects_invalid_group_serial() {
        assert!(!is_ssn("234-00-5678")); // Group 00 never assigned
        assert!(!is_ssn("234-56-0000")); // Serial 0000 never assigned
    }

    #[test]
    fn test_is_ssn_rejects_test_patterns() {
        assert!(!is_ssn("123-45-6789")); // Sequential
        assert!(!is_ssn("078-05-1120")); // Woolworth's advertising SSN
        assert!(!is_ssn("219-09-9999")); // SSA example
        assert!(!is_ssn("457-55-5462")); // IRS example
        assert!(!is_ssn("111-11-1111")); // Repeating digits
        assert!(!is_ssn("555-55-5555")); // Repeating digits
    }

    #[test]
    fn test_is_ssn_rejects_itin_range() {
        // 900-999 area codes are ITINs, not SSNs
        assert!(!is_ssn("900-70-1234"));
        assert!(!is_ssn("912-34-5678"));
        assert!(!is_ssn("999-88-7654"));
    }

    #[test]
    fn test_is_tax_id() {
        assert!(is_tax_id("00-0000001"));
        assert!(is_tax_id("912-34-5678")); // ITIN
        assert!(!is_tax_id("invalid"));
    }

    #[test]
    fn test_is_driver_license() {
        assert!(is_driver_license("A1234567")); // CA format
        assert!(is_driver_license("12345678")); // TX format
        assert!(!is_driver_license("invalid"));
    }

    #[test]
    fn test_is_passport() {
        assert!(is_passport("C12345678"));
        assert!(!is_passport("invalid"));
    }

    #[test]
    fn test_is_national_id() {
        assert!(is_national_id("AB123456C")); // UK NI
        assert!(is_national_id("123-456-789")); // Canadian SIN
        assert!(!is_national_id("invalid"));
    }

    #[test]
    fn test_is_vehicle_id() {
        assert!(is_vehicle_id("1HGBH41JXMN109186")); // VIN
        assert!(!is_vehicle_id("invalid"));
    }

    #[test]
    fn test_is_government_identifier() {
        assert!(is_government_identifier("517-29-8346")); // SSN
        assert!(is_government_identifier("00-0000001")); // EIN
        assert!(is_government_identifier("1HGBH41JXMN109186")); // VIN
        assert!(!is_government_identifier("not an id"));
    }

    #[test]
    fn test_detect_government_identifier() {
        assert_eq!(
            detect_government_identifier("517-29-8346"),
            Some(IdentifierType::Ssn)
        );
        assert_eq!(
            detect_government_identifier("00-0000001"),
            Some(IdentifierType::TaxId)
        );
        assert_eq!(
            detect_government_identifier("1HGBH41JXMN109186"),
            Some(IdentifierType::VehicleId)
        );
        assert_eq!(detect_government_identifier("not an id"), None);
    }

    #[test]
    fn test_detect_is_consistency() {
        // Verify: is_government_identifier(x) == detect_government_identifier(x).is_some()
        let test_values = [
            "517-29-8346",       // SSN (valid)
            "00-0000001",        // Tax ID
            "A1234567",          // Driver License
            "C12345678",         // Passport
            "AB123456C",         // National ID
            "1HGBH41JXMN109186", // VIN
            "not an id",         // Invalid
            "",                  // Empty
        ];

        for value in test_values {
            assert_eq!(
                is_government_identifier(value),
                detect_government_identifier(value).is_some(),
                "Consistency check failed for: {}",
                value
            );
        }
    }

    // ===== Text Scanning Tests =====

    #[test]
    fn test_find_ssns_in_text() {
        let text = "Employee SSN: 517-29-8346 and contractor SSN: 142-58-3697";
        let matches = find_ssns_in_text(text);
        assert_eq!(matches.len(), 2);
        let first = matches.first().expect("Should detect SSN patterns");
        assert_eq!(first.identifier_type, IdentifierType::Ssn);
        // Labeled matches get High confidence
        assert_eq!(first.confidence, DetectionConfidence::High);
    }

    #[test]
    fn test_find_ssns_bare_pattern_medium_confidence() {
        let text = "The number is 517-29-8346 in the file";
        let matches = find_ssns_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect bare SSN");
        assert_eq!(first.confidence, DetectionConfidence::Medium);
    }

    #[test]
    fn test_find_ssns_rejects_false_positives() {
        // These should all be filtered out
        let text = "area 000-12-3456 and 666-12-3456 and 234-00-5678 and 234-56-0000";
        let matches = find_ssns_in_text(text);
        assert_eq!(matches.len(), 0, "Should reject all invalid SSN patterns");
    }

    #[test]
    fn test_find_ssns_rejects_test_patterns() {
        let text = "test 123-45-6789 and 078-05-1120 and 111-11-1111";
        let matches = find_ssns_in_text(text);
        assert_eq!(matches.len(), 0, "Should reject test/advertising SSNs");
    }

    #[test]
    fn test_find_ssns_reclassifies_itin() {
        let text = "ITIN holder SSN: 900-70-1234 and 912-34-5678";
        let matches = find_ssns_in_text(text);
        // Both should be reclassified as TaxId
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::TaxId),
            "900-999 area codes should be classified as TaxId, not Ssn"
        );
        assert!(
            !matches.is_empty(),
            "ITINs should still be detected as TaxId"
        );
    }

    #[test]
    fn test_find_tax_ids_in_text() {
        let text = "Company EIN: 00-0000001";
        let matches = find_tax_ids_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect tax ID pattern");
        assert_eq!(first.identifier_type, IdentifierType::TaxId);
    }

    #[test]
    fn test_find_driver_licenses_in_text() {
        let text = "Driver License: CA A1234567";
        let matches = find_driver_licenses_in_text(text);
        assert!(!matches.is_empty());
        let first = matches
            .first()
            .expect("Should detect driver license pattern");
        assert_eq!(first.identifier_type, IdentifierType::DriverLicense);
    }

    #[test]
    fn test_find_passports_in_text() {
        let text = "Passport: 123456789";
        let matches = find_passports_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect passport pattern");
        assert_eq!(first.identifier_type, IdentifierType::Passport);
    }

    #[test]
    fn test_find_national_ids_in_text() {
        let text = "UK NI: AB123456C";
        let matches = find_national_ids_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect national ID pattern");
        assert_eq!(first.identifier_type, IdentifierType::NationalId);
    }

    #[test]
    fn test_find_vehicle_ids_in_text() {
        let text = "VIN: 1HGBH41JXMN109186";
        let matches = find_vehicle_ids_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect vehicle ID pattern");
        assert_eq!(first.identifier_type, IdentifierType::VehicleId);
    }

    #[test]
    fn test_find_all_government_ids() {
        let text = "SSN: 517-29-8346, VIN: 1HGBH41JXMN109186, EIN: 00-0000001";
        let matches = find_all_government_ids_in_text(text);
        assert!(matches.len() >= 3);

        // Verify sorted by position
        for window in matches.windows(2) {
            let [prev, curr] = window else { continue };
            assert!(curr.start >= prev.start);
        }
    }

    #[test]
    fn test_no_matches_in_clean_text() {
        let text = "This text contains no government IDs";
        let matches = find_all_government_ids_in_text(text);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_is_government_present() {
        assert!(is_government_present("SSN: 517-29-8346"));
        assert!(!is_government_present("No government IDs here"));
    }

    // ===== Edge Case Tests =====

    #[test]
    fn test_empty_input() {
        assert!(!is_ssn(""));
        assert!(!is_tax_id(""));
        assert!(!is_driver_license(""));
        assert!(!is_passport(""));
        assert!(!is_national_id(""));
        assert!(!is_vehicle_id(""));
        assert_eq!(find_all_government_ids_in_text("").len(), 0);
    }

    #[test]
    fn test_deduplicate_matches() {
        let matches = vec![
            IdentifierMatch::high_confidence(0, 10, "test1".into(), IdentifierType::Ssn),
            IdentifierMatch::high_confidence(0, 15, "test1long".into(), IdentifierType::Ssn),
            IdentifierMatch::high_confidence(20, 30, "test2".into(), IdentifierType::Ssn),
        ];

        let deduped = deduplicate_matches(matches);
        assert_eq!(deduped.len(), 2);
        let first = deduped.first().expect("Should have first match");
        let second = deduped.get(1).expect("Should have second match");
        assert_eq!(first.matched_text, "test1long");
        assert_eq!(second.matched_text, "test2");
    }
}

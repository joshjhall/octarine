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
// Single-Value Detection (Format Validation)
// ============================================================================

/// Check if a value matches SSN format
///
/// Validates format only (XXX-XX-XXXX or variants), not authenticity.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// assert!(detection::is_ssn("900-00-0001"));
/// assert!(detection::is_ssn("123 45 6789"));
/// assert!(!detection::is_ssn("900000001")); // No separators
/// ```
#[must_use]
pub fn is_ssn(value: &str) -> bool {
    patterns::ssn::all().iter().any(|p| p.is_match(value))
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
/// assert_eq!(detection::detect_government_identifier("900-00-0001"), Some(IdentifierType::Ssn));
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

/// Find all SSN patterns in text
///
/// Scans text for Social Security Number patterns with various formats:
/// - Labeled: "SSN: 900-00-0001"
/// - With dashes: "900-00-0001"
/// - With spaces: "123 45 6789"
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
/// let text = "Employee SSN: 900-00-0001";
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

    for pattern in patterns::ssn::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::Ssn,
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
/// let text = "SSN: 900-00-0001, VIN: 1HGBH41JXMN109186";
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
        assert!(is_ssn("900-00-0001"));
        assert!(is_ssn("123 45 6789"));
        assert!(!is_ssn("900000001")); // No separators
        assert!(!is_ssn("invalid"));
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
        assert!(is_government_identifier("900-00-0001")); // SSN
        assert!(is_government_identifier("00-0000001")); // EIN
        assert!(is_government_identifier("1HGBH41JXMN109186")); // VIN
        assert!(!is_government_identifier("not an id"));
    }

    #[test]
    fn test_detect_government_identifier() {
        assert_eq!(
            detect_government_identifier("900-00-0001"),
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
            "900-00-0001",       // SSN
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
        let text = "Employee SSN: 900-00-0001 and contractor SSN: 900-00-0002";
        let matches = find_ssns_in_text(text);
        assert_eq!(matches.len(), 2);
        let first = matches.first().expect("Should detect SSN patterns");
        assert_eq!(first.identifier_type, IdentifierType::Ssn);
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
        let text = "SSN: 900-00-0001, VIN: 1HGBH41JXMN109186, EIN: 00-0000001";
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
        assert!(is_government_present("SSN: 900-00-0001"));
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

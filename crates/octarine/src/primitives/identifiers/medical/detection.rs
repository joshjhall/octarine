//! Medical identifier detection (primitives layer)
//!
//! Pure detection functions for medical identifiers with no observe dependencies.
//! Used by observe/pii and security modules.
//!
//! # Supported Identifiers
//!
//! - **Medical Record Numbers (MRN)**: Patient ID, medical record numbers
//! - **Health Insurance**: Policy, member, group numbers, Medicare format
//! - **Prescriptions**: RX/prescription numbers
//! - **Provider IDs**: NPI (National Provider Identifier)
//! - **Medical Codes**: ICD-10 diagnosis codes, CPT procedure codes
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns data, no side effects
//! - Used by observe/pii and security modules
//!
//! # HIPAA Compliance
//!
//! All identifiers in this module are Protected Health Information (PHI):
//! - 45 CFR 164.514(b)(2) - De-identification standard
//! - Medical record numbers are direct identifiers
//! - Requires removal or redaction under HIPAA Safe Harbor

use super::super::common::patterns;
use super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};
use crate::primitives::collections::LruCache;
use once_cell::sync::Lazy;
use std::time::Duration;

// ============================================================================
// Constants
// ============================================================================

/// Maximum input length for ReDoS protection
///
/// Inputs longer than this are rejected to prevent regex denial of service.
const MAX_INPUT_LENGTH: usize = 10_000;

/// Maximum single identifier length
///
/// Individual identifiers (MRN, NPI, etc.) shouldn't exceed this.
const MAX_IDENTIFIER_LENGTH: usize = 100;

// ============================================================================
// Caching Infrastructure
// ============================================================================

/// Cache for NPI validation results
///
/// Caches up to 5,000 NPI validations for 1 hour.
static NPI_CACHE: Lazy<LruCache<String, bool>> =
    Lazy::new(|| LruCache::new(5_000, Duration::from_secs(3600)));

/// Get NPI cache statistics
///
/// Returns cache hit/miss stats for performance monitoring.
#[must_use]
pub fn npi_cache_stats() -> crate::primitives::collections::CacheStats {
    NPI_CACHE.stats()
}

/// Clear all medical detection caches
///
/// Useful for testing or when memory pressure is high.
pub fn clear_medical_caches() {
    NPI_CACHE.clear();
}

/// Check if NPI is a known test/sample pattern
///
/// Detects common test NPI numbers used for development:
/// - Sequential patterns (1234567890)
/// - Repeated digits (1111111111)
/// - Common test patterns from CMS documentation
#[must_use]
pub fn is_test_npi(npi: &str) -> bool {
    let digits_only: String = npi.chars().filter(|c| c.is_ascii_digit()).collect();

    // Common test patterns
    let test_patterns = [
        "1234567890",
        "1111111111",
        "2222222222",
        "9999999999",
        "1234567893", // Common example in CMS documentation
        "1000000001", // Sequential test pattern
    ];

    test_patterns.contains(&digits_only.as_str())
}

/// Check if MRN is a known test/sample pattern
///
/// Detects common test MRN patterns used in development/testing:
/// - Sequential patterns (MRN-123456)
/// - All zeros or all nines
/// - Common test prefixes
#[must_use]
pub fn is_test_mrn(mrn: &str) -> bool {
    let upper = mrn.to_uppercase();
    let digits_only: String = mrn.chars().filter(|c| c.is_ascii_digit()).collect();

    // Test prefixes
    if upper.starts_with("TEST") || upper.starts_with("DEMO") || upper.starts_with("SAMPLE") {
        return true;
    }

    // All same digit patterns
    if digits_only.len() >= 6 && digits_only.chars().all(|c| c == '0' || c == '9') {
        return true;
    }

    // Sequential test patterns
    if digits_only.contains("123456") || digits_only.contains("654321") {
        return true;
    }

    false
}

/// Check if insurance number is a known test/sample pattern
///
/// Detects common test insurance patterns:
/// - Test prefixes (TEST, DEMO, SAMPLE)
/// - All zeros/nines
/// - Sequential patterns
#[must_use]
pub fn is_test_insurance(insurance: &str) -> bool {
    let upper = insurance.to_uppercase();
    let digits_only: String = insurance.chars().filter(|c| c.is_ascii_digit()).collect();

    // Test prefixes
    if upper.starts_with("TEST")
        || upper.starts_with("DEMO")
        || upper.starts_with("SAMPLE")
        || upper.starts_with("XXX")
    {
        return true;
    }

    // All same digit patterns
    if digits_only.len() >= 6 && digits_only.chars().all(|c| c == '0' || c == '9') {
        return true;
    }

    // Sequential patterns
    if digits_only.contains("123456") || digits_only.contains("654321") {
        return true;
    }

    false
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract the full match from a regex capture.
///
/// # Safety
/// Capture group 0 always exists per regex spec - it's the full match.
#[allow(clippy::expect_used)]
fn get_full_match<'a>(capture: &'a regex::Captures<'a>) -> regex::Match<'a> {
    capture
        .get(0)
        .expect("BUG: capture group 0 always exists per regex spec")
}

/// Check if input exceeds safe length for regex processing
#[inline]
fn exceeds_safe_length(input: &str, max_len: usize) -> bool {
    input.len() > max_len
}

// ============================================================================
// Single-Value Detection
// ============================================================================

/// Detect medical identifier type
///
/// Returns the type of medical identifier detected, or None if not recognized.
#[must_use]
pub fn detect_medical_identifier(value: &str) -> Option<IdentifierType> {
    if is_provider_id(value) {
        return Some(IdentifierType::ProviderID);
    }
    if is_medical_record_number(value) {
        return Some(IdentifierType::MedicalRecordNumber);
    }
    if is_health_insurance(value) {
        return Some(IdentifierType::HealthInsurance);
    }
    if is_prescription(value) {
        return Some(IdentifierType::Prescription);
    }
    if is_medical_code(value) {
        return Some(IdentifierType::MedicalCode);
    }
    None
}

/// Check if value is a medical identifier
#[must_use]
pub fn is_medical_identifier(value: &str) -> bool {
    detect_medical_identifier(value).is_some()
}

/// Check if value is a medical record number
///
/// Checks both labeled ("MRN: 12345678") and unlabeled ("PAT_789012") formats.
///
/// # Examples
///
/// ```ignore
/// assert!(is_medical_record_number("MRN: 12345678"));  // Labeled
/// assert!(is_medical_record_number("PAT_789012"));     // Unlabeled
/// assert!(is_medical_record_number("123456789"));      // Raw digits
/// assert!(!is_medical_record_number("not a record"));
/// ```
#[must_use]
pub fn is_medical_record_number(value: &str) -> bool {
    let trimmed = value.trim();

    // ReDoS protection
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }

    // Check both labeled and unlabeled patterns
    patterns::medical::MRN_LABELED.is_match(trimmed)
        || patterns::medical::MRN_UNLABELED.is_match(trimmed)
}

/// Check if value is health insurance information
///
/// Checks both labeled ("Policy Number: ABC123") and unlabeled ("ABC123456789") formats.
///
/// # Examples
///
/// ```ignore
/// assert!(is_health_insurance("Policy Number: ABC123456789"));  // Labeled
/// assert!(is_health_insurance("ABC123456789"));                 // Unlabeled
/// assert!(!is_health_insurance("not insurance"));
/// ```
#[must_use]
pub fn is_health_insurance(value: &str) -> bool {
    let trimmed = value.trim();

    // ReDoS protection
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }

    // Check both labeled and unlabeled patterns
    patterns::medical::INSURANCE_MEDICARE.is_match(trimmed)
        || patterns::medical::INSURANCE_POLICY.is_match(trimmed)
        || patterns::medical::INSURANCE_GROUP.is_match(trimmed)
        || patterns::medical::INSURANCE_UNLABELED.is_match(trimmed)
}

/// Check if value is a prescription number
///
/// Checks both labeled ("RX# 123456") and unlabeled ("RX-123456", "123456789") formats.
///
/// # Examples
///
/// ```ignore
/// assert!(is_prescription("RX# 123456789"));      // Labeled
/// assert!(is_prescription("RX-123456"));          // Unlabeled with prefix
/// assert!(is_prescription("123456789"));          // Raw digits
/// assert!(!is_prescription("not a prescription"));
/// ```
#[must_use]
pub fn is_prescription(value: &str) -> bool {
    let trimmed = value.trim();

    // ReDoS protection
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }

    // Check both labeled and unlabeled patterns
    patterns::medical::PRESCRIPTION.is_match(trimmed)
        || patterns::medical::PRESCRIPTION_UNLABELED.is_match(trimmed)
}

/// Check if value is a provider ID (NPI)
///
/// Checks both labeled ("NPI: 1234567890") and unlabeled ("1234567890") formats.
/// NPI must be exactly 10 digits starting with 1 or 2.
///
/// # Examples
///
/// ```ignore
/// assert!(is_provider_id("NPI: 1234567890"));    // Labeled
/// assert!(is_provider_id("1234567890"));         // Unlabeled
/// assert!(!is_provider_id("3123456789"));        // Must start with 1 or 2
/// ```
#[must_use]
pub fn is_provider_id(value: &str) -> bool {
    let trimmed = value.trim();

    // ReDoS protection
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }

    // Check both labeled and unlabeled patterns
    patterns::medical::NPI.is_match(trimmed) || patterns::medical::NPI_UNLABELED.is_match(trimmed)
}

/// Check if value is a medical code (ICD-10, CPT)
///
/// # Examples
///
/// ```ignore
/// assert!(is_medical_code("A01.1"));      // ICD-10
/// assert!(is_medical_code("CPT: 99213")); // CPT
/// assert!(!is_medical_code("not a code"));
/// ```
#[must_use]
pub fn is_medical_code(value: &str) -> bool {
    let trimmed = value.trim();

    // ReDoS protection
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }

    patterns::medical::ICD10.is_match(trimmed) || patterns::medical::CPT.is_match(trimmed)
}

/// Check if text contains any medical identifier
#[must_use]
pub fn is_medical_identifier_present(value: &str) -> bool {
    is_medical_identifier(value) || is_medical_present(value)
}

// ============================================================================
// Text Scanning (Find Multiple Matches in Documents)
// ============================================================================

/// Find all medical record numbers in text
///
/// Scans text for MRN patterns and returns all matches with positions.
/// Includes ReDoS protection for large inputs.
#[must_use]
pub fn find_mrns_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::medical::mrn() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::MedicalRecordNumber,
                DetectionConfidence::High,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all health insurance IDs in text
///
/// Scans text for insurance ID patterns and returns all matches with positions.
/// Includes ReDoS protection for large inputs.
#[must_use]
pub fn find_insurance_ids_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::medical::insurance() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::HealthInsurance,
                DetectionConfidence::High,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all prescription numbers in text
///
/// Scans text for prescription patterns and returns all matches with positions.
/// Includes ReDoS protection for large inputs.
#[must_use]
pub fn find_prescriptions_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::medical::prescriptions() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::Prescription,
                DetectionConfidence::High,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all provider IDs (NPI) in text
///
/// Scans text for NPI patterns and returns all matches with positions.
/// Includes ReDoS protection for large inputs.
#[must_use]
pub fn find_provider_ids_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::medical::provider_ids() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::ProviderID,
                DetectionConfidence::High,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all medical codes (ICD-10, CPT) in text
///
/// Scans text for medical code patterns and returns all matches with positions.
/// Includes ReDoS protection for large inputs.
///
/// # Security Considerations
///
/// Medical codes may reveal diagnoses (PHI under HIPAA).
/// Consider context when deciding whether to redact.
#[must_use]
pub fn find_medical_codes_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::medical::medical_codes() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::MedicalCode,
                DetectionConfidence::High,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all medical identifiers in text
///
/// Comprehensive scanner that returns all medical identifier types in one pass:
/// MRN, insurance, prescriptions, provider IDs, medical codes.
#[must_use]
pub fn find_all_medical_in_text(text: &str) -> Vec<IdentifierMatch> {
    let mut all_matches = Vec::new();

    all_matches.extend(find_mrns_in_text(text));
    all_matches.extend(find_insurance_ids_in_text(text));
    all_matches.extend(find_prescriptions_in_text(text));
    all_matches.extend(find_provider_ids_in_text(text));
    all_matches.extend(find_medical_codes_in_text(text));

    deduplicate_matches(all_matches)
}

/// Check if text contains any medical identifier
#[must_use]
pub fn is_medical_present(text: &str) -> bool {
    !find_all_medical_in_text(text).is_empty()
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Deduplicate overlapping matches (keep longest/highest confidence)
fn deduplicate_matches(mut matches: Vec<IdentifierMatch>) -> Vec<IdentifierMatch> {
    if matches.is_empty() {
        return matches;
    }

    // Sort by position, then length (descending), then confidence
    matches.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| b.len().cmp(&a.len()))
            .then_with(|| b.confidence.cmp(&a.confidence))
    });

    let mut deduped = Vec::new();
    let mut last_end = 0;

    for m in matches {
        if m.start >= last_end {
            last_end = m.end;
            deduped.push(m);
        }
    }

    deduped
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use serial_test::serial;

    // ===== Single-Value Detection Tests =====

    #[test]
    fn test_is_medical_record_number() {
        assert!(is_medical_record_number("MRN: 12345678"));
        assert!(is_medical_record_number("Patient ID: 987654321"));
        assert!(is_medical_record_number("pt-id: 456789"));
        assert!(!is_medical_record_number("not a record number"));
    }

    #[test]
    fn test_is_health_insurance() {
        assert!(is_health_insurance("Policy Number: ABC123456789"));
        assert!(is_health_insurance("Member ID: XYZ987654"));
        assert!(is_health_insurance("Group #: GRP12345"));
        assert!(!is_health_insurance("not insurance"));
    }

    #[test]
    fn test_is_prescription() {
        assert!(is_prescription("RX# 123456789"));
        assert!(is_prescription("Prescription Number: 987654"));
        assert!(is_prescription("rx 456789012"));
        assert!(!is_prescription("not a prescription"));
    }

    #[test]
    fn test_is_provider_id() {
        assert!(is_provider_id("NPI: 1234567890"));
        assert!(is_provider_id("NPI: 2987654321"));
        assert!(!is_provider_id("NPI: 3123456789")); // Must start with 1 or 2
        assert!(!is_provider_id("not a provider id"));
    }

    #[test]
    fn test_is_medical_code() {
        assert!(is_medical_code("A01.1"));
        assert!(is_medical_code("Z12.31"));
        assert!(is_medical_code("CPT: 99213"));
        assert!(!is_medical_code("not a code"));
    }

    #[test]
    fn test_detect_medical_identifier() {
        assert_eq!(
            detect_medical_identifier("MRN: 12345678"),
            Some(IdentifierType::MedicalRecordNumber)
        );
        assert_eq!(
            detect_medical_identifier("NPI: 1234567890"),
            Some(IdentifierType::ProviderID)
        );
        assert_eq!(detect_medical_identifier("not medical"), None);
    }

    // ===== Text Scanning Tests =====

    #[test]
    fn test_find_mrns_in_text() {
        let text = "Patient MRN: 12345678 and Medical Record: 987654321";
        let matches = find_mrns_in_text(text);
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("Should have match").identifier_type,
            IdentifierType::MedicalRecordNumber
        );
    }

    #[test]
    fn test_find_insurance_ids_in_text() {
        let text = "Policy Number: ABC123456789, Member ID: XYZ987654";
        let matches = find_insurance_ids_in_text(text);
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("Should have match").identifier_type,
            IdentifierType::HealthInsurance
        );
    }

    #[test]
    fn test_find_prescriptions_in_text() {
        let text = "RX# 123456789 and Prescription Number: 987654";
        let matches = find_prescriptions_in_text(text);
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("Should have match").identifier_type,
            IdentifierType::Prescription
        );
    }

    #[test]
    fn test_find_provider_ids_in_text() {
        let text = "Doctor NPI: 1234567890 and Provider NPI: 2987654321";
        let matches = find_provider_ids_in_text(text);
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("Should have match").identifier_type,
            IdentifierType::ProviderID
        );
    }

    #[test]
    fn test_find_medical_codes_in_text() {
        let text = "Diagnosis: A01.1, Procedure CPT: 99213";
        let matches = find_medical_codes_in_text(text);
        assert!(matches.len() >= 2);
        assert_eq!(
            matches.first().expect("Should have match").identifier_type,
            IdentifierType::MedicalCode
        );
    }

    #[test]
    fn test_find_all_medical_in_text() {
        let text = "MRN: 12345678, NPI: 1234567890, RX# 987654";
        let matches = find_all_medical_in_text(text);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_no_matches_in_clean_text() {
        let text = "This text contains no medical identifiers";
        assert_eq!(find_mrns_in_text(text).len(), 0);
        assert_eq!(find_insurance_ids_in_text(text).len(), 0);
        assert_eq!(find_prescriptions_in_text(text).len(), 0);
        assert_eq!(find_provider_ids_in_text(text).len(), 0);
        assert_eq!(find_medical_codes_in_text(text).len(), 0);
    }

    #[test]
    fn test_is_medical_present() {
        assert!(is_medical_present("Patient MRN: 12345678"));
        assert!(!is_medical_present("No medical data here"));
    }

    // ===== Test Pattern Detection =====

    #[test]
    fn test_is_test_npi() {
        assert!(is_test_npi("1234567890"));
        assert!(is_test_npi("1111111111"));
        assert!(!is_test_npi("1245319599")); // Valid real-looking NPI
    }

    // ===== Cache Tests =====

    #[test]
    #[serial]
    fn test_npi_cache_stats() {
        clear_medical_caches();
        let stats = npi_cache_stats();
        assert_eq!(stats.size, 0);
    }

    // ===== Deduplication Tests =====

    #[test]
    fn test_deduplicate_matches() {
        let matches = vec![
            IdentifierMatch::high_confidence(
                0,
                10,
                "test1".to_string(),
                IdentifierType::MedicalRecordNumber,
            ),
            IdentifierMatch::high_confidence(
                0,
                15,
                "test1long".to_string(),
                IdentifierType::MedicalRecordNumber,
            ),
            IdentifierMatch::high_confidence(
                20,
                30,
                "test2".to_string(),
                IdentifierType::Prescription,
            ),
        ];

        let deduped = deduplicate_matches(matches);
        assert_eq!(deduped.len(), 2);
        assert_eq!(
            deduped.first().expect("Should have first").matched_text,
            "test1long"
        );
        assert_eq!(
            deduped.get(1).expect("Should have second").matched_text,
            "test2"
        );
    }

    // ===== Edge Case Tests =====

    #[test]
    fn test_empty_input() {
        assert!(!is_medical_record_number(""));
        assert!(!is_health_insurance(""));
        assert!(!is_prescription(""));
        assert!(!is_provider_id(""));
        assert!(!is_medical_code(""));
        assert_eq!(find_all_medical_in_text("").len(), 0);
    }

    #[test]
    fn test_whitespace_handling() {
        // Leading/trailing whitespace should be trimmed
        assert!(is_medical_record_number("  MRN: 12345678  "));
        assert!(is_provider_id("  NPI: 1234567890  "));

        // Whitespace-only should not match
        assert!(!is_medical_record_number("   "));
        assert!(!is_provider_id("\t\n"));
    }

    #[test]
    fn test_redos_protection() {
        // Long inputs should be rejected for ReDoS protection
        let long_input = "a".repeat(MAX_IDENTIFIER_LENGTH + 1);
        assert!(!is_medical_record_number(&long_input));
        assert!(!is_health_insurance(&long_input));
        assert!(!is_prescription(&long_input));
        assert!(!is_provider_id(&long_input));
        assert!(!is_medical_code(&long_input));

        // Very long text should return empty for text scanning
        let very_long_text = "a".repeat(MAX_INPUT_LENGTH + 1);
        assert_eq!(find_mrns_in_text(&very_long_text).len(), 0);
        assert_eq!(find_insurance_ids_in_text(&very_long_text).len(), 0);
        assert_eq!(find_provider_ids_in_text(&very_long_text).len(), 0);
    }

    #[test]
    fn test_mixed_case() {
        // Case-insensitive detection
        assert!(is_medical_record_number("mrn: 12345678"));
        assert!(is_medical_record_number("MRN: 12345678"));
        assert!(is_medical_record_number("Mrn: 12345678"));

        assert!(is_prescription("rx# 123456789"));
        assert!(is_prescription("RX# 123456789"));

        assert!(is_provider_id("npi: 1234567890"));
        assert!(is_provider_id("NPI: 1234567890"));
    }

    #[test]
    fn test_boundary_lengths() {
        // MRN: 6-12 digits
        assert!(is_medical_record_number("MRN: 123456")); // 6 digits
        assert!(is_medical_record_number("MRN: 123456789012")); // 12 digits

        // NPI: exactly 10 digits
        assert!(is_provider_id("NPI: 1234567890")); // 10 digits
        assert!(!is_provider_id("NPI: 123456789")); // 9 digits
        assert!(!is_provider_id("NPI: 12345678901")); // 11 digits
    }

    #[test]
    fn test_separator_variations() {
        // Various separator styles
        assert!(is_medical_record_number("MRN:12345678"));
        assert!(is_medical_record_number("MRN: 12345678"));
        assert!(is_medical_record_number("MRN-12345678"));
        assert!(is_medical_record_number("MRN #12345678"));
    }

    #[test]
    fn test_additional_test_patterns() {
        // Test MRN patterns
        assert!(is_test_mrn("TEST-123456"));
        assert!(is_test_mrn("DEMO-789012"));
        assert!(is_test_mrn("MRN-123456"));
        assert!(is_test_mrn("000000"));
        assert!(is_test_mrn("999999"));
        assert!(!is_test_mrn("ABC-789012")); // Not a test pattern

        // Test insurance patterns
        assert!(is_test_insurance("TEST123456789"));
        assert!(is_test_insurance("DEMO-123456"));
        assert!(is_test_insurance("XXX123456789"));
        assert!(is_test_insurance("000000"));
        assert!(!is_test_insurance("BCBS-987654")); // Not a test pattern
    }

    #[test]
    fn test_icd10_code_variations() {
        // Valid ICD-10 codes
        assert!(is_medical_code("A00")); // Basic
        assert!(is_medical_code("A00.0")); // With decimal
        assert!(is_medical_code("Z99.89")); // Multiple decimal digits
        assert!(is_medical_code("S72.001A")); // With extension

        // Invalid ICD-10 (U is not allowed)
        assert!(!is_medical_code("U00.0"));
    }

    #[test]
    fn test_cpt_code_variations() {
        // Valid CPT codes
        assert!(is_medical_code("CPT: 99213"));
        assert!(is_medical_code("CPT:99213"));
        assert!(is_medical_code("CPT 99213"));
    }

    #[test]
    fn test_multiple_matches_in_text() {
        let text = "Patient MRN: 12345678, Insurance: ABC123456789, RX# 987654321, NPI: 1234567890, Code: A01.1";
        let matches = find_all_medical_in_text(text);

        // Should find multiple different types
        assert!(
            matches.len() >= 3,
            "Expected at least 3 matches, got {}",
            matches.len()
        );
    }

    #[test]
    fn test_medicare_format() {
        // Medicare format: 1-3 letters + 6 digits + optional letter/digit
        assert!(is_health_insurance("A123456"));
        assert!(is_health_insurance("AB123456"));
        assert!(is_health_insurance("ABC123456"));
        assert!(is_health_insurance("ABC123456A"));
    }

    #[test]
    fn test_npi_starting_digits() {
        // NPI must start with 1 or 2
        assert!(is_provider_id("NPI: 1234567890"));
        assert!(is_provider_id("NPI: 2987654321"));
        assert!(!is_provider_id("NPI: 3123456789")); // Invalid start
        assert!(!is_provider_id("NPI: 0123456789")); // Invalid start
    }

    #[test]
    fn test_false_positive_prevention() {
        // Should not match regular text that looks similar
        assert!(!is_medical_record_number("My phone number is 12345678"));
        assert!(!is_provider_id("The year 1234567890 was eventful"));
        assert!(!is_prescription("Order #123456789 shipped"));
    }
}

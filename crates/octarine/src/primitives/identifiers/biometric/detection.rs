//! Biometric identifier detection (primitives layer)
//!
//! Pure detection functions for biometric identifiers with NO logging.
//! Uses patterns from `primitives/identifiers/common/patterns.rs`.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Supported Biometric Types
//!
//! - **Fingerprints**: Fingerprint hashes and identifiers
//! - **Facial Recognition**: Face encodings, FaceID/TouchID
//! - **Iris Scans**: IrisCode format, iris templates
//! - **Voice Prints**: Voice/speaker identification
//! - **DNA Sequences**: Genetic information, STR markers
//! - **Biometric Templates**: ISO/IEC 19794 standard formats
//!
//! # Privacy Regulations
//!
//! - **GDPR Article 9**: Biometric data is "special category" requiring explicit consent
//! - **BIPA**: Biometric Information Privacy Act (Illinois) - strictest US law
//! - **CCPA**: California Consumer Privacy Act includes biometric data

use super::super::common::patterns;
use super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};

// ============================================================================
// Constants for ReDoS Protection
// ============================================================================

/// Maximum text length for scanning operations (10KB)
const MAX_INPUT_LENGTH: usize = 10_000;

/// Maximum identifier length for single-value checks
const MAX_IDENTIFIER_LENGTH: usize = 1_000;

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract full match from capture group
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

/// Check if value is a fingerprint identifier
#[must_use]
pub fn is_fingerprint(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::biometric::FINGERPRINT_LABELED.is_match(trimmed)
}

/// Check if value is facial recognition data
#[must_use]
pub fn is_facial_recognition(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::biometric::FACE_ENCODING.is_match(trimmed)
        || patterns::biometric::FACE_ID.is_match(trimmed)
}

/// Check if value is an iris scan
#[must_use]
pub fn is_iris_scan(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::biometric::IRIS_CODE.is_match(trimmed)
        || patterns::biometric::IRIS_TEMPLATE.is_match(trimmed)
}

/// Check if value is a voice print
#[must_use]
pub fn is_voice_print(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::biometric::VOICE_PRINT.is_match(trimmed)
}

/// Check if value is a DNA sequence
#[must_use]
pub fn is_dna_sequence(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::biometric::DNA_SEQUENCE.is_match(trimmed)
        || patterns::biometric::DNA_STR_MARKER.is_match(trimmed)
}

/// Check if value is a biometric template
#[must_use]
pub fn is_biometric_template(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::biometric::BIOMETRIC_TEMPLATE_ISO.is_match(trimmed)
        || patterns::biometric::BIOMETRIC_TEMPLATE_GENERIC.is_match(trimmed)
}

/// Check if value is any biometric identifier
#[must_use]
pub fn is_biometric_identifier(value: &str) -> bool {
    is_fingerprint(value)
        || is_facial_recognition(value)
        || is_iris_scan(value)
        || is_voice_print(value)
        || is_dna_sequence(value)
        || is_biometric_template(value)
}

/// Check if text contains any biometric identifier
#[must_use]
pub fn is_biometric_present(text: &str) -> bool {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return false;
    }
    patterns::biometric::all().iter().any(|p| p.is_match(text))
}

// ============================================================================
// Test Pattern Detection
// ============================================================================

/// Check if fingerprint ID is a known test/sample pattern
///
/// Detects common test patterns like TEST-, DEMO-, SAMPLE- prefixes,
/// all zeros/nines, and sequential patterns.
#[must_use]
pub fn is_test_fingerprint(fingerprint_id: &str) -> bool {
    let upper = fingerprint_id.to_uppercase();
    let clean: String = fingerprint_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    // Test prefixes
    if upper.starts_with("TEST")
        || upper.starts_with("DEMO")
        || upper.starts_with("SAMPLE")
        || upper.starts_with("FAKE")
    {
        return true;
    }

    // All zeros or nines (at least 6 chars)
    if clean.len() >= 6 && clean.chars().all(|c| c == '0' || c == '9') {
        return true;
    }

    // Sequential patterns
    if clean.contains("123456") || clean.contains("654321") || clean.contains("ABCDEF") {
        return true;
    }

    false
}

/// Check if DNA sequence is a known test/sample pattern
///
/// Detects simple repeating patterns and obviously fake sequences.
#[must_use]
pub fn is_test_dna(dna: &str) -> bool {
    let trimmed = dna.trim().to_uppercase();

    // Check for simple repeating patterns
    if trimmed.len() >= 20 {
        // All same nucleotide
        if trimmed.chars().all(|c| c == 'A')
            || trimmed.chars().all(|c| c == 'T')
            || trimmed.chars().all(|c| c == 'C')
            || trimmed.chars().all(|c| c == 'G')
        {
            return true;
        }

        // Simple alternating pattern
        let chars: Vec<char> = trimmed.chars().collect();
        if chars.len() >= 20 {
            let is_alternating = chars.windows(2).all(|w| w.first() != w.get(1));
            if is_alternating && chars.iter().collect::<std::collections::HashSet<_>>().len() == 2 {
                return true;
            }
        }
    }

    false
}

/// Check if biometric ID is a known test/sample pattern
///
/// Generic test pattern detection for any biometric identifier.
#[must_use]
pub fn is_test_biometric_id(id: &str) -> bool {
    let upper = id.to_uppercase();
    let digits_only: String = id.chars().filter(|c| c.is_ascii_digit()).collect();

    // Test prefixes
    if upper.starts_with("TEST")
        || upper.starts_with("DEMO")
        || upper.starts_with("SAMPLE")
        || upper.starts_with("FAKE")
        || upper.starts_with("XXX")
    {
        return true;
    }

    // All zeros or nines
    if digits_only.len() >= 6 && digits_only.chars().all(|c| c == '0' || c == '9') {
        return true;
    }

    // Sequential patterns
    if digits_only.contains("123456") || digits_only.contains("654321") {
        return true;
    }

    false
}

/// Detect the type of biometric identifier
#[must_use]
pub fn detect_biometric_identifier(value: &str) -> Option<IdentifierType> {
    if is_fingerprint(value) {
        Some(IdentifierType::Fingerprint)
    } else if is_facial_recognition(value) {
        Some(IdentifierType::FacialRecognition)
    } else if is_iris_scan(value) {
        Some(IdentifierType::IrisScan)
    } else if is_voice_print(value) {
        Some(IdentifierType::VoicePrint)
    } else if is_dna_sequence(value) {
        Some(IdentifierType::DNASequence)
    } else if is_biometric_template(value) {
        Some(IdentifierType::BiometricTemplate)
    } else {
        None
    }
}

// ============================================================================
// Text Scanning (Detect Multiple Matches in Documents)
// ============================================================================

/// Detect all fingerprint identifiers in text
#[must_use]
pub fn detect_fingerprints_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for pattern in patterns::biometric::fingerprints() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::Fingerprint,
                DetectionConfidence::High,
            ));
        }
    }
    deduplicate_matches(matches)
}

/// Detect all facial recognition data in text
#[must_use]
pub fn detect_facial_data_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for pattern in patterns::biometric::facial() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::FacialRecognition,
                DetectionConfidence::High,
            ));
        }
    }
    deduplicate_matches(matches)
}

/// Detect all iris scans in text
#[must_use]
pub fn detect_iris_scans_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for pattern in patterns::biometric::iris() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::IrisScan,
                DetectionConfidence::High,
            ));
        }
    }
    deduplicate_matches(matches)
}

/// Detect all voice prints in text
#[must_use]
pub fn detect_voice_prints_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for pattern in patterns::biometric::voice() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::VoicePrint,
                DetectionConfidence::High,
            ));
        }
    }
    deduplicate_matches(matches)
}

/// Detect all DNA sequences in text
#[must_use]
pub fn detect_dna_sequences_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for pattern in patterns::biometric::dna() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::DNASequence,
                DetectionConfidence::High,
            ));
        }
    }
    deduplicate_matches(matches)
}

/// Detect all biometric templates in text
#[must_use]
pub fn detect_biometric_templates_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for pattern in patterns::biometric::templates() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::BiometricTemplate,
                DetectionConfidence::High,
            ));
        }
    }
    deduplicate_matches(matches)
}

/// Detect all biometric identifiers in text
#[must_use]
pub fn detect_all_biometric_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut all_matches = Vec::new();
    all_matches.extend(detect_fingerprints_in_text(text));
    all_matches.extend(detect_facial_data_in_text(text));
    all_matches.extend(detect_iris_scans_in_text(text));
    all_matches.extend(detect_voice_prints_in_text(text));
    all_matches.extend(detect_dna_sequences_in_text(text));
    all_matches.extend(detect_biometric_templates_in_text(text));

    deduplicate_matches(all_matches)
}

// ============================================================================
// Deduplication
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

    // ===== Single-Value Detection Tests =====

    #[test]
    fn test_is_fingerprint() {
        assert!(is_fingerprint(
            "fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234"
        ));
        assert!(is_fingerprint("fp: abc123def456789012345678901234567890")); // 38 hex chars
        assert!(!is_fingerprint("not a fingerprint"));
    }

    #[test]
    fn test_is_facial_recognition() {
        assert!(is_facial_recognition(
            "face_encoding: dGhpc2lzYWZha2VmYWNlZW5jb2Rpbmc="
        ));
        assert!(is_facial_recognition("faceid: FACE1234567890ABCDEF"));
        assert!(!is_facial_recognition("not facial data"));
    }

    #[test]
    fn test_is_iris_scan() {
        assert!(is_iris_scan("iris_id: IRIS1234567890ABCDEF"));
        assert!(!is_iris_scan("not an iris scan"));
    }

    #[test]
    fn test_is_voice_print() {
        assert!(is_voice_print("voiceprint: VP1234567890ABCDEF"));
        assert!(is_voice_print("speaker_id: SPKR1234567890"));
        assert!(!is_voice_print("not a voice print"));
    }

    #[test]
    fn test_is_dna_sequence() {
        assert!(is_dna_sequence("ATCGATCGATCGATCGATCG"));
        assert!(is_dna_sequence("D3S1358: 15"));
        assert!(!is_dna_sequence("ABCDEFG")); // Not ATCG
    }

    #[test]
    fn test_is_biometric_template() {
        assert!(is_biometric_template(
            "FMR: SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        ));
        assert!(is_biometric_template(
            "biometric: ABC123DEF456GHI789JKL012MNO345PQR678STU901VWX234YZ"
        ));
        assert!(!is_biometric_template("not a template"));
    }

    #[test]
    fn test_is_biometric_identifier() {
        assert!(is_biometric_identifier(
            "fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234"
        ));
        assert!(is_biometric_identifier("ATCGATCGATCGATCGATCG"));
        assert!(!is_biometric_identifier("not biometric"));
    }

    #[test]
    fn test_detect_biometric_identifier() {
        assert_eq!(
            detect_biometric_identifier(
                "fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234"
            ),
            Some(IdentifierType::Fingerprint)
        );
        assert_eq!(
            detect_biometric_identifier("ATCGATCGATCGATCGATCG"),
            Some(IdentifierType::DNASequence)
        );
        assert_eq!(detect_biometric_identifier("not biometric"), None);
    }

    // ===== Text Scanning Tests =====

    #[test]
    fn test_detect_fingerprints_in_text() {
        let text = "User fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234";
        let matches = detect_fingerprints_in_text(text);
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("Should have match").identifier_type,
            IdentifierType::Fingerprint
        );
    }

    #[test]
    fn test_detect_facial_data_in_text() {
        let text = "face_encoding: dGhpc2lzYWZha2VmYWNlZW5jb2Rpbmc=";
        let matches = detect_facial_data_in_text(text);
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("Should have match").identifier_type,
            IdentifierType::FacialRecognition
        );
    }

    #[test]
    fn test_detect_iris_scans_in_text() {
        let text = "iris_id: IRIS1234567890ABCDEF";
        let matches = detect_iris_scans_in_text(text);
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("Should have match").identifier_type,
            IdentifierType::IrisScan
        );
    }

    #[test]
    fn test_detect_voice_prints_in_text() {
        let text = "voiceprint: VP1234567890ABCDEF";
        let matches = detect_voice_prints_in_text(text);
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("Should have match").identifier_type,
            IdentifierType::VoicePrint
        );
    }

    #[test]
    fn test_detect_dna_sequences_in_text() {
        let text = "Sequence: ATCGATCGATCGATCGATCG";
        let matches = detect_dna_sequences_in_text(text);
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("Should have match").identifier_type,
            IdentifierType::DNASequence
        );
    }

    #[test]
    fn test_detect_biometric_templates_in_text() {
        let text = "FMR: SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        let matches = detect_biometric_templates_in_text(text);
        assert!(!matches.is_empty());
        assert_eq!(
            matches.first().expect("Should have match").identifier_type,
            IdentifierType::BiometricTemplate
        );
    }

    #[test]
    fn test_detect_all_biometric_in_text() {
        let text = "Data: fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234 and ATCGATCGATCGATCGATCG";
        let matches = detect_all_biometric_in_text(text);
        assert!(matches.len() >= 2);
    }

    #[test]
    fn test_no_matches_in_clean_text() {
        let text = "This text contains no biometric identifiers";
        assert!(detect_fingerprints_in_text(text).is_empty());
        assert!(detect_facial_data_in_text(text).is_empty());
        assert!(detect_iris_scans_in_text(text).is_empty());
        assert!(detect_voice_prints_in_text(text).is_empty());
        assert!(detect_dna_sequences_in_text(text).is_empty());
        assert!(detect_biometric_templates_in_text(text).is_empty());
    }

    // ===== ReDoS Protection Tests =====

    #[test]
    fn test_redos_protection() {
        let long_input = "x".repeat(MAX_INPUT_LENGTH + 1);
        assert!(detect_all_biometric_in_text(&long_input).is_empty());
        assert!(!is_fingerprint(&long_input));
        assert!(!is_biometric_present(&long_input));
    }

    // ===== Edge Case Tests =====

    #[test]
    fn test_empty_input() {
        assert!(!is_fingerprint(""));
        assert!(!is_biometric_identifier(""));
        assert!(detect_all_biometric_in_text("").is_empty());
    }

    #[test]
    fn test_whitespace_handling() {
        assert!(is_fingerprint(
            "  fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234  "
        ));
    }

    #[test]
    fn test_deduplicate_matches() {
        let matches = vec![
            IdentifierMatch::new(
                0,
                10,
                "test1".to_string(),
                IdentifierType::Fingerprint,
                DetectionConfidence::High,
            ),
            IdentifierMatch::new(
                0,
                15,
                "test1long".to_string(),
                IdentifierType::Fingerprint,
                DetectionConfidence::High,
            ),
            IdentifierMatch::new(
                20,
                30,
                "test2".to_string(),
                IdentifierType::DNASequence,
                DetectionConfidence::High,
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

    // ===== Test Pattern Detection Tests =====

    #[test]
    fn test_is_test_fingerprint_prefixes() {
        assert!(is_test_fingerprint("TEST-FP-123456"));
        assert!(is_test_fingerprint("DEMO_FINGERPRINT_001"));
        assert!(is_test_fingerprint("SAMPLE-FP-ABC"));
        assert!(is_test_fingerprint("FAKE-fingerprint-123"));
        assert!(is_test_fingerprint("test123")); // lowercase
    }

    #[test]
    fn test_is_test_fingerprint_all_zeros() {
        assert!(is_test_fingerprint("000000"));
        assert!(is_test_fingerprint("0000000000"));
        assert!(is_test_fingerprint("00-00-00-00"));
        assert!(!is_test_fingerprint("00000")); // Too short (< 6 digits)
    }

    #[test]
    fn test_is_test_fingerprint_all_nines() {
        assert!(is_test_fingerprint("999999"));
        assert!(is_test_fingerprint("9999999999"));
        assert!(is_test_fingerprint("99-99-99-99"));
    }

    #[test]
    fn test_is_test_fingerprint_sequential() {
        assert!(is_test_fingerprint("FP-123456-ABC"));
        assert!(is_test_fingerprint("654321-FP"));
        assert!(is_test_fingerprint("ABCDEF-123"));
    }

    #[test]
    fn test_is_test_fingerprint_valid() {
        assert!(!is_test_fingerprint("FP-A1B2C3D4"));
        assert!(!is_test_fingerprint("FINGER-789012"));
        assert!(!is_test_fingerprint("abc123def456"));
    }

    #[test]
    fn test_is_test_dna_all_same_nucleotide() {
        assert!(is_test_dna("AAAAAAAAAAAAAAAAAAAA")); // 20 As
        assert!(is_test_dna("TTTTTTTTTTTTTTTTTTTT")); // 20 Ts
        assert!(is_test_dna("CCCCCCCCCCCCCCCCCCCC")); // 20 Cs
        assert!(is_test_dna("GGGGGGGGGGGGGGGGGGGG")); // 20 Gs
    }

    #[test]
    fn test_is_test_dna_alternating() {
        assert!(is_test_dna("ATATATATATATATATATAT")); // 20 chars alternating
        assert!(is_test_dna("GCGCGCGCGCGCGCGCGCGC")); // 20 chars alternating
    }

    #[test]
    fn test_is_test_dna_short_sequences() {
        assert!(!is_test_dna("AAAA")); // Too short (< 20)
        assert!(!is_test_dna("ATAT")); // Too short (< 20)
    }

    #[test]
    fn test_is_test_dna_valid() {
        assert!(!is_test_dna("ATCGATCGATCGATCGATCG")); // Mixed, not test
        assert!(!is_test_dna("AACGTTAGCCTAAGCTTAGC")); // Real-looking
    }

    #[test]
    fn test_is_test_biometric_id_prefixes() {
        assert!(is_test_biometric_id("TEST-BIO-123"));
        assert!(is_test_biometric_id("DEMO_BIOMETRIC"));
        assert!(is_test_biometric_id("SAMPLE-ID-001"));
        assert!(is_test_biometric_id("FAKE-USER-BIO"));
        assert!(is_test_biometric_id("XXX-000-000"));
    }

    #[test]
    fn test_is_test_biometric_id_all_zeros() {
        assert!(is_test_biometric_id("ID-000000"));
        assert!(is_test_biometric_id("BIO-00000000"));
    }

    #[test]
    fn test_is_test_biometric_id_sequential() {
        assert!(is_test_biometric_id("BIO-123456"));
        assert!(is_test_biometric_id("ID-654321"));
    }

    #[test]
    fn test_is_test_biometric_id_valid() {
        assert!(!is_test_biometric_id("BIO-A1B2C3"));
        assert!(!is_test_biometric_id("ID-789012-XYZ"));
    }

    // ===== Additional Edge Case Tests =====

    #[test]
    fn test_is_biometric_present() {
        assert!(is_biometric_present(
            "User data: fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234"
        ));
        assert!(is_biometric_present("DNA: ATCGATCGATCGATCGATCG"));
        assert!(is_biometric_present("voiceprint: VP1234567890ABCDEF"));
        assert!(!is_biometric_present("No biometric data here"));
    }

    #[test]
    fn test_unicode_handling() {
        // Should not match unicode characters as biometric data
        assert!(!is_fingerprint("指纹: 12345"));
        assert!(!is_dna_sequence("基因: ATCG"));
    }

    #[test]
    fn test_case_sensitivity() {
        // DNA patterns match uppercase
        assert!(is_dna_sequence("ATCGATCGATCGATCGATCG"));
        // Voice print patterns check labels (case varies by pattern)
        assert!(is_voice_print("voiceprint: VP1234567890ABCDEF"));
    }

    #[test]
    fn test_mixed_content() {
        let text = "User info: email@example.com, fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234, SSN: 123-45-6789";
        let matches = detect_all_biometric_in_text(text);
        assert!(!matches.is_empty());
        // Should find fingerprint but not email or SSN
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::Fingerprint)
        );
    }

    #[test]
    fn test_multiple_same_type() {
        let text = "FP1: fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234 FP2: fingerprint: b2c3d4e5f6789012345678901234567890123456789012345678901234ab";
        let matches = detect_fingerprints_in_text(text);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_boundary_conditions() {
        // Exactly at max length
        let just_under = "x".repeat(MAX_INPUT_LENGTH);
        assert!(!is_biometric_present(&just_under)); // No match but should process

        // Single char over
        let just_over = "x".repeat(MAX_INPUT_LENGTH + 1);
        assert!(!is_biometric_present(&just_over)); // Should reject
    }

    #[test]
    fn test_special_characters_in_text() {
        // Should not crash on special chars
        let text = "Data: \t\n\r fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234 \x00";
        let matches = detect_fingerprints_in_text(text);
        // May or may not match depending on pattern, but shouldn't crash
        assert!(matches.len() <= 1);
    }

    #[test]
    fn test_newline_separated() {
        let text = "Line 1: fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234\nLine 2: voiceprint: VP1234567890ABCDEF";
        let matches = detect_all_biometric_in_text(text);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_identifier_match_len() {
        let m = IdentifierMatch::new(
            5,
            15,
            "testvalue".to_string(),
            IdentifierType::Fingerprint,
            DetectionConfidence::High,
        );
        assert_eq!(m.len(), 10);
    }

    #[test]
    fn test_confidence_levels() {
        let text = "fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234";
        let matches = detect_fingerprints_in_text(text);
        assert!(!matches.is_empty());
        // All biometric matches should be high confidence
        assert!(
            matches
                .iter()
                .all(|m| m.confidence == DetectionConfidence::High)
        );
    }

    #[test]
    fn test_find_priority() {
        // Test detection priority when value could match multiple types
        let fingerprint =
            "fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234";
        let detected = detect_biometric_identifier(fingerprint);
        assert_eq!(detected, Some(IdentifierType::Fingerprint));
    }
}

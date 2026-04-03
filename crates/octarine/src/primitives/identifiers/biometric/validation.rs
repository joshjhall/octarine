//! Biometric identifier validation (primitives layer)
//!
//! Pure validation functions for biometric identifiers with NO logging.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Important Note
//!
//! This module validates **identifier formats** for biometric data, not the
//! actual biometric templates themselves. Actual biometric data validation
//! requires specialized algorithms and is outside the scope of this module.
//!
//! # Detection Layer Exception (Issue #48)
//!
//! Unlike other identifier modules, biometric validators do NOT call detection
//! functions first. This is an intentional architectural decision:
//!
//! - **Detection patterns** (`detection::is_fingerprint()`, etc.) require labels
//!   (e.g., "fingerprint: a1b2c3d4...") to avoid false positives with git
//!   commit hashes and other hex strings
//! - **Validators** work on bare identifier strings (e.g., "FP-A1B2C3D4")
//!   which are application-assigned IDs, not raw biometric data
//!
//! The detection layer is designed for text-scanning (finding labeled biometric
//! data in documents), while validators check application-level ID formats.
//! Calling detection functions here would always return false, adding no value.

use crate::primitives::Problem;

// ============================================================================
// Constants
// ============================================================================

/// Minimum length for biometric IDs
const MIN_ID_LENGTH: usize = 6;

/// Maximum length for biometric IDs
const MAX_ID_LENGTH: usize = 30;

/// Minimum length for DNA sequences (matches detection pattern)
const MIN_DNA_LENGTH: usize = 20;

/// Maximum length for raw biometric data inputs (ReDoS protection)
const MAX_DATA_LENGTH: usize = 10_000;

/// Minimum content length for ISO biometric templates (after prefix + separator)
const MIN_ISO_TEMPLATE_CONTENT: usize = 50;

/// Minimum content length for generic biometric templates (after prefix + separator)
const MIN_GENERIC_TEMPLATE_CONTENT: usize = 32;

/// Known ISO 19794 biometric template prefixes
const ISO_PREFIXES: [&str; 4] = ["FMR", "FIR", "FTR", "IIR"];

/// Known generic biometric template prefixes
const GENERIC_PREFIXES: [&str; 2] = ["biometric", "bio_template"];

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if value contains injection patterns
fn is_injection_pattern_present(value: &str) -> bool {
    value.contains("$(")
        || value.contains('`')
        || value.contains("${")
        || value.contains(';')
        || value.contains('|')
        || value.contains('&')
}

// ============================================================================
// Fingerprint ID Validation
// ============================================================================

/// Validate fingerprint identifier format
///
/// # Errors
///
/// Returns `Problem` if the fingerprint ID format is invalid
pub fn validate_fingerprint_id(fingerprint_id: &str) -> Result<(), Problem> {
    let trimmed = fingerprint_id.trim();

    // Length validation
    if trimmed.len() < MIN_ID_LENGTH || trimmed.len() > MAX_ID_LENGTH {
        return Err(Problem::Validation(format!(
            "Fingerprint ID must be {}-{} characters",
            MIN_ID_LENGTH, MAX_ID_LENGTH
        )));
    }

    // Check for injection patterns
    if is_injection_pattern_present(trimmed) {
        return Err(Problem::Validation(
            "Fingerprint ID contains invalid characters".into(),
        ));
    }

    // Must be alphanumeric with allowed separators
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Problem::Validation(
            "Fingerprint ID must contain only alphanumeric characters, hyphens, and underscores"
                .into(),
        ));
    }

    // Must contain at least one alphanumeric character
    if !trimmed.chars().any(|c| c.is_ascii_alphanumeric()) {
        return Err(Problem::Validation(
            "Fingerprint ID must contain at least one alphanumeric character".into(),
        ));
    }

    Ok(())
}

// ============================================================================
// Facial ID Validation
// ============================================================================

/// Validate facial recognition identifier format
///
/// # Errors
///
/// Returns `Problem` if the facial ID format is invalid
pub fn validate_facial_id(facial_id: &str) -> Result<(), Problem> {
    let trimmed = facial_id.trim();

    // Length validation
    if trimmed.len() < MIN_ID_LENGTH || trimmed.len() > MAX_ID_LENGTH {
        return Err(Problem::Validation(format!(
            "Facial ID must be {}-{} characters",
            MIN_ID_LENGTH, MAX_ID_LENGTH
        )));
    }

    // Check for injection patterns
    if is_injection_pattern_present(trimmed) {
        return Err(Problem::Validation(
            "Facial ID contains invalid characters".into(),
        ));
    }

    // Must be alphanumeric with allowed separators
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Problem::Validation(
            "Facial ID must contain only alphanumeric characters, hyphens, and underscores".into(),
        ));
    }

    // Must contain at least one alphanumeric character
    if !trimmed.chars().any(|c| c.is_ascii_alphanumeric()) {
        return Err(Problem::Validation(
            "Facial ID must contain at least one alphanumeric character".into(),
        ));
    }

    Ok(())
}

// ============================================================================
// Iris ID Validation
// ============================================================================

/// Validate iris scan identifier format
///
/// # Errors
///
/// Returns `Problem` if the iris ID format is invalid
pub fn validate_iris_id(iris_id: &str) -> Result<(), Problem> {
    let trimmed = iris_id.trim();

    // Length validation
    if trimmed.len() < MIN_ID_LENGTH || trimmed.len() > MAX_ID_LENGTH {
        return Err(Problem::Validation(format!(
            "Iris ID must be {}-{} characters",
            MIN_ID_LENGTH, MAX_ID_LENGTH
        )));
    }

    // Check for injection patterns
    if is_injection_pattern_present(trimmed) {
        return Err(Problem::Validation(
            "Iris ID contains invalid characters".into(),
        ));
    }

    // Must be alphanumeric with allowed separators
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Problem::Validation(
            "Iris ID must contain only alphanumeric characters, hyphens, and underscores".into(),
        ));
    }

    // Must contain at least one alphanumeric character
    if !trimmed.chars().any(|c| c.is_ascii_alphanumeric()) {
        return Err(Problem::Validation(
            "Iris ID must contain at least one alphanumeric character".into(),
        ));
    }

    Ok(())
}

// ============================================================================
// Voice ID Validation
// ============================================================================

/// Validate voice print identifier format
///
/// # Errors
///
/// Returns `Problem` if the voice ID format is invalid
pub fn validate_voice_id(voice_id: &str) -> Result<(), Problem> {
    let trimmed = voice_id.trim();

    // Length validation
    if trimmed.len() < MIN_ID_LENGTH || trimmed.len() > MAX_ID_LENGTH {
        return Err(Problem::Validation(format!(
            "Voice ID must be {}-{} characters",
            MIN_ID_LENGTH, MAX_ID_LENGTH
        )));
    }

    // Check for injection patterns
    if is_injection_pattern_present(trimmed) {
        return Err(Problem::Validation(
            "Voice ID contains invalid characters".into(),
        ));
    }

    // Must be alphanumeric with allowed separators
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Problem::Validation(
            "Voice ID must contain only alphanumeric characters, hyphens, and underscores".into(),
        ));
    }

    // Must contain at least one alphanumeric character
    if !trimmed.chars().any(|c| c.is_ascii_alphanumeric()) {
        return Err(Problem::Validation(
            "Voice ID must contain at least one alphanumeric character".into(),
        ));
    }

    Ok(())
}

// ============================================================================
// DNA Sequence Validation
// ============================================================================

/// Validate DNA sequence format
///
/// Validates that the input is a well-formed DNA sequence using the FASTA/FASTQ
/// nucleotide character set (A, T, C, G). Also accepts STR marker format
/// (e.g., "D3S1358: 15").
///
/// # Rules
///
/// - Minimum 20 characters (matching detection threshold)
/// - Maximum 10,000 characters (ReDoS protection)
/// - Pure sequences: only uppercase A, T, C, G
/// - STR markers: `D{digits}S{digits}: {digits}` format
/// - No injection patterns
///
/// # Errors
///
/// Returns `Problem` if the DNA sequence format is invalid
pub fn validate_dna_sequence(sequence: &str) -> Result<(), Problem> {
    let trimmed = sequence.trim();

    if trimmed.is_empty() {
        return Err(Problem::Validation("DNA sequence cannot be empty".into()));
    }

    if trimmed.len() > MAX_DATA_LENGTH {
        return Err(Problem::Validation(format!(
            "DNA sequence exceeds maximum length of {} characters",
            MAX_DATA_LENGTH
        )));
    }

    // Check for injection patterns
    if is_injection_pattern_present(trimmed) {
        return Err(Problem::Validation(
            "DNA sequence contains invalid characters".into(),
        ));
    }

    // Check if it's an STR marker format: D{digits}S{digits}: {digits}
    if is_str_marker(trimmed) {
        return Ok(());
    }

    // Pure nucleotide sequence validation
    if trimmed.len() < MIN_DNA_LENGTH {
        return Err(Problem::Validation(format!(
            "DNA sequence must be at least {} characters",
            MIN_DNA_LENGTH
        )));
    }

    if !trimmed
        .bytes()
        .all(|b| matches!(b, b'A' | b'T' | b'C' | b'G'))
    {
        return Err(Problem::Validation(
            "DNA sequence must contain only nucleotide characters (A, T, C, G)".into(),
        ));
    }

    Ok(())
}

/// Check if value matches STR marker format: D{digits}S{digits}: {digits}
fn is_str_marker(value: &str) -> bool {
    // Must start with 'D'
    let rest = match value.strip_prefix('D') {
        Some(r) => r,
        None => return false,
    };

    // Find the 'S' separator - digits before it
    let s_pos = rest.find('S');
    let s_pos = match s_pos {
        Some(p) if p > 0 => p,
        _ => return false,
    };

    let (chromosome_digits, after_s) = rest.split_at(s_pos);
    if !chromosome_digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }

    // Skip the 'S'
    let after_s = &after_s[1..];

    // Find the separator (colon or space) between locus number and repeat count
    let sep_pos = after_s.find([':', ' ']);
    let sep_pos = match sep_pos {
        Some(p) if p > 0 => p,
        _ => return false,
    };

    let (locus_digits, after_sep) = after_s.split_at(sep_pos);
    if !locus_digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }

    // Skip separators (colon, spaces)
    let repeat_count = after_sep.trim_start_matches([':', ' ']);
    if repeat_count.is_empty() {
        return false;
    }

    repeat_count.bytes().all(|b| b.is_ascii_digit())
}

// ============================================================================
// Biometric Template Validation
// ============================================================================

/// Validate biometric template format
///
/// Validates that the input is a well-formed biometric template with a recognized
/// prefix and valid base64-encoded content.
///
/// # Rules
///
/// - Must start with a recognized prefix:
///   - ISO 19794: `FMR`, `FIR`, `FTR`, `IIR` (min 50 chars content)
///   - Generic: `biometric`, `bio_template` (min 32 chars content)
/// - Content after prefix separator must be valid base64 (A-Za-z0-9+/=)
/// - Maximum 10,000 characters total (ReDoS protection)
/// - No injection patterns
/// - Content must have minimum entropy (not all same character)
///
/// # Errors
///
/// Returns `Problem` if the biometric template format is invalid
pub fn validate_biometric_template(template: &str) -> Result<(), Problem> {
    let trimmed = template.trim();

    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Biometric template cannot be empty".into(),
        ));
    }

    if trimmed.len() > MAX_DATA_LENGTH {
        return Err(Problem::Validation(format!(
            "Biometric template exceeds maximum length of {} characters",
            MAX_DATA_LENGTH
        )));
    }

    // Check for injection patterns
    if is_injection_pattern_present(trimmed) {
        return Err(Problem::Validation(
            "Biometric template contains invalid characters".into(),
        ));
    }

    // Try to match a recognized prefix
    let (min_content_len, content) = match extract_template_content(trimmed) {
        Some(result) => result,
        None => {
            return Err(Problem::Validation(
                "Biometric template must start with a recognized prefix (FMR, FIR, FTR, IIR, biometric, bio_template)".into(),
            ));
        }
    };

    // Validate content length
    if content.len() < min_content_len {
        return Err(Problem::Validation(format!(
            "Biometric template content must be at least {} characters",
            min_content_len
        )));
    }

    // Validate base64 character set
    if !content
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return Err(Problem::Validation(
            "Biometric template content must be valid base64 characters".into(),
        ));
    }

    // Minimum entropy: reject all-same-character content
    if content
        .bytes()
        .next()
        .is_some_and(|first| content.bytes().all(|b| b == first))
    {
        return Err(Problem::Validation(
            "Biometric template content has insufficient entropy".into(),
        ));
    }

    Ok(())
}

/// Extract content after a recognized prefix and separator.
/// Returns (minimum_content_length, content_str) or None if no prefix matches.
fn extract_template_content(value: &str) -> Option<(usize, &str)> {
    // Check ISO prefixes (case-insensitive)
    for prefix in &ISO_PREFIXES {
        if value.len() > prefix.len() {
            let candidate = &value[..prefix.len()];
            if candidate.eq_ignore_ascii_case(prefix) {
                let rest = &value[prefix.len()..];
                let content = rest.trim_start_matches([':', ' ', '#', '-']);
                if content.len() < rest.len() {
                    // At least one separator was consumed
                    return Some((MIN_ISO_TEMPLATE_CONTENT, content));
                }
            }
        }
    }

    // Check generic prefixes (case-insensitive)
    for prefix in &GENERIC_PREFIXES {
        if value.len() > prefix.len() {
            let candidate = &value[..prefix.len()];
            if candidate.eq_ignore_ascii_case(prefix) {
                let rest = &value[prefix.len()..];
                let content = rest.trim_start_matches([':', ' ', '#', '-']);
                if content.len() < rest.len() {
                    return Some((MIN_GENERIC_TEMPLATE_CONTENT, content));
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== Fingerprint ID Tests =====

    #[test]
    fn test_fingerprint_id_valid() {
        assert!(validate_fingerprint_id("FP-A1B2C3D4").is_ok());
        assert!(validate_fingerprint_id("FINGER_123456").is_ok());
        assert!(validate_fingerprint_id("FP123456789").is_ok());
        assert!(validate_fingerprint_id("FP-123-ABC").is_ok());
    }

    #[test]
    fn test_fingerprint_id_edge_lengths() {
        assert!(validate_fingerprint_id("FP1234").is_ok()); // Min length (6)
        assert!(validate_fingerprint_id("FP12345678901234567890123456").is_ok());
        // Max length (30)
    }

    #[test]
    fn test_fingerprint_id_invalid_length() {
        assert!(validate_fingerprint_id("FP-12").is_err()); // Too short
        assert!(validate_fingerprint_id("FP1234567890123456789012345678901").is_err());
        // Too long
    }

    #[test]
    fn test_fingerprint_id_invalid_characters() {
        assert!(validate_fingerprint_id("FP@123").is_err()); // @ not allowed
        assert!(validate_fingerprint_id("FP 123").is_err()); // Space not allowed
        assert!(validate_fingerprint_id("FP.123").is_err()); // Dot not allowed
    }

    #[test]
    fn test_fingerprint_id_injection() {
        assert!(validate_fingerprint_id("FP-$(whoami)").is_err());
        assert!(validate_fingerprint_id("FP-`ls`").is_err());
        assert!(validate_fingerprint_id("FP-;rm -rf").is_err());
    }

    #[test]
    fn test_fingerprint_id_only_separators() {
        assert!(validate_fingerprint_id("------").is_err()); // Only hyphens
        assert!(validate_fingerprint_id("______").is_err()); // Only underscores
    }

    // ===== Facial ID Tests =====

    #[test]
    fn test_facial_id_valid() {
        assert!(validate_facial_id("FACE-123456").is_ok());
        assert!(validate_facial_id("FR_A1B2C3").is_ok());
        assert!(validate_facial_id("FACE789012").is_ok());
    }

    #[test]
    fn test_facial_id_invalid() {
        assert!(validate_facial_id("FC-12").is_err()); // Too short
        assert!(validate_facial_id("FACE@123").is_err()); // Invalid char
    }

    // ===== Iris ID Tests =====

    #[test]
    fn test_iris_id_valid() {
        assert!(validate_iris_id("IRIS-123456").is_ok());
        assert!(validate_iris_id("IR_A1B2C3").is_ok());
        assert!(validate_iris_id("IRIS789012").is_ok());
    }

    #[test]
    fn test_iris_id_invalid() {
        assert!(validate_iris_id("IR-12").is_err()); // Too short
        assert!(validate_iris_id("IRIS@123").is_err()); // Invalid char
    }

    // ===== Voice ID Tests =====

    #[test]
    fn test_voice_id_valid() {
        assert!(validate_voice_id("VOICE-123456").is_ok());
        assert!(validate_voice_id("VP_A1B2C3").is_ok());
        assert!(validate_voice_id("VOICE789012").is_ok());
    }

    #[test]
    fn test_voice_id_invalid() {
        assert!(validate_voice_id("VP-12").is_err()); // Too short
        assert!(validate_voice_id("VOICE@123").is_err()); // Invalid char
    }

    // ===== Empty/Whitespace Tests =====

    #[test]
    fn test_empty_inputs() {
        assert!(validate_fingerprint_id("").is_err());
        assert!(validate_facial_id("").is_err());
        assert!(validate_iris_id("").is_err());
        assert!(validate_voice_id("").is_err());
    }

    #[test]
    fn test_whitespace_trimming() {
        assert!(validate_fingerprint_id("  FP-A1B2C3D4  ").is_ok());
        assert!(validate_facial_id("  FACE-123456  ").is_ok());
    }

    // ===== DNA Sequence Tests =====

    #[test]
    fn test_dna_sequence_valid_pure() {
        assert!(validate_dna_sequence("ATCGATCGATCGATCGATCG").is_ok()); // Exactly 20
        assert!(validate_dna_sequence("ATCGATCGATCGATCGATCGATCG").is_ok()); // 24
        assert!(validate_dna_sequence(&"ATCG".repeat(100)).is_ok()); // 400
    }

    #[test]
    fn test_dna_sequence_valid_str_marker() {
        assert!(validate_dna_sequence("D3S1358: 15").is_ok());
        assert!(validate_dna_sequence("D5S818: 12").is_ok());
        assert!(validate_dna_sequence("D13S317: 8").is_ok());
        assert!(validate_dna_sequence("D21S11: 30").is_ok());
    }

    #[test]
    fn test_dna_sequence_too_short() {
        assert!(validate_dna_sequence("ATCGATCG").is_err()); // 8 chars
        assert!(validate_dna_sequence("ATCGATCGATCGATCGATC").is_err()); // 19 chars
    }

    #[test]
    fn test_dna_sequence_too_long() {
        let long = "A".repeat(10_001);
        assert!(validate_dna_sequence(&long).is_err());
    }

    #[test]
    fn test_dna_sequence_invalid_characters() {
        // Lowercase not allowed
        assert!(validate_dna_sequence("atcgatcgatcgatcgatcg").is_err());
        // N (ambiguity code) not allowed in strict validation
        assert!(validate_dna_sequence("ATCGATCGATCNATCGATCG").is_err());
        // Numbers not allowed
        assert!(validate_dna_sequence("ATCG1234ATCGATCGATCG").is_err());
    }

    #[test]
    fn test_dna_sequence_injection() {
        assert!(validate_dna_sequence("$(whoami)ATCGATCGATCGATCGATCG").is_err());
        assert!(validate_dna_sequence("ATCG`ls`ATCGATCGATCG").is_err());
    }

    #[test]
    fn test_dna_sequence_empty() {
        assert!(validate_dna_sequence("").is_err());
        assert!(validate_dna_sequence("   ").is_err());
    }

    #[test]
    fn test_dna_sequence_whitespace_trimming() {
        assert!(validate_dna_sequence("  ATCGATCGATCGATCGATCG  ").is_ok());
        assert!(validate_dna_sequence("  D3S1358: 15  ").is_ok());
    }

    // ===== Biometric Template Tests =====

    #[test]
    fn test_biometric_template_valid_iso() {
        // FMR (Finger Minutiae Record) - needs 50+ base64 chars content
        let content = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        assert!(validate_biometric_template(&format!("FMR: {content}")).is_ok());
        assert!(validate_biometric_template(&format!("FIR: {content}")).is_ok());
        assert!(validate_biometric_template(&format!("FTR: {content}")).is_ok());
        assert!(validate_biometric_template(&format!("IIR: {content}")).is_ok());
    }

    #[test]
    fn test_biometric_template_valid_generic() {
        // Generic prefix - needs 32+ base64 chars content
        let content = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYQ==";
        assert!(validate_biometric_template(&format!("biometric: {content}")).is_ok());
        assert!(validate_biometric_template(&format!("bio_template: {content}")).is_ok());
    }

    #[test]
    fn test_biometric_template_valid_separators() {
        let content = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        // Various separator styles
        assert!(validate_biometric_template(&format!("FMR:{content}")).is_ok());
        assert!(validate_biometric_template(&format!("FMR: {content}")).is_ok());
        assert!(validate_biometric_template(&format!("FMR# {content}")).is_ok());
        assert!(validate_biometric_template(&format!("FMR-{content}")).is_ok());
    }

    #[test]
    fn test_biometric_template_case_insensitive_prefix() {
        let content = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        assert!(validate_biometric_template(&format!("fmr: {content}")).is_ok());
        assert!(validate_biometric_template(&format!("Biometric: {content}")).is_ok());
    }

    #[test]
    fn test_biometric_template_no_prefix() {
        assert!(validate_biometric_template("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0").is_err());
        assert!(validate_biometric_template("UNKNOWN: SGVsbG8gV29ybGQ=").is_err());
    }

    #[test]
    fn test_biometric_template_content_too_short() {
        // ISO prefix needs 50 chars content
        assert!(validate_biometric_template("FMR: SGVsbG8gV29ybGQ=").is_err()); // ~20 chars
        // Generic prefix needs 32 chars content
        assert!(validate_biometric_template("biometric: SGVsbG8=").is_err()); // ~7 chars
    }

    #[test]
    fn test_biometric_template_invalid_base64() {
        let bad_content = "SGVsbG8!@#$%gV29ybGQ!IFRoaXMgaXMgYSB0ZXN0ABCDEFGHIJKLMNOP";
        assert!(validate_biometric_template(&format!("FMR: {bad_content}")).is_err());
    }

    #[test]
    fn test_biometric_template_low_entropy() {
        let same_chars = "A".repeat(60);
        assert!(validate_biometric_template(&format!("FMR: {same_chars}")).is_err());
    }

    #[test]
    fn test_biometric_template_injection() {
        assert!(validate_biometric_template("FMR: $(whoami)AAAA").is_err());
        assert!(validate_biometric_template("biometric: `ls`AAAA").is_err());
    }

    #[test]
    fn test_biometric_template_empty() {
        assert!(validate_biometric_template("").is_err());
        assert!(validate_biometric_template("   ").is_err());
    }

    #[test]
    fn test_biometric_template_too_long() {
        let long_content = "A1B2C3D4".repeat(2000); // 16,000 chars
        assert!(validate_biometric_template(&format!("FMR: {long_content}")).is_err());
    }

    #[test]
    fn test_biometric_template_whitespace_trimming() {
        let content = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        assert!(validate_biometric_template(&format!("  FMR: {content}  ")).is_ok());
    }
}

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
}

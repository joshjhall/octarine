//! Medical identifier validation (primitives layer)
//!
//! Pure validation functions for medical identifiers with no observe dependencies.
//! Used by observe/pii and security modules.
//!
//! # Supported Validations
//!
//! - **MRN**: Medical Record Number format validation
//! - **Insurance**: Health insurance number format validation
//! - **Prescription**: Prescription number format validation
//! - **NPI**: National Provider Identifier with Luhn checksum
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns Result/bool, no side effects
//! - Used by observe/pii and security modules
//!
//! # HIPAA Compliance
//!
//! Medical identifiers are Protected Health Information (PHI):
//! - HIPAA Privacy Rule (45 CFR 164.514)
//! - Requires proper access controls
//! - Validation does not sanitize - use sanitization module for that

use super::super::common::luhn;
use crate::primitives::Problem;

use super::detection;

// ============================================================================
// MRN Validation
// ============================================================================

/// Validate Medical Record Number format
///
/// Validates MRN format used by hospitals and clinics.
///
/// Format requirements:
/// - Must match MRN detection pattern (labeled or unlabeled)
/// - Length: 4-20 characters
/// - Characters: Alphanumeric, hyphens, underscores
/// - Must contain at least one alphanumeric character
/// - No injection patterns allowed
///
/// # Errors
///
/// Returns `Problem::validation` if:
/// - Does not match MRN detection pattern
/// - Length is not 4-20 characters
/// - Contains invalid characters
/// - Contains injection patterns
/// - No alphanumeric characters
pub fn validate_mrn(mrn: &str) -> Result<(), Problem> {
    // Use detection layer first (DRY principle + type safety)
    if !detection::is_medical_record_number(mrn) {
        return Err(Problem::Validation("Invalid MRN format".into()));
    }

    let trimmed = mrn.trim();

    // Length validation (4-20 characters)
    if trimmed.len() < 4 || trimmed.len() > 20 {
        return Err(Problem::Validation("MRN must be 4-20 characters".into()));
    }

    // Check for injection patterns
    if is_injection_pattern_present(trimmed) {
        return Err(Problem::Validation(
            "MRN contains invalid characters".into(),
        ));
    }

    // Must be alphanumeric with allowed separators
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Problem::Validation(
            "MRN must contain only alphanumeric characters, hyphens, and underscores".into(),
        ));
    }

    // Must contain at least one alphanumeric character
    if !trimmed.chars().any(|c| c.is_ascii_alphanumeric()) {
        return Err(Problem::Validation(
            "MRN must contain at least one alphanumeric character".into(),
        ));
    }

    Ok(())
}

// ============================================================================
// Insurance Number Validation
// ============================================================================

/// Validate health insurance number format
///
/// Validates health insurance policy/member identifier format.
///
/// Format requirements:
/// - Must match insurance detection pattern (labeled or unlabeled)
/// - Length: 6-25 characters
/// - Characters: Alphanumeric, hyphens
/// - Must contain at least one alphanumeric character
/// - No injection patterns allowed
///
/// # Errors
///
/// Returns `Problem::validation` if:
/// - Does not match insurance detection pattern
/// - Length is not 6-25 characters
/// - Contains invalid characters
/// - Contains injection patterns
/// - No alphanumeric characters
pub fn validate_insurance_number(insurance_number: &str) -> Result<(), Problem> {
    // Use detection layer first (DRY principle + type safety)
    if !detection::is_health_insurance(insurance_number) {
        return Err(Problem::Validation(
            "Invalid insurance number format".into(),
        ));
    }

    let trimmed = insurance_number.trim();

    // Length validation (6-25 characters)
    if trimmed.len() < 6 || trimmed.len() > 25 {
        return Err(Problem::Validation(
            "Insurance number must be 6-25 characters".into(),
        ));
    }

    // Check for injection patterns
    if is_injection_pattern_present(trimmed) {
        return Err(Problem::Validation(
            "Insurance number contains invalid characters".into(),
        ));
    }

    // Must be alphanumeric with hyphens
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(Problem::Validation(
            "Insurance number must contain only alphanumeric characters and hyphens".into(),
        ));
    }

    // Must contain at least one alphanumeric character
    if !trimmed.chars().any(|c| c.is_ascii_alphanumeric()) {
        return Err(Problem::Validation(
            "Insurance number must contain at least one alphanumeric character".into(),
        ));
    }

    Ok(())
}

// ============================================================================
// Prescription Number Validation
// ============================================================================

/// Validate prescription number format
///
/// Validates pharmacy prescription identifier format.
///
/// Format requirements:
/// - Must match prescription detection pattern (labeled or unlabeled)
/// - Length: 6-20 characters
/// - Characters: Alphanumeric, hyphens
/// - Must contain at least one digit
/// - No injection patterns allowed
///
/// # Errors
///
/// Returns `Problem::validation` if:
/// - Does not match prescription detection pattern
/// - Length is not 6-20 characters
/// - Contains invalid characters
/// - No digits present
/// - Contains injection patterns
pub fn validate_prescription_number(prescription_number: &str) -> Result<(), Problem> {
    // Use detection layer first (DRY principle + type safety)
    if !detection::is_prescription(prescription_number) {
        return Err(Problem::Validation(
            "Invalid prescription number format".into(),
        ));
    }

    let trimmed = prescription_number.trim();

    // Length validation (6-20 characters)
    if trimmed.len() < 6 || trimmed.len() > 20 {
        return Err(Problem::Validation(
            "Prescription number must be 6-20 characters".into(),
        ));
    }

    // Check for injection patterns
    if is_injection_pattern_present(trimmed) {
        return Err(Problem::Validation(
            "Prescription number contains invalid characters".into(),
        ));
    }

    // Must be alphanumeric with hyphens
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(Problem::Validation(
            "Prescription number must contain only alphanumeric characters and hyphens".into(),
        ));
    }

    // Must contain at least one digit
    if !trimmed.chars().any(|c| c.is_ascii_digit()) {
        return Err(Problem::Validation(
            "Prescription number must contain at least one digit".into(),
        ));
    }

    Ok(())
}

// ============================================================================
// NPI Validation
// ============================================================================

/// Validate NPI (National Provider Identifier) format
///
/// Validates NPI format as defined by CMS.
/// NPI is a unique 10-digit identifier for healthcare providers.
///
/// Format requirements:
/// - Must match NPI detection pattern (labeled or unlabeled)
/// - Exactly 10 digits
/// - Passes Luhn checksum with "80840" prefix
/// - No other characters allowed
///
/// # Errors
///
/// Returns `Problem::validation` if:
/// - Does not match NPI detection pattern
/// - Not exactly 10 digits
/// - Contains non-digit characters
/// - Fails Luhn checksum validation
pub fn validate_npi(npi: &str) -> Result<(), Problem> {
    // Use detection layer first (DRY principle + type safety)
    if !detection::is_provider_id(npi) {
        return Err(Problem::Validation("Invalid NPI format".into()));
    }

    let trimmed = npi.trim();

    // Must be exactly 10 digits
    if trimmed.len() != 10 {
        return Err(Problem::Validation("NPI must be exactly 10 digits".into()));
    }

    // Must be all digits
    if !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Err(Problem::Validation("NPI must contain only digits".into()));
    }

    // Validate Luhn checksum with CMS prefix "80840"
    let prefixed = format!("80840{trimmed}");
    if !luhn::is_valid(&prefixed) {
        return Err(Problem::Validation("NPI checksum validation failed".into()));
    }

    Ok(())
}

/// Validate NPI with test pattern rejection
///
/// Like `validate_npi` but also rejects known test patterns.
///
/// # Errors
///
/// Returns `Problem::validation` if:
/// - All conditions from `validate_npi`
/// - NPI is a known test pattern
pub fn validate_npi_no_test(npi: &str) -> Result<(), Problem> {
    validate_npi(npi)?;

    if super::detection::is_test_npi(npi) {
        return Err(Problem::Validation("Test NPI patterns not allowed".into()));
    }

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check for common injection patterns
fn is_injection_pattern_present(value: &str) -> bool {
    // Command injection
    if value.contains("$(")
        || value.contains('`')
        || value.contains("${")
        || value.contains(';')
        || value.contains('|')
        || value.contains('&')
    {
        return true;
    }

    // SQL injection
    if value.to_lowercase().contains("--")
        || value.contains("/*")
        || value.to_lowercase().contains("union")
        || value.to_lowercase().contains("select")
    {
        return true;
    }

    // XSS
    if value.contains('<') || value.contains('>') {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== MRN Tests =====

    #[test]
    fn test_mrn_valid() {
        assert!(validate_mrn("MRN-123456").is_ok());
        assert!(validate_mrn("PAT_789012").is_ok());
        assert!(validate_mrn("123456").is_ok());
        assert!(validate_mrn("ABC-123-DEF").is_ok());
    }

    #[test]
    fn test_mrn_edge_lengths() {
        assert!(validate_mrn("ABCD").is_ok()); // Min length (4)
        assert!(validate_mrn("12345678901234567890").is_ok()); // Max length (20)
    }

    #[test]
    fn test_mrn_invalid_length() {
        assert!(validate_mrn("ABC").is_err()); // Too short
        assert!(validate_mrn("123456789012345678901").is_err()); // Too long
    }

    #[test]
    fn test_mrn_invalid_characters() {
        assert!(validate_mrn("MRN@123").is_err()); // Invalid character
        assert!(validate_mrn("MRN 123").is_err()); // Space not allowed
        assert!(validate_mrn("MRN.123").is_err()); // Dot not allowed
    }

    #[test]
    fn test_mrn_injection() {
        assert!(validate_mrn("MRN-$(whoami)").is_err());
        assert!(validate_mrn("MRN-`ls`").is_err());
        assert!(validate_mrn("MRN-;rm -rf").is_err());
    }

    #[test]
    fn test_mrn_only_separators() {
        assert!(validate_mrn("----").is_err()); // Only hyphens (needs 4 chars min)
        assert!(validate_mrn("____").is_err()); // Only underscores
    }

    // ===== Insurance Number Tests =====

    #[test]
    fn test_insurance_number_valid() {
        assert!(validate_insurance_number("INS-987654321").is_ok());
        assert!(validate_insurance_number("BCBS-123-456-789").is_ok());
        assert!(validate_insurance_number("H123456789").is_ok());
        assert!(validate_insurance_number("AETNA-12345").is_ok());
    }

    #[test]
    fn test_insurance_number_edge_lengths() {
        assert!(validate_insurance_number("INS123").is_ok()); // Min length (6)
        assert!(validate_insurance_number("1234567890123456789012345").is_ok());
        // Max length (25)
    }

    #[test]
    fn test_insurance_number_invalid_length() {
        assert!(validate_insurance_number("12345").is_err()); // Too short
        assert!(validate_insurance_number("12345678901234567890123456").is_err());
        // Too long
    }

    #[test]
    fn test_insurance_number_invalid_characters() {
        assert!(validate_insurance_number("INS@123456").is_err()); // @ not allowed
        assert!(validate_insurance_number("INS_123456").is_err()); // Underscore not allowed
        assert!(validate_insurance_number("INS 123456").is_err()); // Space not allowed
    }

    #[test]
    fn test_insurance_number_injection() {
        assert!(validate_insurance_number("INS-$(whoami)").is_err());
        assert!(validate_insurance_number("INS-`ls`123").is_err());
    }

    // ===== Prescription Number Tests =====

    #[test]
    fn test_prescription_number_valid() {
        assert!(validate_prescription_number("RX-123456").is_ok());
        assert!(validate_prescription_number("9876543210").is_ok());
        assert!(validate_prescription_number("CVS-123-456").is_ok());
        assert!(validate_prescription_number("123456").is_ok());
    }

    #[test]
    fn test_prescription_number_edge_lengths() {
        assert!(validate_prescription_number("RX1234").is_ok()); // Min length (6)
        assert!(validate_prescription_number("12345678901234567890").is_ok()); // Max length (20)
    }

    #[test]
    fn test_prescription_number_invalid_length() {
        assert!(validate_prescription_number("RX-12").is_err()); // Too short
        assert!(validate_prescription_number("123456789012345678901").is_err());
        // Too long
    }

    #[test]
    fn test_prescription_number_no_digits() {
        assert!(validate_prescription_number("ABCDEF").is_err()); // No digits
        assert!(validate_prescription_number("RX-ABC").is_err()); // No digits
    }

    #[test]
    fn test_prescription_number_invalid_characters() {
        assert!(validate_prescription_number("RX@123456").is_err()); // @ not allowed
        assert!(validate_prescription_number("RX 123456").is_err()); // Space not allowed
    }

    #[test]
    fn test_prescription_number_injection() {
        assert!(validate_prescription_number("RX-$(whoami)").is_err());
        assert!(validate_prescription_number("123`ls`456").is_err());
    }

    // ===== NPI Tests =====

    #[test]
    fn test_npi_valid() {
        // Valid NPI with correct Luhn checksum
        assert!(validate_npi("1245319599").is_ok()); // Known valid NPI
        assert!(validate_npi("1679576722").is_ok()); // Valid checksum
    }

    #[test]
    fn test_npi_invalid_length() {
        assert!(validate_npi("123456789").is_err()); // Too short
        assert!(validate_npi("12345678901").is_err()); // Too long
    }

    #[test]
    fn test_npi_invalid_characters() {
        assert!(validate_npi("12345678AB").is_err()); // Contains letters
        assert!(validate_npi("123-456-789").is_err()); // Contains hyphens
        assert!(validate_npi("123 456 789").is_err()); // Contains spaces
    }

    #[test]
    fn test_npi_invalid_checksum() {
        assert!(validate_npi("1234567890").is_err()); // Invalid checksum
        assert!(validate_npi("9999999999").is_err()); // Invalid checksum
    }

    #[test]
    fn test_npi_no_test() {
        // Valid NPI that passes checksum
        assert!(validate_npi_no_test("1245319599").is_ok());

        // Test patterns should be rejected
        assert!(validate_npi_no_test("1234567890").is_err());
        assert!(validate_npi_no_test("1111111111").is_err());
    }

    // ===== Edge Case Tests =====

    #[test]
    fn test_empty_inputs() {
        assert!(validate_mrn("").is_err());
        assert!(validate_insurance_number("").is_err());
        assert!(validate_prescription_number("").is_err());
        assert!(validate_npi("").is_err());
    }

    #[test]
    fn test_whitespace_inputs() {
        assert!(validate_mrn("   ").is_err());
        assert!(validate_insurance_number("   ").is_err());
        assert!(validate_prescription_number("   ").is_err());
        assert!(validate_npi("   ").is_err());
    }

    #[test]
    fn test_whitespace_trimming() {
        // Leading/trailing whitespace should be trimmed
        assert!(validate_mrn("  MRN-123456  ").is_ok());
        assert!(validate_insurance_number("  INS-123456789  ").is_ok());
        assert!(validate_prescription_number("  RX-123456  ").is_ok());
        assert!(validate_npi("  1245319599  ").is_ok());
    }
}

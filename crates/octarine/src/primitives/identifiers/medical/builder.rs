//! Medical identifier builder (primitives layer)
//!
//! Unified API for medical identifier detection, validation, and sanitization.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - provides a builder pattern
//! with no observe dependencies.

use super::super::types::{IdentifierMatch, IdentifierType};
use super::{conversion, detection, redaction, sanitization, validation};
use crate::primitives::Problem;
use crate::primitives::collections::CacheStats;
use std::borrow::Cow;

// Re-export redaction strategies for convenience
pub use redaction::{
    InsuranceRedactionStrategy, MedicalCodeRedactionStrategy, MrnRedactionStrategy,
    NpiRedactionStrategy, PrescriptionRedactionStrategy, TextRedactionPolicy,
};

// Re-export conversion format styles for convenience
pub use conversion::{Icd10FormatStyle, NpiFormatStyle};

/// Builder for medical identifier operations
///
/// Provides a unified API for detecting, validating, and sanitizing
/// medical identifiers including MRN, insurance, prescriptions, NPI,
/// and medical codes.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::MedicalIdentifierBuilder;
///
/// let builder = MedicalIdentifierBuilder::new();
///
/// // Detection
/// assert!(builder.is_provider_id("NPI: 1234567890"));
///
/// // Validation
/// assert!(builder.validate_npi("1245319599"));
///
/// // Sanitization
/// let safe = builder.redact_all_in_text("NPI: 1234567890");
/// assert!(safe.contains("[PROVIDER_ID]"));
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct MedicalIdentifierBuilder;

impl MedicalIdentifierBuilder {
    /// Create a new medical identifier builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // =========================================================================
    // Detection Methods
    // =========================================================================

    /// Detect the type of medical identifier
    #[must_use]
    pub fn detect(&self, value: &str) -> Option<IdentifierType> {
        detection::detect_medical_identifier(value)
    }

    /// Check if value is any medical identifier
    #[must_use]
    pub fn is_medical(&self, value: &str) -> bool {
        detection::is_medical_identifier(value)
    }

    /// Check if value is a medical record number
    #[must_use]
    pub fn is_mrn(&self, value: &str) -> bool {
        detection::is_medical_record_number(value)
    }

    /// Check if value is health insurance information
    #[must_use]
    pub fn is_insurance(&self, value: &str) -> bool {
        detection::is_health_insurance(value)
    }

    /// Check if value is a prescription number
    #[must_use]
    pub fn is_prescription(&self, value: &str) -> bool {
        detection::is_prescription(value)
    }

    /// Check if value is a provider ID (NPI)
    #[must_use]
    pub fn is_provider_id(&self, value: &str) -> bool {
        detection::is_provider_id(value)
    }

    /// Check if value is a medical code (ICD-10, CPT)
    #[must_use]
    pub fn is_medical_code(&self, value: &str) -> bool {
        detection::is_medical_code(value)
    }

    /// Check if value is a DEA number (format + checksum)
    #[must_use]
    pub fn is_dea_number(&self, value: &str) -> bool {
        detection::is_dea_number(value)
    }

    /// Check if text contains any medical identifier
    #[must_use]
    pub fn is_medical_identifier_present(&self, text: &str) -> bool {
        detection::is_medical_identifier_present(text)
    }

    // =========================================================================
    // Text Scanning Methods
    // =========================================================================

    /// Find all MRNs in text
    #[must_use]
    pub fn find_mrns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_mrns_in_text(text)
    }

    /// Find all insurance IDs in text
    #[must_use]
    pub fn find_insurance_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_insurance_ids_in_text(text)
    }

    /// Find all prescriptions in text
    #[must_use]
    pub fn find_prescriptions_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_prescriptions_in_text(text)
    }

    /// Find all provider IDs (NPI) in text
    #[must_use]
    pub fn find_provider_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_provider_ids_in_text(text)
    }

    /// Find all medical codes in text
    #[must_use]
    pub fn find_medical_codes_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_medical_codes_in_text(text)
    }

    /// Find all DEA numbers in text
    #[must_use]
    pub fn find_dea_numbers_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_dea_numbers_in_text(text)
    }

    /// Find all medical identifiers in text
    #[must_use]
    pub fn find_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_all_medical_in_text(text)
    }

    // =========================================================================
    // Validation Methods
    // =========================================================================

    /// Validate MRN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the MRN format is invalid
    pub fn validate_mrn(&self, mrn: &str) -> Result<(), Problem> {
        validation::validate_mrn(mrn)
    }

    /// Validate insurance number format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the insurance number format is invalid
    pub fn validate_insurance(&self, insurance: &str) -> Result<(), Problem> {
        validation::validate_insurance_number(insurance)
    }

    /// Validate prescription number format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the prescription number format is invalid
    pub fn validate_prescription(&self, prescription: &str) -> Result<(), Problem> {
        validation::validate_prescription_number(prescription)
    }

    /// Validate NPI format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NPI format is invalid
    pub fn validate_npi(&self, npi: &str) -> Result<(), Problem> {
        validation::validate_npi(npi)
    }

    /// Validate NPI with test pattern rejection
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NPI is invalid or a known test pattern
    pub fn validate_npi_no_test(&self, npi: &str) -> Result<(), Problem> {
        validation::validate_npi_no_test(npi)
    }

    // =========================================================================
    // Sanitization Methods
    // =========================================================================

    /// Redact a medical record number (MRN) with explicit strategy
    ///
    /// # Arguments
    ///
    /// * `mrn` - Medical record number to redact
    /// * `strategy` - MRN-specific redaction strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::medical::{MedicalIdentifierBuilder, MrnRedactionStrategy};
    ///
    /// let builder = MedicalIdentifierBuilder::new();
    /// assert_eq!(builder.redact_mrn_with_strategy("MRN-123456", MrnRedactionStrategy::Token), "[MEDICAL_RECORD]");
    /// assert_eq!(builder.redact_mrn_with_strategy("MRN-123456", MrnRedactionStrategy::ShowPrefix), "MRN-12****");
    /// ```
    #[must_use]
    pub fn redact_mrn_with_strategy(&self, mrn: &str, strategy: MrnRedactionStrategy) -> String {
        sanitization::redact_mrn_with_strategy(mrn, strategy)
    }

    /// Redact MRNs in text using text redaction policy
    ///
    /// # Arguments
    ///
    /// * `text` - Text to scan for MRNs
    /// * `policy` - Text redaction policy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::medical::{MedicalIdentifierBuilder, TextRedactionPolicy};
    ///
    /// let builder = MedicalIdentifierBuilder::new();
    /// let text = "Patient MRN: 12345678";
    /// let safe = builder.redact_mrn_in_text(text, TextRedactionPolicy::Complete);
    /// assert!(safe.contains("[MEDICAL_RECORD]"));
    /// ```
    #[must_use]
    pub fn redact_mrn_in_text<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_mrn_in_text(text, policy)
    }

    /// Redact a health insurance number with explicit strategy
    ///
    /// # Arguments
    ///
    /// * `insurance` - Insurance number to redact
    /// * `strategy` - Insurance-specific redaction strategy
    #[must_use]
    pub fn redact_insurance_number_with_strategy(
        &self,
        insurance: &str,
        strategy: InsuranceRedactionStrategy,
    ) -> String {
        sanitization::redact_insurance_number_with_strategy(insurance, strategy)
    }

    /// Redact insurance info in text using text redaction policy
    ///
    /// # Arguments
    ///
    /// * `text` - Text to scan for insurance information
    /// * `policy` - Text redaction policy
    #[must_use]
    pub fn redact_insurance_in_text<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_insurance_in_text(text, policy)
    }

    /// Redact a prescription number with explicit strategy
    ///
    /// # Arguments
    ///
    /// * `prescription` - Prescription number to redact
    /// * `strategy` - Prescription-specific redaction strategy
    #[must_use]
    pub fn redact_prescription_number_with_strategy(
        &self,
        prescription: &str,
        strategy: PrescriptionRedactionStrategy,
    ) -> String {
        sanitization::redact_prescription_number_with_strategy(prescription, strategy)
    }

    /// Redact prescriptions in text using text redaction policy
    ///
    /// # Arguments
    ///
    /// * `text` - Text to scan for prescription numbers
    /// * `policy` - Text redaction policy
    #[must_use]
    pub fn redact_prescriptions_in_text<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_prescriptions_in_text(text, policy)
    }

    /// Redact a National Provider Identifier (NPI) with explicit strategy
    ///
    /// # Arguments
    ///
    /// * `npi` - National Provider Identifier to redact
    /// * `strategy` - NPI-specific redaction strategy
    #[must_use]
    pub fn redact_npi_with_strategy(&self, npi: &str, strategy: NpiRedactionStrategy) -> String {
        sanitization::redact_npi_with_strategy(npi, strategy)
    }

    /// Redact a provider identifier with explicit strategy
    ///
    /// Alias for `redact_npi_with_strategy()`.
    ///
    /// # Arguments
    ///
    /// * `id` - Provider identifier to redact
    /// * `strategy` - NPI-specific redaction strategy
    #[must_use]
    pub fn redact_provider_id_with_strategy(
        &self,
        id: &str,
        strategy: NpiRedactionStrategy,
    ) -> String {
        sanitization::redact_provider_id_with_strategy(id, strategy)
    }

    /// Redact provider IDs in text using text redaction policy
    ///
    /// # Arguments
    ///
    /// * `text` - Text to scan for provider IDs
    /// * `policy` - Text redaction policy
    #[must_use]
    pub fn redact_provider_ids_in_text<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_provider_ids_in_text(text, policy)
    }

    /// Redact a medical code (ICD-10, CPT) with explicit strategy
    ///
    /// # Arguments
    ///
    /// * `code` - Medical code to redact
    /// * `strategy` - Medical code-specific redaction strategy
    #[must_use]
    pub fn redact_medical_code_with_strategy(
        &self,
        code: &str,
        strategy: MedicalCodeRedactionStrategy,
    ) -> String {
        sanitization::redact_medical_code_with_strategy(code, strategy)
    }

    /// Redact medical codes in text using text redaction policy
    ///
    /// # Arguments
    ///
    /// * `text` - Text to scan for medical codes
    /// * `policy` - Text redaction policy
    #[must_use]
    pub fn redact_medical_codes_in_text<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_medical_codes_in_text(text, policy)
    }

    /// Redact DEA numbers in text using text redaction policy
    #[must_use]
    pub fn redact_dea_numbers_in_text<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_dea_numbers_in_text(text, policy)
    }

    /// Redact all medical identifiers in text using Complete policy
    #[must_use]
    pub fn redact_all_in_text(&self, text: &str) -> String {
        sanitization::redact_all_medical_in_text(text, TextRedactionPolicy::Complete)
    }

    /// Redact all medical identifiers in text with custom policy
    #[must_use]
    pub fn redact_all_in_text_with_policy(
        &self,
        text: &str,
        policy: TextRedactionPolicy,
    ) -> String {
        sanitization::redact_all_medical_in_text(text, policy)
    }

    // =========================================================================
    // Conversion Methods
    // =========================================================================

    /// Convert an NPI to display format using specified style
    ///
    /// # Arguments
    ///
    /// * `npi` - NPI string
    /// * `style` - Desired formatting style
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::medical::{MedicalIdentifierBuilder, NpiFormatStyle};
    ///
    /// let builder = MedicalIdentifierBuilder::new();
    /// assert_eq!(builder.format_npi("1234567890", NpiFormatStyle::Dashed), "1234-567-890");
    /// ```
    #[must_use]
    pub fn format_npi(&self, npi: &str, style: NpiFormatStyle) -> String {
        conversion::to_npi_display(npi, style)
    }

    /// Validate NPI checksum using Luhn mod-10 algorithm
    ///
    /// # Arguments
    ///
    /// * `npi` - NPI string
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::medical::MedicalIdentifierBuilder;
    ///
    /// let builder = MedicalIdentifierBuilder::new();
    /// assert!(builder.validate_npi_checksum("1245319599").is_ok());
    /// assert!(builder.validate_npi_checksum("1234567890").is_err());
    /// ```
    pub fn validate_npi_checksum(&self, npi: &str) -> Result<(), Problem> {
        conversion::validate_npi_checksum(npi)
    }

    /// Normalize NPI to canonical 10-digit format
    ///
    /// Extracts digits from various input formats. Does NOT validate.
    /// Use `sanitize_npi()` for validation + normalization.
    ///
    /// # Arguments
    ///
    /// * `npi` - NPI string (may contain labels, spaces, dashes)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::medical::MedicalIdentifierBuilder;
    ///
    /// let builder = MedicalIdentifierBuilder::new();
    /// assert_eq!(builder.normalize_npi("NPI: 1234-567-890"), "1234567890");
    /// ```
    #[must_use]
    pub fn normalize_npi(&self, npi: &str) -> String {
        conversion::normalize_npi(npi)
    }

    /// Sanitize NPI strict (normalize format + validate checksum)
    ///
    /// Strips non-digits, validates format and Luhn checksum, returns normalized NPI.
    ///
    /// # Arguments
    ///
    /// * `npi` - NPI string (may contain labels, spaces, dashes)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::medical::MedicalIdentifierBuilder;
    ///
    /// let builder = MedicalIdentifierBuilder::new();
    /// let sanitized = builder.sanitize_npi("NPI: 1245-319-599")?;
    /// assert_eq!(sanitized, "1245319599");
    /// ```
    pub fn sanitize_npi(&self, npi: &str) -> Result<String, Problem> {
        conversion::sanitize_npi(npi)
    }

    /// Normalize ICD-10 code format
    ///
    /// # Arguments
    ///
    /// * `code` - ICD-10 code string
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::medical::MedicalIdentifierBuilder;
    ///
    /// let builder = MedicalIdentifierBuilder::new();
    /// assert_eq!(builder.normalize_icd10("A011").unwrap(), "A01.1");
    /// assert_eq!(builder.normalize_icd10("ICD-10: E119").unwrap(), "E11.9");
    /// ```
    pub fn normalize_icd10(&self, code: &str) -> Result<String, Problem> {
        conversion::normalize_icd10(code)
    }

    /// Format ICD-10 code to display format using specified style
    ///
    /// # Arguments
    ///
    /// * `code` - ICD-10 code string
    /// * `style` - Desired formatting style
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::medical::{MedicalIdentifierBuilder, Icd10FormatStyle};
    ///
    /// let builder = MedicalIdentifierBuilder::new();
    /// assert_eq!(builder.format_icd10("A01.1", Icd10FormatStyle::CompactNoDecimal), "A011");
    /// ```
    #[must_use]
    pub fn format_icd10(&self, code: &str, style: Icd10FormatStyle) -> String {
        conversion::to_icd10_display(code, style)
    }

    // =========================================================================
    // Test Pattern Detection
    // =========================================================================

    /// Check if NPI is a known test/sample pattern
    ///
    /// Detects common test NPI numbers like 1234567890, 1111111111, etc.
    #[must_use]
    pub fn is_test_npi(&self, npi: &str) -> bool {
        detection::is_test_npi(npi)
    }

    /// Check if MRN is a known test/sample pattern
    ///
    /// Detects test prefixes (TEST-, DEMO-, SAMPLE-), all zeros/nines,
    /// and sequential patterns.
    #[must_use]
    pub fn is_test_mrn(&self, mrn: &str) -> bool {
        detection::is_test_mrn(mrn)
    }

    /// Check if insurance number is a known test/sample pattern
    ///
    /// Detects test prefixes (TEST, DEMO, SAMPLE, XXX), all zeros/nines,
    /// and sequential patterns.
    #[must_use]
    pub fn is_test_insurance(&self, insurance: &str) -> bool {
        detection::is_test_insurance(insurance)
    }

    // =========================================================================
    // Cache Operations
    // =========================================================================

    /// Get combined cache statistics for all medical identifier caches
    ///
    /// Currently only NPI validation is cached. This method provides
    /// a consistent API across all identifier modules.
    #[must_use]
    pub fn cache_stats(&self) -> CacheStats {
        detection::npi_cache_stats()
    }

    /// Get NPI cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn npi_cache_stats(&self) -> CacheStats {
        detection::npi_cache_stats()
    }

    /// Clear all medical identifier caches
    pub fn clear_caches(&self) {
        detection::clear_medical_caches();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_builder_creation() {
        let builder = MedicalIdentifierBuilder::new();
        assert!(!builder.is_medical("not medical"));
    }

    #[test]
    fn test_builder_detection() {
        let builder = MedicalIdentifierBuilder::new();

        assert!(builder.is_mrn("MRN: 12345678"));
        assert!(builder.is_insurance("Policy Number: ABC123456789"));
        assert!(builder.is_prescription("RX# 123456789"));
        assert!(builder.is_provider_id("NPI: 1234567890"));
        assert!(builder.is_medical_code("A01.1"));
    }

    #[test]
    fn test_builder_validation() {
        let builder = MedicalIdentifierBuilder::new();

        assert!(builder.validate_mrn("MRN-123456").is_ok());
        assert!(builder.validate_insurance("INS-987654321").is_ok());
        assert!(builder.validate_prescription("RX-123456").is_ok());
        assert!(builder.validate_npi("1245319599").is_ok());
    }

    #[test]
    fn test_builder_sanitization() {
        let builder = MedicalIdentifierBuilder::new();

        let text = "Patient MRN: 12345678, NPI: 1234567890";
        let result = builder.redact_all_in_text(text);
        assert!(result.contains("[MEDICAL_RECORD]"));
        assert!(result.contains("[PROVIDER_ID]"));
    }

    #[test]
    fn test_builder_text_scanning() {
        let builder = MedicalIdentifierBuilder::new();

        let text = "MRN: 12345678, NPI: 1234567890";
        let matches = builder.find_all_in_text(text);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_builder_test_pattern_detection() {
        let builder = MedicalIdentifierBuilder::new();

        assert!(builder.is_test_npi("1234567890"));
        assert!(!builder.is_test_npi("1245319599"));
    }

    #[test]
    #[serial]
    fn test_builder_cache_stats() {
        let builder = MedicalIdentifierBuilder::new();
        builder.clear_caches();
        let stats = builder.npi_cache_stats();
        assert_eq!(stats.size, 0);
    }
}

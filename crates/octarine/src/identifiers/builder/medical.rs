//! Medical identifier builder with observability
//!
//! Wraps `primitives::identifiers::MedicalIdentifierBuilder` with observe instrumentation.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.

use std::borrow::Cow;

use crate::observe::Problem;
use crate::primitives::identifiers::{
    Icd10FormatStyle, InsuranceRedactionStrategy, MedicalCodeRedactionStrategy,
    MedicalIdentifierBuilder, MrnRedactionStrategy, NpiFormatStyle, NpiRedactionStrategy,
    PrescriptionRedactionStrategy,
};

use super::super::types::{IdentifierMatch, IdentifierType, MedicalTextPolicy};

/// Medical identifier builder with observability (HIPAA compliance)
#[derive(Debug, Clone, Copy, Default)]
pub struct MedicalBuilder {
    inner: MedicalIdentifierBuilder,
    emit_events: bool,
}

impl MedicalBuilder {
    /// Create a new MedicalBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: MedicalIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: MedicalIdentifierBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // =========================================================================
    // Detection Methods
    // =========================================================================

    /// Detect the type of medical identifier
    #[must_use]
    pub fn detect(&self, value: &str) -> Option<IdentifierType> {
        self.inner.detect(value)
    }

    /// Check if value is any medical identifier
    #[must_use]
    pub fn is_medical(&self, value: &str) -> bool {
        self.inner.is_medical(value)
    }

    /// Check if value is a medical record number
    #[must_use]
    pub fn is_mrn(&self, value: &str) -> bool {
        self.inner.is_mrn(value)
    }

    /// Check if value is health insurance information
    #[must_use]
    pub fn is_insurance(&self, value: &str) -> bool {
        self.inner.is_insurance(value)
    }

    /// Check if value is a prescription number
    #[must_use]
    pub fn is_prescription(&self, value: &str) -> bool {
        self.inner.is_prescription(value)
    }

    /// Check if value is a provider ID (NPI)
    #[must_use]
    pub fn is_provider_id(&self, value: &str) -> bool {
        self.inner.is_provider_id(value)
    }

    /// Check if value is a medical code (ICD-10, CPT)
    #[must_use]
    pub fn is_medical_code(&self, value: &str) -> bool {
        self.inner.is_medical_code(value)
    }

    /// Check if text contains any medical identifier
    #[must_use]
    pub fn is_medical_identifier_present(&self, text: &str) -> bool {
        self.inner.is_medical_identifier_present(text)
    }

    // =========================================================================
    // Text Scanning Methods
    // =========================================================================

    /// Find all MRNs in text
    #[must_use]
    pub fn find_mrns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_mrns_in_text(text)
    }

    /// Find all insurance IDs in text
    #[must_use]
    pub fn find_insurance_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_insurance_ids_in_text(text)
    }

    /// Find all prescriptions in text
    #[must_use]
    pub fn find_prescriptions_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_prescriptions_in_text(text)
    }

    /// Find all provider IDs (NPI) in text
    #[must_use]
    pub fn find_provider_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_provider_ids_in_text(text)
    }

    /// Find all medical codes in text
    #[must_use]
    pub fn find_medical_codes_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_medical_codes_in_text(text)
    }

    /// Find all medical identifiers in text
    #[must_use]
    pub fn find_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_all_in_text(text)
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
        self.inner.validate_mrn(mrn)
    }

    /// Validate insurance number format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the insurance number format is invalid
    pub fn validate_insurance(&self, insurance: &str) -> Result<(), Problem> {
        self.inner.validate_insurance(insurance)
    }

    /// Validate prescription number format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the prescription number format is invalid
    pub fn validate_prescription(&self, prescription: &str) -> Result<(), Problem> {
        self.inner.validate_prescription(prescription)
    }

    /// Validate NPI format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NPI format is invalid
    pub fn validate_npi(&self, npi: &str) -> Result<(), Problem> {
        self.inner.validate_npi(npi)
    }

    /// Validate NPI with test pattern rejection
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NPI is invalid or a known test pattern
    pub fn validate_npi_no_test(&self, npi: &str) -> Result<(), Problem> {
        self.inner.validate_npi_no_test(npi)
    }

    // =========================================================================
    // Sanitization Methods
    // =========================================================================

    /// Redact a medical record number (MRN) with explicit strategy
    #[must_use]
    pub fn redact_mrn_with_strategy(&self, mrn: &str, strategy: MrnRedactionStrategy) -> String {
        self.inner.redact_mrn_with_strategy(mrn, strategy)
    }

    /// Redact MRNs in text using text redaction policy
    #[must_use]
    pub fn redact_mrn_in_text<'a>(&self, text: &'a str, policy: MedicalTextPolicy) -> Cow<'a, str> {
        self.inner.redact_mrn_in_text(text, policy)
    }

    /// Redact a health insurance number with explicit strategy
    #[must_use]
    pub fn redact_insurance_number_with_strategy(
        &self,
        insurance: &str,
        strategy: InsuranceRedactionStrategy,
    ) -> String {
        self.inner
            .redact_insurance_number_with_strategy(insurance, strategy)
    }

    /// Redact insurance info in text using text redaction policy
    #[must_use]
    pub fn redact_insurance_in_text<'a>(
        &self,
        text: &'a str,
        policy: MedicalTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_insurance_in_text(text, policy)
    }

    /// Redact a prescription number with explicit strategy
    #[must_use]
    pub fn redact_prescription_number_with_strategy(
        &self,
        prescription: &str,
        strategy: PrescriptionRedactionStrategy,
    ) -> String {
        self.inner
            .redact_prescription_number_with_strategy(prescription, strategy)
    }

    /// Redact prescriptions in text using text redaction policy
    #[must_use]
    pub fn redact_prescriptions_in_text<'a>(
        &self,
        text: &'a str,
        policy: MedicalTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_prescriptions_in_text(text, policy)
    }

    /// Redact a National Provider Identifier (NPI) with explicit strategy
    #[must_use]
    pub fn redact_npi_with_strategy(&self, npi: &str, strategy: NpiRedactionStrategy) -> String {
        self.inner.redact_npi_with_strategy(npi, strategy)
    }

    /// Redact a provider identifier with explicit strategy
    #[must_use]
    pub fn redact_provider_id_with_strategy(
        &self,
        id: &str,
        strategy: NpiRedactionStrategy,
    ) -> String {
        self.inner.redact_provider_id_with_strategy(id, strategy)
    }

    /// Redact provider IDs in text using text redaction policy
    #[must_use]
    pub fn redact_provider_ids_in_text<'a>(
        &self,
        text: &'a str,
        policy: MedicalTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_provider_ids_in_text(text, policy)
    }

    /// Redact a medical code (ICD-10, CPT) with explicit strategy
    #[must_use]
    pub fn redact_medical_code_with_strategy(
        &self,
        code: &str,
        strategy: MedicalCodeRedactionStrategy,
    ) -> String {
        self.inner.redact_medical_code_with_strategy(code, strategy)
    }

    /// Redact medical codes in text using text redaction policy
    #[must_use]
    pub fn redact_medical_codes_in_text<'a>(
        &self,
        text: &'a str,
        policy: MedicalTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_medical_codes_in_text(text, policy)
    }

    /// Redact all medical identifiers in text using Complete policy
    #[must_use]
    pub fn redact_all_in_text(&self, text: &str) -> String {
        self.inner.redact_all_in_text(text)
    }

    /// Redact all medical identifiers in text with custom policy
    #[must_use]
    pub fn redact_all_in_text_with_policy(&self, text: &str, policy: MedicalTextPolicy) -> String {
        self.inner.redact_all_in_text_with_policy(text, policy)
    }

    // =========================================================================
    // Conversion Methods
    // =========================================================================

    /// Format an NPI using specified style
    #[must_use]
    pub fn format_npi(&self, npi: &str, style: NpiFormatStyle) -> String {
        self.inner.format_npi(npi, style)
    }

    /// Validate NPI checksum using Luhn mod-10 algorithm
    pub fn validate_npi_checksum(&self, npi: &str) -> Result<(), Problem> {
        self.inner.validate_npi_checksum(npi)
    }

    /// Normalize NPI to canonical 10-digit format
    ///
    /// Extracts digits from various input formats. Does NOT validate.
    /// Use `sanitize_npi()` for validation + normalization.
    #[must_use]
    pub fn normalize_npi(&self, npi: &str) -> String {
        self.inner.normalize_npi(npi)
    }

    /// Sanitize NPI strict (normalize format + validate checksum)
    ///
    /// Strips non-digits, validates format and Luhn checksum, returns normalized NPI.
    pub fn sanitize_npi(&self, npi: &str) -> Result<String, Problem> {
        self.inner.sanitize_npi(npi)
    }

    /// Normalize ICD-10 code format
    pub fn normalize_icd10(&self, code: &str) -> Result<String, Problem> {
        self.inner.normalize_icd10(code)
    }

    /// Format ICD-10 code using specified style
    #[must_use]
    pub fn format_icd10(&self, code: &str, style: Icd10FormatStyle) -> String {
        self.inner.format_icd10(code, style)
    }

    // =========================================================================
    // Test Pattern Detection
    // =========================================================================

    /// Check if NPI is a known test/sample pattern
    #[must_use]
    pub fn is_test_npi(&self, npi: &str) -> bool {
        self.inner.is_test_npi(npi)
    }

    /// Check if MRN is a known test/sample pattern
    #[must_use]
    pub fn is_test_mrn(&self, mrn: &str) -> bool {
        self.inner.is_test_mrn(mrn)
    }

    /// Check if insurance number is a known test/sample pattern
    #[must_use]
    pub fn is_test_insurance(&self, insurance: &str) -> bool {
        self.inner.is_test_insurance(insurance)
    }

    // =========================================================================
    // Cache Management
    // =========================================================================

    /// Get combined cache statistics for all medical identifier caches
    ///
    /// Returns aggregated stats across NPI validation caches.
    /// Use this for overall module performance monitoring.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::identifiers::MedicalBuilder;
    ///
    /// let builder = MedicalBuilder::new();
    /// let stats = builder.cache_stats();
    ///
    /// println!("Cache size: {}/{}", stats.size, stats.capacity);
    /// println!("Hit rate: {:.1}%", stats.hit_rate());
    /// ```
    #[must_use]
    pub fn cache_stats(&self) -> super::super::types::CacheStats {
        self.inner.cache_stats()
    }

    /// Get NPI validation cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn npi_cache_stats(&self) -> super::super::types::CacheStats {
        self.inner.npi_cache_stats()
    }

    /// Clear all medical identifier caches
    ///
    /// Use this to reset cache state, typically for testing or memory management.
    pub fn clear_caches(&self) {
        self.inner.clear_caches();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = MedicalBuilder::new();
        assert!(builder.emit_events);

        let silent = MedicalBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = MedicalBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_mrn_detection() {
        let builder = MedicalBuilder::silent();
        assert!(builder.is_mrn("MRN: 12345678"));
    }
}

//! Biometric identifier builder (primitives layer)
//!
//! Unified API for biometric identifier detection, validation, and sanitization.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - provides a builder pattern
//! with no observe dependencies.

use super::super::types::{IdentifierMatch, IdentifierType};
use super::{detection, redaction, sanitization, validation};
use crate::primitives::Problem;
use std::borrow::Cow;

// Re-export redaction strategies for builder API
pub use redaction::{
    BiometricTemplateRedactionStrategy, DnaRedactionStrategy, FacialIdRedactionStrategy,
    FingerprintRedactionStrategy, IrisIdRedactionStrategy, TextRedactionPolicy,
    VoiceIdRedactionStrategy,
};

/// Builder for biometric identifier operations
///
/// Provides a unified API for detecting, validating, and sanitizing
/// biometric identifiers including fingerprints, facial recognition,
/// iris scans, voice prints, DNA sequences, and biometric templates.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::biometric::BiometricIdentifierBuilder;
///
/// let builder = BiometricIdentifierBuilder::new();
///
/// // Detection
/// assert!(builder.is_fingerprint("fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234"));
///
/// // Validation
/// assert!(builder.validate_fingerprint_id("FP-A1B2C3D4"));
///
/// // Sanitization
/// let safe = builder.redact_all_in_text("fingerprint: abc123...");
/// assert!(safe.contains("[FINGERPRINT]"));
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct BiometricIdentifierBuilder;

impl BiometricIdentifierBuilder {
    /// Create a new biometric identifier builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // =========================================================================
    // Detection Methods
    // =========================================================================

    /// Find the type of biometric identifier
    #[must_use]
    pub fn find(&self, value: &str) -> Option<IdentifierType> {
        detection::find_biometric_identifier(value)
    }

    /// Check if value is any biometric identifier
    #[must_use]
    pub fn is_biometric(&self, value: &str) -> bool {
        detection::is_biometric_identifier(value)
    }

    /// Check if value is a fingerprint identifier
    #[must_use]
    pub fn is_fingerprint(&self, value: &str) -> bool {
        detection::is_fingerprint(value)
    }

    /// Check if value is facial recognition data
    #[must_use]
    pub fn is_facial_recognition(&self, value: &str) -> bool {
        detection::is_facial_recognition(value)
    }

    /// Check if value is an iris scan
    #[must_use]
    pub fn is_iris_scan(&self, value: &str) -> bool {
        detection::is_iris_scan(value)
    }

    /// Check if value is a voice print
    #[must_use]
    pub fn is_voice_print(&self, value: &str) -> bool {
        detection::is_voice_print(value)
    }

    /// Check if value is a DNA sequence
    #[must_use]
    pub fn is_dna_sequence(&self, value: &str) -> bool {
        detection::is_dna_sequence(value)
    }

    /// Check if value is a biometric template
    #[must_use]
    pub fn is_biometric_template(&self, value: &str) -> bool {
        detection::is_biometric_template(value)
    }

    /// Check if text contains any biometric identifier
    #[must_use]
    pub fn is_biometric_present(&self, text: &str) -> bool {
        detection::is_biometric_present(text)
    }

    // =========================================================================
    // Test Pattern Detection Methods
    // =========================================================================

    /// Check if fingerprint ID is a known test/sample pattern
    #[must_use]
    pub fn is_test_fingerprint(&self, fingerprint_id: &str) -> bool {
        detection::is_test_fingerprint(fingerprint_id)
    }

    /// Check if DNA sequence is a known test/sample pattern
    #[must_use]
    pub fn is_test_dna(&self, dna: &str) -> bool {
        detection::is_test_dna(dna)
    }

    /// Check if biometric ID is a known test/sample pattern
    #[must_use]
    pub fn is_test_biometric_id(&self, id: &str) -> bool {
        detection::is_test_biometric_id(id)
    }

    // =========================================================================
    // Text Scanning Methods
    // =========================================================================

    /// Detect all fingerprints in text
    #[must_use]
    pub fn detect_fingerprints_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_fingerprints_in_text(text)
    }

    /// Detect all facial data in text
    #[must_use]
    pub fn detect_facial_data_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_facial_data_in_text(text)
    }

    /// Detect all iris scans in text
    #[must_use]
    pub fn detect_iris_scans_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_iris_scans_in_text(text)
    }

    /// Detect all voice prints in text
    #[must_use]
    pub fn detect_voice_prints_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_voice_prints_in_text(text)
    }

    /// Detect all DNA sequences in text
    #[must_use]
    pub fn detect_dna_sequences_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_dna_sequences_in_text(text)
    }

    /// Detect all biometric templates in text
    #[must_use]
    pub fn detect_biometric_templates_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_biometric_templates_in_text(text)
    }

    /// Detect all biometric identifiers in text
    #[must_use]
    pub fn detect_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_all_biometric_in_text(text)
    }

    // =========================================================================
    // Validation Methods
    // =========================================================================

    /// Validate fingerprint ID format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the fingerprint ID format is invalid
    pub fn validate_fingerprint_id(&self, id: &str) -> Result<(), Problem> {
        validation::validate_fingerprint_id(id)
    }

    /// Validate facial ID format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the facial ID format is invalid
    pub fn validate_facial_id(&self, id: &str) -> Result<(), Problem> {
        validation::validate_facial_id(id)
    }

    /// Validate iris ID format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the iris ID format is invalid
    pub fn validate_iris_id(&self, id: &str) -> Result<(), Problem> {
        validation::validate_iris_id(id)
    }

    /// Validate voice ID format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the voice ID format is invalid
    pub fn validate_voice_id(&self, id: &str) -> Result<(), Problem> {
        validation::validate_voice_id(id)
    }

    /// Validate DNA sequence format
    ///
    /// Validates FASTA/FASTQ nucleotide sequences (A, T, C, G) and STR markers.
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the DNA sequence format is invalid
    pub fn validate_dna_sequence(&self, sequence: &str) -> Result<(), Problem> {
        validation::validate_dna_sequence(sequence)
    }

    /// Validate biometric template format
    ///
    /// Validates templates with recognized prefixes (FMR, FIR, FTR, IIR,
    /// biometric, bio_template) and base64-encoded content.
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the biometric template format is invalid
    pub fn validate_biometric_template(&self, template: &str) -> Result<(), Problem> {
        validation::validate_biometric_template(template)
    }

    // =========================================================================
    // Sanitization Methods - Individual Redaction (With Strategy)
    // =========================================================================

    /// Redact a single fingerprint identifier with custom strategy
    #[must_use]
    pub fn redact_fingerprint_with_strategy(
        &self,
        fingerprint: &str,
        strategy: FingerprintRedactionStrategy,
    ) -> String {
        sanitization::redact_fingerprint_with_strategy(fingerprint, strategy)
    }

    /// Redact a single facial recognition identifier with custom strategy
    #[must_use]
    pub fn redact_facial_id_with_strategy(
        &self,
        facial_id: &str,
        strategy: FacialIdRedactionStrategy,
    ) -> String {
        sanitization::redact_facial_id_with_strategy(facial_id, strategy)
    }

    /// Redact a single iris scan identifier with custom strategy
    #[must_use]
    pub fn redact_iris_id_with_strategy(
        &self,
        iris_id: &str,
        strategy: IrisIdRedactionStrategy,
    ) -> String {
        sanitization::redact_iris_id_with_strategy(iris_id, strategy)
    }

    /// Redact a single voice print identifier with custom strategy
    #[must_use]
    pub fn redact_voice_id_with_strategy(
        &self,
        voice_id: &str,
        strategy: VoiceIdRedactionStrategy,
    ) -> String {
        sanitization::redact_voice_id_with_strategy(voice_id, strategy)
    }

    /// Redact a single DNA sequence with custom strategy
    #[must_use]
    pub fn redact_dna_sequence_with_strategy(
        &self,
        dna: &str,
        strategy: DnaRedactionStrategy,
    ) -> String {
        sanitization::redact_dna_sequence_with_strategy(dna, strategy)
    }

    /// Redact a single biometric template with custom strategy
    #[must_use]
    pub fn redact_biometric_template_with_strategy(
        &self,
        template: &str,
        strategy: BiometricTemplateRedactionStrategy,
    ) -> String {
        sanitization::redact_biometric_template_with_strategy(template, strategy)
    }

    // =========================================================================
    // Sanitization Methods - Text Redaction
    // =========================================================================

    /// Redact fingerprints in text
    #[must_use]
    pub fn redact_fingerprints_in_text<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_fingerprints_in_text(text, policy)
    }

    /// Redact facial data in text
    #[must_use]
    pub fn redact_facial_data_in_text<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_facial_data_in_text(text, policy)
    }

    /// Redact iris scans in text
    #[must_use]
    pub fn redact_iris_scans_in_text<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_iris_scans_in_text(text, policy)
    }

    /// Redact voice prints in text
    #[must_use]
    pub fn redact_voice_prints_in_text<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_voice_prints_in_text(text, policy)
    }

    /// Redact DNA sequences in text
    #[must_use]
    pub fn redact_dna_sequences_in_text<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_dna_sequences_in_text(text, policy)
    }

    /// Redact biometric templates in text
    #[must_use]
    pub fn redact_biometric_templates_in_text<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_biometric_templates_in_text(text, policy)
    }

    /// Redact all biometric identifiers in text with explicit policy
    #[must_use]
    pub fn redact_all_in_text_with_policy(
        &self,
        text: &str,
        policy: TextRedactionPolicy,
    ) -> String {
        sanitization::redact_all_biometric_in_text(text, policy)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = BiometricIdentifierBuilder::new();
        assert!(!builder.is_biometric("not biometric"));
    }

    #[test]
    fn test_builder_detection() {
        let builder = BiometricIdentifierBuilder::new();

        assert!(builder.is_fingerprint(
            "fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234"
        ));
        assert!(builder.is_dna_sequence("ATCGATCGATCGATCGATCG"));
        assert!(builder.is_voice_print("voiceprint: VP1234567890ABCDEF"));
    }

    #[test]
    fn test_builder_validation() {
        let builder = BiometricIdentifierBuilder::new();

        assert!(builder.validate_fingerprint_id("FP-A1B2C3D4").is_ok());
        assert!(builder.validate_facial_id("FACE-123456").is_ok());
        assert!(builder.validate_iris_id("IRIS-123456").is_ok());
        assert!(builder.validate_voice_id("VOICE-123456").is_ok());
    }

    #[test]
    fn test_builder_sanitization() {
        let builder = BiometricIdentifierBuilder::new();

        let text = "User fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234";
        let result = builder.redact_all_in_text_with_policy(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[FINGERPRINT]"));
    }

    #[test]
    fn test_builder_individual_redaction_with_strategy() {
        let builder = BiometricIdentifierBuilder::new();

        // Test individual redaction functions with custom strategies
        let fp = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234";
        assert_eq!(
            builder.redact_fingerprint_with_strategy(fp, FingerprintRedactionStrategy::Token),
            "[FINGERPRINT]"
        );
        assert_eq!(
            builder.redact_fingerprint_with_strategy(fp, FingerprintRedactionStrategy::Anonymous),
            "[REDACTED]"
        );

        let face = "dGhpc2lzYWZha2VmYWNlZW5jb2Rpbmc=";
        assert_eq!(
            builder.redact_facial_id_with_strategy(face, FacialIdRedactionStrategy::Token),
            "[FACIAL_DATA]"
        );
        assert_eq!(
            builder.redact_facial_id_with_strategy(face, FacialIdRedactionStrategy::Anonymous),
            "[REDACTED]"
        );

        let iris = "IRIS1234567890ABCDEF";
        assert_eq!(
            builder.redact_iris_id_with_strategy(iris, IrisIdRedactionStrategy::Token),
            "[IRIS_SCAN]"
        );
        assert_eq!(
            builder.redact_iris_id_with_strategy(iris, IrisIdRedactionStrategy::Anonymous),
            "[REDACTED]"
        );

        let voice = "VP1234567890ABCDEF";
        assert_eq!(
            builder.redact_voice_id_with_strategy(voice, VoiceIdRedactionStrategy::Token),
            "[VOICE_PRINT]"
        );
        assert_eq!(
            builder.redact_voice_id_with_strategy(voice, VoiceIdRedactionStrategy::Anonymous),
            "[REDACTED]"
        );

        let dna = "ATCGATCGATCGATCGATCG";
        assert_eq!(
            builder.redact_dna_sequence_with_strategy(dna, DnaRedactionStrategy::Token),
            "[DNA_SEQUENCE]"
        );
        assert_eq!(
            builder.redact_dna_sequence_with_strategy(dna, DnaRedactionStrategy::Anonymous),
            "[REDACTED]"
        );

        let template =
            "FMR: SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        assert_eq!(
            builder.redact_biometric_template_with_strategy(
                template,
                BiometricTemplateRedactionStrategy::Token
            ),
            "[BIOMETRIC_TEMPLATE]"
        );
        assert_eq!(
            builder.redact_biometric_template_with_strategy(
                template,
                BiometricTemplateRedactionStrategy::Anonymous
            ),
            "[REDACTED]"
        );
    }

    #[test]
    fn test_builder_text_scanning() {
        let builder = BiometricIdentifierBuilder::new();

        let text = "fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234, DNA: ATCGATCGATCGATCGATCG";
        let matches = builder.detect_all_in_text(text);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_builder_test_pattern_detection() {
        let builder = BiometricIdentifierBuilder::new();

        // Test fingerprint patterns
        assert!(builder.is_test_fingerprint("TEST-FP-123456"));
        assert!(builder.is_test_fingerprint("000000"));
        assert!(!builder.is_test_fingerprint("FP-A1B2C3D4"));

        // Test DNA patterns
        assert!(builder.is_test_dna("AAAAAAAAAAAAAAAAAAAA"));
        assert!(!builder.is_test_dna("ATCGATCGATCGATCGATCG"));

        // Test generic biometric ID patterns
        assert!(builder.is_test_biometric_id("DEMO_BIOMETRIC"));
        assert!(!builder.is_test_biometric_id("BIO-A1B2C3"));
    }

    #[test]
    fn test_builder_is_biometric_present() {
        let builder = BiometricIdentifierBuilder::new();
        let text = "voiceprint: VP1234567890ABCDEF";
        assert!(builder.is_biometric_present(text));
    }

    #[test]
    fn test_builder_validate_dna_sequence() {
        let builder = BiometricIdentifierBuilder::new();

        assert!(
            builder
                .validate_dna_sequence("ATCGATCGATCGATCGATCG")
                .is_ok()
        );
        assert!(builder.validate_dna_sequence("D3S1358: 15").is_ok());
        assert!(builder.validate_dna_sequence("ATCG").is_err()); // Too short
        assert!(builder.validate_dna_sequence("").is_err());
    }

    #[test]
    fn test_builder_validate_biometric_template() {
        let builder = BiometricIdentifierBuilder::new();

        let content = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        assert!(
            builder
                .validate_biometric_template(&format!("FMR: {content}"))
                .is_ok()
        );
        assert!(
            builder
                .validate_biometric_template(&format!("biometric: {content}"))
                .is_ok()
        );
        assert!(builder.validate_biometric_template("").is_err());
        assert!(
            builder
                .validate_biometric_template("UNKNOWN: data")
                .is_err()
        );
    }
}

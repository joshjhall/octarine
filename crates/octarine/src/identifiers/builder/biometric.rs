//! Biometric identifier builder with observability
//!
//! Wraps `primitives::data::identifiers::BiometricIdentifierBuilder` with observe instrumentation.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.
//!
//! # Why Wrapper Types?
//!
//! Wrapper types are necessary for two reasons:
//! 1. **Visibility bridging**: Primitives are `pub(crate)`, so we can't directly
//!    re-export them as `pub`. Wrapper types provide the public API surface.
//! 2. **API stability**: Wrappers allow the public API to evolve independently
//!    from internal primitives.

use std::borrow::Cow;

use crate::observe::{Problem, event};
use crate::primitives::identifiers::BiometricIdentifierBuilder;

use super::super::types::{
    BiometricTemplateRedactionStrategy, BiometricTextPolicy, DnaRedactionStrategy,
    FacialIdRedactionStrategy, FingerprintRedactionStrategy, IdentifierMatch, IdentifierType,
    IrisIdRedactionStrategy, VoiceIdRedactionStrategy,
};

/// Biometric identifier builder with observability (BIPA compliance)
///
/// This builder wraps `BiometricIdentifierBuilder` and adds observe
/// instrumentation for compliance-grade audit trails.
///
/// # Example
///
/// ```ignore
/// use octarine::data::identifiers::BiometricBuilder;
///
/// let builder = BiometricBuilder::new();
///
/// // Detection
/// if builder.is_fingerprint("fingerprint: abc123...") {
///     println!("Found fingerprint");
/// }
///
/// // Silent mode (no events)
/// let silent = BiometricBuilder::silent();
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct BiometricBuilder {
    /// The underlying primitive builder
    inner: BiometricIdentifierBuilder,
    /// Whether to emit observe events
    emit_events: bool,
}

impl BiometricBuilder {
    /// Create a new BiometricBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: BiometricIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: BiometricIdentifierBuilder::new(),
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

    /// Find the type of biometric identifier
    #[must_use]
    pub fn find(&self, value: &str) -> Option<IdentifierType> {
        let result = self.inner.find(value);

        if self.emit_events && result.is_some() {
            event::debug("Biometric identifier detected".to_string());
        }

        result.map(Into::into)
    }

    /// Check if value is any biometric identifier
    pub fn is_biometric(&self, value: &str) -> bool {
        let result = self.inner.is_biometric(value);

        if self.emit_events && result {
            event::debug("Biometric data detected".to_string());
        }

        result
    }

    /// Check if value is a fingerprint identifier
    pub fn is_fingerprint(&self, value: &str) -> bool {
        let result = self.inner.is_fingerprint(value);

        if self.emit_events && result {
            event::debug("Fingerprint identifier detected".to_string());
        }

        result
    }

    /// Check if value is facial recognition data
    pub fn is_facial_recognition(&self, value: &str) -> bool {
        let result = self.inner.is_facial_recognition(value);

        if self.emit_events && result {
            event::debug("Facial recognition data detected".to_string());
        }

        result
    }

    /// Check if value is an iris scan
    pub fn is_iris_scan(&self, value: &str) -> bool {
        let result = self.inner.is_iris_scan(value);

        if self.emit_events && result {
            event::debug("Iris scan detected".to_string());
        }

        result
    }

    /// Check if value is a voice print
    pub fn is_voice_print(&self, value: &str) -> bool {
        let result = self.inner.is_voice_print(value);

        if self.emit_events && result {
            event::debug("Voice print detected".to_string());
        }

        result
    }

    /// Check if value is a DNA sequence
    pub fn is_dna_sequence(&self, value: &str) -> bool {
        let result = self.inner.is_dna_sequence(value);

        if self.emit_events && result {
            event::debug("DNA sequence detected".to_string());
        }

        result
    }

    /// Check if value is a biometric template
    pub fn is_biometric_template(&self, value: &str) -> bool {
        let result = self.inner.is_biometric_template(value);

        if self.emit_events && result {
            event::debug("Biometric template detected".to_string());
        }

        result
    }

    /// Check if text contains any biometric identifier
    pub fn is_biometric_present(&self, text: &str) -> bool {
        let result = self.inner.is_biometric_present(text);

        if self.emit_events && result {
            event::debug("Biometric data present in text".to_string());
        }

        result
    }

    // =========================================================================
    // Test Pattern Detection Methods
    // =========================================================================

    /// Check if fingerprint ID is a known test/sample pattern
    #[must_use]
    pub fn is_test_fingerprint(&self, fingerprint_id: &str) -> bool {
        self.inner.is_test_fingerprint(fingerprint_id)
    }

    /// Check if DNA sequence is a known test/sample pattern
    #[must_use]
    pub fn is_test_dna(&self, dna: &str) -> bool {
        self.inner.is_test_dna(dna)
    }

    /// Check if biometric ID is a known test/sample pattern
    #[must_use]
    pub fn is_test_biometric_id(&self, id: &str) -> bool {
        self.inner.is_test_biometric_id(id)
    }

    // =========================================================================
    // Text Scanning Methods
    // =========================================================================

    /// Detect all fingerprints in text
    #[must_use]
    pub fn detect_fingerprints_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let results: Vec<IdentifierMatch> = self
            .inner
            .detect_fingerprints_in_text(text)
            .into_iter()
            .map(Into::into)
            .collect();

        if self.emit_events && !results.is_empty() {
            event::debug(format!("Found {} fingerprint(s) in text", results.len()));
        }

        results
    }

    /// Detect all facial data in text
    #[must_use]
    pub fn detect_facial_data_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let results: Vec<IdentifierMatch> = self
            .inner
            .detect_facial_data_in_text(text)
            .into_iter()
            .map(Into::into)
            .collect();

        if self.emit_events && !results.is_empty() {
            event::debug(format!(
                "Found {} facial recognition identifier(s) in text",
                results.len()
            ));
        }

        results
    }

    /// Detect all iris scans in text
    #[must_use]
    pub fn detect_iris_scans_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let results: Vec<IdentifierMatch> = self
            .inner
            .detect_iris_scans_in_text(text)
            .into_iter()
            .map(Into::into)
            .collect();

        if self.emit_events && !results.is_empty() {
            event::debug(format!("Found {} iris scan(s) in text", results.len()));
        }

        results
    }

    /// Detect all voice prints in text
    #[must_use]
    pub fn detect_voice_prints_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let results: Vec<IdentifierMatch> = self
            .inner
            .detect_voice_prints_in_text(text)
            .into_iter()
            .map(Into::into)
            .collect();

        if self.emit_events && !results.is_empty() {
            event::debug(format!("Found {} voice print(s) in text", results.len()));
        }

        results
    }

    /// Detect all DNA sequences in text
    #[must_use]
    pub fn detect_dna_sequences_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let results: Vec<IdentifierMatch> = self
            .inner
            .detect_dna_sequences_in_text(text)
            .into_iter()
            .map(Into::into)
            .collect();

        if self.emit_events && !results.is_empty() {
            event::debug(format!("Found {} DNA sequence(s) in text", results.len()));
        }

        results
    }

    /// Detect all biometric templates in text
    #[must_use]
    pub fn detect_biometric_templates_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let results: Vec<IdentifierMatch> = self
            .inner
            .detect_biometric_templates_in_text(text)
            .into_iter()
            .map(Into::into)
            .collect();

        if self.emit_events && !results.is_empty() {
            event::debug(format!(
                "Found {} biometric template(s) in text",
                results.len()
            ));
        }

        results
    }

    /// Detect all biometric identifiers in text
    #[must_use]
    pub fn detect_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let results: Vec<IdentifierMatch> = self
            .inner
            .detect_all_in_text(text)
            .into_iter()
            .map(Into::into)
            .collect();

        if self.emit_events && !results.is_empty() {
            event::debug(format!(
                "Found {} biometric identifier(s) in text",
                results.len()
            ));
        }

        results
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
        let result = self.inner.validate_fingerprint_id(id);

        if self.emit_events && result.is_err() {
            event::warn("Invalid fingerprint ID format".to_string());
        }

        result
    }

    /// Validate facial ID format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the facial ID format is invalid
    pub fn validate_facial_id(&self, id: &str) -> Result<(), Problem> {
        let result = self.inner.validate_facial_id(id);

        if self.emit_events && result.is_err() {
            event::warn("Invalid facial ID format".to_string());
        }

        result
    }

    /// Validate iris ID format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the iris ID format is invalid
    pub fn validate_iris_id(&self, id: &str) -> Result<(), Problem> {
        let result = self.inner.validate_iris_id(id);

        if self.emit_events && result.is_err() {
            event::warn("Invalid iris ID format".to_string());
        }

        result
    }

    /// Validate voice ID format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the voice ID format is invalid
    pub fn validate_voice_id(&self, id: &str) -> Result<(), Problem> {
        let result = self.inner.validate_voice_id(id);

        if self.emit_events && result.is_err() {
            event::warn("Invalid voice ID format".to_string());
        }

        result
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
        self.inner
            .redact_fingerprint_with_strategy(fingerprint, strategy.into())
    }

    /// Redact a single facial recognition identifier with custom strategy
    #[must_use]
    pub fn redact_facial_id_with_strategy(
        &self,
        facial_id: &str,
        strategy: FacialIdRedactionStrategy,
    ) -> String {
        self.inner
            .redact_facial_id_with_strategy(facial_id, strategy.into())
    }

    /// Redact a single iris scan identifier with custom strategy
    #[must_use]
    pub fn redact_iris_id_with_strategy(
        &self,
        iris_id: &str,
        strategy: IrisIdRedactionStrategy,
    ) -> String {
        self.inner
            .redact_iris_id_with_strategy(iris_id, strategy.into())
    }

    /// Redact a single voice print identifier with custom strategy
    #[must_use]
    pub fn redact_voice_id_with_strategy(
        &self,
        voice_id: &str,
        strategy: VoiceIdRedactionStrategy,
    ) -> String {
        self.inner
            .redact_voice_id_with_strategy(voice_id, strategy.into())
    }

    /// Redact a single DNA sequence with custom strategy
    #[must_use]
    pub fn redact_dna_sequence_with_strategy(
        &self,
        dna: &str,
        strategy: DnaRedactionStrategy,
    ) -> String {
        self.inner
            .redact_dna_sequence_with_strategy(dna, strategy.into())
    }

    /// Redact a single biometric template with custom strategy
    #[must_use]
    pub fn redact_biometric_template_with_strategy(
        &self,
        template: &str,
        strategy: BiometricTemplateRedactionStrategy,
    ) -> String {
        self.inner
            .redact_biometric_template_with_strategy(template, strategy.into())
    }

    // =========================================================================
    // Sanitization Methods - Text Redaction
    // =========================================================================

    /// Redact fingerprints in text
    #[must_use]
    pub fn redact_fingerprints_in_text<'a>(
        &self,
        text: &'a str,
        policy: BiometricTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_fingerprints_in_text(text, policy.into())
    }

    /// Redact facial data in text
    #[must_use]
    pub fn redact_facial_data_in_text<'a>(
        &self,
        text: &'a str,
        policy: BiometricTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_facial_data_in_text(text, policy.into())
    }

    /// Redact iris scans in text
    #[must_use]
    pub fn redact_iris_scans_in_text<'a>(
        &self,
        text: &'a str,
        policy: BiometricTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_iris_scans_in_text(text, policy.into())
    }

    /// Redact voice prints in text
    #[must_use]
    pub fn redact_voice_prints_in_text<'a>(
        &self,
        text: &'a str,
        policy: BiometricTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_voice_prints_in_text(text, policy.into())
    }

    /// Redact DNA sequences in text
    #[must_use]
    pub fn redact_dna_sequences_in_text<'a>(
        &self,
        text: &'a str,
        policy: BiometricTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_dna_sequences_in_text(text, policy.into())
    }

    /// Redact biometric templates in text
    #[must_use]
    pub fn redact_biometric_templates_in_text<'a>(
        &self,
        text: &'a str,
        policy: BiometricTextPolicy,
    ) -> Cow<'a, str> {
        self.inner
            .redact_biometric_templates_in_text(text, policy.into())
    }

    /// Redact all biometric identifiers in text using Complete policy
    #[must_use]
    pub fn redact_all_in_text(&self, text: &str) -> String {
        self.inner
            .redact_all_in_text_with_policy(text, BiometricTextPolicy::Complete.into())
    }

    /// Redact all biometric identifiers in text with custom policy
    #[must_use]
    pub fn redact_all_in_text_with_policy(
        &self,
        text: &str,
        policy: BiometricTextPolicy,
    ) -> String {
        self.inner
            .redact_all_in_text_with_policy(text, policy.into())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = BiometricBuilder::new();
        assert!(builder.emit_events);

        let silent = BiometricBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = BiometricBuilder::new().with_events(false);
        assert!(!builder.emit_events);

        let builder = BiometricBuilder::silent().with_events(true);
        assert!(builder.emit_events);
    }

    #[test]
    fn test_detection_methods() {
        let builder = BiometricBuilder::silent();

        // Test detection returns false for non-biometric data
        assert!(!builder.is_biometric("hello"));
        assert!(!builder.is_fingerprint("hello"));
        assert!(!builder.is_facial_recognition("hello"));
    }
}

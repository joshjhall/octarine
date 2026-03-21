//! Biometric identifier redaction strategies (primitives layer)
//!
//! Type-safe redaction strategies for biometric identifiers with NO logging.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - defines redaction strategies with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Type-safe strategy enums
//!
//! # Design Pattern: Two-Tier Strategy Architecture
//!
//! ## Tier 1: Domain-Specific Strategies (For Individual Identifiers)
//!
//! Each biometric type has its own strategy enum with specific options:
//! - `FingerprintRedactionStrategy` - For single fingerprint IDs
//! - `FacialIdRedactionStrategy` - For single facial recognition IDs
//! - `IrisIdRedactionStrategy` - For single iris scan IDs
//! - `VoiceIdRedactionStrategy` - For single voice print IDs
//! - `DnaRedactionStrategy` - For single DNA sequences
//! - `BiometricTemplateRedactionStrategy` - For single biometric templates
//!
//! ## Tier 2: Generic Text Policy (For Text Scanning)
//!
//! `TextRedactionPolicy` provides a simpler, generic interface for text scanning:
//! - Maps to appropriate domain strategy for each identifier type
//! - Used by `*_in_text()` functions
//! - Consistent across all identifier types
//!
//! # GDPR Article 9 & BIPA Compliance
//!
//! Biometric data is **special category data** under GDPR Article 9:
//! - Requires explicit consent
//! - Subject to Right to Erasure (Article 17)
//! - Stricter breach notification requirements
//!
//! BIPA (Illinois Biometric Information Privacy Act):
//! - Written consent required for biometric capture
//! - Must provide retention schedules
//! - Penalties: $1,000-$5,000 per violation
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::identifiers::biometric::{
//!     FingerprintRedactionStrategy, TextRedactionPolicy, redact_fingerprint, redact_fingerprints_in_text
//! };
//!
//! // Individual identifier with specific strategy
//! let redacted = redact_fingerprint("FP-123456", FingerprintRedactionStrategy::ShowSensor);
//! // Result: "FP-****56"
//!
//! // Text scanning with generic policy
//! let redacted = redact_fingerprints_in_text(
//!     "User FP: FP-123456",
//!     TextRedactionPolicy::Partial
//! );
//! // Result: "User FP: FP-****56"
//! ```

/// Fingerprint redaction strategies
///
/// Controls how fingerprint identifiers are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show sensor metadata: `FP-Sensor5-****`
    ShowSensor,
    /// Token placeholder: `<FINGERPRINT>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// Facial recognition ID redaction strategies
///
/// Controls how facial recognition identifiers are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FacialIdRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show camera metadata: `FACE-Cam12-****`
    ShowCamera,
    /// Token placeholder: `<FACIAL_DATA>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// Iris scan ID redaction strategies
///
/// Controls how iris scan identifiers are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrisIdRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show eye metadata: `IRIS-Left-****` or `IRIS-Right-****`
    ShowEye,
    /// Token placeholder: `<IRIS_SCAN>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// Voice print ID redaction strategies
///
/// Controls how voice print identifiers are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoiceIdRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Token placeholder: `<VOICE_PRINT>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// DNA sequence redaction strategies
///
/// Controls how DNA sequences are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnaRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show marker count: `DNA-13markers-****`
    ShowMarkerCount,
    /// Token placeholder: `<DNA_SEQUENCE>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// Biometric template redaction strategies
///
/// Controls how biometric templates are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiometricTemplateRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show template type: `TEMPLATE-Fingerprint-****`
    ShowType,
    /// Token placeholder: `<BIOMETRIC_TEMPLATE>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// Generic redaction policy for text scanning
///
/// Simpler interface that maps to domain-specific strategies.
/// Used by `*_in_text()` functions for consistent text redaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextRedactionPolicy {
    /// Skip redaction
    Skip,
    /// Partial redaction (show metadata like sensor, camera, eye)
    Partial,
    /// Complete redaction (use type tokens)
    #[default]
    Complete,
    /// Anonymous redaction (generic `[REDACTED]`)
    Anonymous,
}

impl TextRedactionPolicy {
    /// Convert policy to fingerprint strategy
    #[must_use]
    pub const fn to_fingerprint_strategy(self) -> FingerprintRedactionStrategy {
        match self {
            Self::Skip => FingerprintRedactionStrategy::Skip,
            Self::Partial => FingerprintRedactionStrategy::ShowSensor,
            Self::Complete => FingerprintRedactionStrategy::Token,
            Self::Anonymous => FingerprintRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to facial ID strategy
    #[must_use]
    pub const fn to_facial_id_strategy(self) -> FacialIdRedactionStrategy {
        match self {
            Self::Skip => FacialIdRedactionStrategy::Skip,
            Self::Partial => FacialIdRedactionStrategy::ShowCamera,
            Self::Complete => FacialIdRedactionStrategy::Token,
            Self::Anonymous => FacialIdRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to iris ID strategy
    #[must_use]
    pub const fn to_iris_id_strategy(self) -> IrisIdRedactionStrategy {
        match self {
            Self::Skip => IrisIdRedactionStrategy::Skip,
            Self::Partial => IrisIdRedactionStrategy::ShowEye,
            Self::Complete => IrisIdRedactionStrategy::Token,
            Self::Anonymous => IrisIdRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to voice ID strategy
    #[must_use]
    pub const fn to_voice_id_strategy(self) -> VoiceIdRedactionStrategy {
        match self {
            Self::Skip => VoiceIdRedactionStrategy::Skip,
            Self::Partial => VoiceIdRedactionStrategy::Token, // No metadata to show
            Self::Complete => VoiceIdRedactionStrategy::Token,
            Self::Anonymous => VoiceIdRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to DNA strategy
    #[must_use]
    pub const fn to_dna_strategy(self) -> DnaRedactionStrategy {
        match self {
            Self::Skip => DnaRedactionStrategy::Skip,
            Self::Partial => DnaRedactionStrategy::ShowMarkerCount,
            Self::Complete => DnaRedactionStrategy::Token,
            Self::Anonymous => DnaRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to biometric template strategy
    #[must_use]
    pub const fn to_biometric_template_strategy(self) -> BiometricTemplateRedactionStrategy {
        match self {
            Self::Skip => BiometricTemplateRedactionStrategy::Skip,
            Self::Partial => BiometricTemplateRedactionStrategy::ShowType,
            Self::Complete => BiometricTemplateRedactionStrategy::Token,
            Self::Anonymous => BiometricTemplateRedactionStrategy::Anonymous,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_text_policy_to_fingerprint_strategy() {
        assert_eq!(
            TextRedactionPolicy::Skip.to_fingerprint_strategy(),
            FingerprintRedactionStrategy::Skip
        );
        assert_eq!(
            TextRedactionPolicy::Partial.to_fingerprint_strategy(),
            FingerprintRedactionStrategy::ShowSensor
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_fingerprint_strategy(),
            FingerprintRedactionStrategy::Token
        );
        assert_eq!(
            TextRedactionPolicy::Anonymous.to_fingerprint_strategy(),
            FingerprintRedactionStrategy::Anonymous
        );
    }

    #[test]
    fn test_text_policy_to_facial_id_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_facial_id_strategy(),
            FacialIdRedactionStrategy::ShowCamera
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_facial_id_strategy(),
            FacialIdRedactionStrategy::Token
        );
    }

    #[test]
    fn test_text_policy_to_iris_id_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_iris_id_strategy(),
            IrisIdRedactionStrategy::ShowEye
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_iris_id_strategy(),
            IrisIdRedactionStrategy::Token
        );
    }

    #[test]
    fn test_text_policy_to_voice_id_strategy() {
        assert_eq!(
            TextRedactionPolicy::Complete.to_voice_id_strategy(),
            VoiceIdRedactionStrategy::Token
        );
    }

    #[test]
    fn test_text_policy_to_dna_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_dna_strategy(),
            DnaRedactionStrategy::ShowMarkerCount
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_dna_strategy(),
            DnaRedactionStrategy::Token
        );
    }

    #[test]
    fn test_text_policy_to_biometric_template_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_biometric_template_strategy(),
            BiometricTemplateRedactionStrategy::ShowType
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_biometric_template_strategy(),
            BiometricTemplateRedactionStrategy::Token
        );
    }
}

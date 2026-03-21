//! Biometric identifier types
//!
//! Types related to biometric identifiers and their redaction strategies:
//! - Fingerprint, Facial, Iris, Voice, DNA redaction strategies
//! - Biometric template redaction strategy
//! - Biometric text policy

// ============================================================================
// Fingerprint Redaction Strategy
// ============================================================================

/// Fingerprint redaction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FingerprintRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show sensor metadata
    ShowSensor,
    /// Token placeholder: `[FINGERPRINT]`
    #[default]
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

impl From<crate::primitives::identifiers::FingerprintRedactionStrategy>
    for FingerprintRedactionStrategy
{
    fn from(s: crate::primitives::identifiers::FingerprintRedactionStrategy) -> Self {
        use crate::primitives::identifiers::FingerprintRedactionStrategy as P;
        match s {
            P::Skip => Self::Skip,
            P::ShowSensor => Self::ShowSensor,
            P::Token => Self::Token,
            P::Anonymous => Self::Anonymous,
            P::Asterisks => Self::Asterisks,
            P::Hashes => Self::Hashes,
        }
    }
}

impl From<FingerprintRedactionStrategy>
    for crate::primitives::identifiers::FingerprintRedactionStrategy
{
    fn from(s: FingerprintRedactionStrategy) -> Self {
        match s {
            FingerprintRedactionStrategy::Skip => Self::Skip,
            FingerprintRedactionStrategy::ShowSensor => Self::ShowSensor,
            FingerprintRedactionStrategy::Token => Self::Token,
            FingerprintRedactionStrategy::Anonymous => Self::Anonymous,
            FingerprintRedactionStrategy::Asterisks => Self::Asterisks,
            FingerprintRedactionStrategy::Hashes => Self::Hashes,
        }
    }
}

// ============================================================================
// Facial ID Redaction Strategy
// ============================================================================

/// Facial ID redaction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FacialIdRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show camera metadata
    ShowCamera,
    /// Token placeholder: `[FACIAL_DATA]`
    #[default]
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

impl From<crate::primitives::identifiers::FacialIdRedactionStrategy> for FacialIdRedactionStrategy {
    fn from(s: crate::primitives::identifiers::FacialIdRedactionStrategy) -> Self {
        use crate::primitives::identifiers::FacialIdRedactionStrategy as P;
        match s {
            P::Skip => Self::Skip,
            P::ShowCamera => Self::ShowCamera,
            P::Token => Self::Token,
            P::Anonymous => Self::Anonymous,
            P::Asterisks => Self::Asterisks,
            P::Hashes => Self::Hashes,
        }
    }
}

impl From<FacialIdRedactionStrategy> for crate::primitives::identifiers::FacialIdRedactionStrategy {
    fn from(s: FacialIdRedactionStrategy) -> Self {
        match s {
            FacialIdRedactionStrategy::Skip => Self::Skip,
            FacialIdRedactionStrategy::ShowCamera => Self::ShowCamera,
            FacialIdRedactionStrategy::Token => Self::Token,
            FacialIdRedactionStrategy::Anonymous => Self::Anonymous,
            FacialIdRedactionStrategy::Asterisks => Self::Asterisks,
            FacialIdRedactionStrategy::Hashes => Self::Hashes,
        }
    }
}

// ============================================================================
// Iris ID Redaction Strategy
// ============================================================================

/// Iris ID redaction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IrisIdRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show eye metadata
    ShowEye,
    /// Token placeholder: `[IRIS_SCAN]`
    #[default]
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

impl From<crate::primitives::identifiers::IrisIdRedactionStrategy> for IrisIdRedactionStrategy {
    fn from(s: crate::primitives::identifiers::IrisIdRedactionStrategy) -> Self {
        use crate::primitives::identifiers::IrisIdRedactionStrategy as P;
        match s {
            P::Skip => Self::Skip,
            P::ShowEye => Self::ShowEye,
            P::Token => Self::Token,
            P::Anonymous => Self::Anonymous,
            P::Asterisks => Self::Asterisks,
            P::Hashes => Self::Hashes,
        }
    }
}

impl From<IrisIdRedactionStrategy> for crate::primitives::identifiers::IrisIdRedactionStrategy {
    fn from(s: IrisIdRedactionStrategy) -> Self {
        match s {
            IrisIdRedactionStrategy::Skip => Self::Skip,
            IrisIdRedactionStrategy::ShowEye => Self::ShowEye,
            IrisIdRedactionStrategy::Token => Self::Token,
            IrisIdRedactionStrategy::Anonymous => Self::Anonymous,
            IrisIdRedactionStrategy::Asterisks => Self::Asterisks,
            IrisIdRedactionStrategy::Hashes => Self::Hashes,
        }
    }
}

// ============================================================================
// Voice ID Redaction Strategy
// ============================================================================

/// Voice ID redaction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VoiceIdRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Token placeholder: `[VOICE_PRINT]`
    #[default]
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

impl From<crate::primitives::identifiers::VoiceIdRedactionStrategy> for VoiceIdRedactionStrategy {
    fn from(s: crate::primitives::identifiers::VoiceIdRedactionStrategy) -> Self {
        use crate::primitives::identifiers::VoiceIdRedactionStrategy as P;
        match s {
            P::Skip => Self::Skip,
            P::Token => Self::Token,
            P::Anonymous => Self::Anonymous,
            P::Asterisks => Self::Asterisks,
            P::Hashes => Self::Hashes,
        }
    }
}

impl From<VoiceIdRedactionStrategy> for crate::primitives::identifiers::VoiceIdRedactionStrategy {
    fn from(s: VoiceIdRedactionStrategy) -> Self {
        match s {
            VoiceIdRedactionStrategy::Skip => Self::Skip,
            VoiceIdRedactionStrategy::Token => Self::Token,
            VoiceIdRedactionStrategy::Anonymous => Self::Anonymous,
            VoiceIdRedactionStrategy::Asterisks => Self::Asterisks,
            VoiceIdRedactionStrategy::Hashes => Self::Hashes,
        }
    }
}

// ============================================================================
// DNA Redaction Strategy
// ============================================================================

/// DNA redaction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnaRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show marker count
    ShowMarkerCount,
    /// Token placeholder: `[DNA_SEQUENCE]`
    #[default]
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

impl From<crate::primitives::identifiers::DnaRedactionStrategy> for DnaRedactionStrategy {
    fn from(s: crate::primitives::identifiers::DnaRedactionStrategy) -> Self {
        use crate::primitives::identifiers::DnaRedactionStrategy as P;
        match s {
            P::Skip => Self::Skip,
            P::ShowMarkerCount => Self::ShowMarkerCount,
            P::Token => Self::Token,
            P::Anonymous => Self::Anonymous,
            P::Asterisks => Self::Asterisks,
            P::Hashes => Self::Hashes,
        }
    }
}

impl From<DnaRedactionStrategy> for crate::primitives::identifiers::DnaRedactionStrategy {
    fn from(s: DnaRedactionStrategy) -> Self {
        match s {
            DnaRedactionStrategy::Skip => Self::Skip,
            DnaRedactionStrategy::ShowMarkerCount => Self::ShowMarkerCount,
            DnaRedactionStrategy::Token => Self::Token,
            DnaRedactionStrategy::Anonymous => Self::Anonymous,
            DnaRedactionStrategy::Asterisks => Self::Asterisks,
            DnaRedactionStrategy::Hashes => Self::Hashes,
        }
    }
}

// ============================================================================
// Biometric Template Redaction Strategy
// ============================================================================

/// Biometric template redaction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BiometricTemplateRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show template type
    ShowType,
    /// Token placeholder: `[BIOMETRIC_TEMPLATE]`
    #[default]
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

impl From<crate::primitives::identifiers::BiometricTemplateRedactionStrategy>
    for BiometricTemplateRedactionStrategy
{
    fn from(s: crate::primitives::identifiers::BiometricTemplateRedactionStrategy) -> Self {
        use crate::primitives::identifiers::BiometricTemplateRedactionStrategy as P;
        match s {
            P::Skip => Self::Skip,
            P::ShowType => Self::ShowType,
            P::Token => Self::Token,
            P::Anonymous => Self::Anonymous,
            P::Asterisks => Self::Asterisks,
            P::Hashes => Self::Hashes,
        }
    }
}

impl From<BiometricTemplateRedactionStrategy>
    for crate::primitives::identifiers::BiometricTemplateRedactionStrategy
{
    fn from(s: BiometricTemplateRedactionStrategy) -> Self {
        match s {
            BiometricTemplateRedactionStrategy::Skip => Self::Skip,
            BiometricTemplateRedactionStrategy::ShowType => Self::ShowType,
            BiometricTemplateRedactionStrategy::Token => Self::Token,
            BiometricTemplateRedactionStrategy::Anonymous => Self::Anonymous,
            BiometricTemplateRedactionStrategy::Asterisks => Self::Asterisks,
            BiometricTemplateRedactionStrategy::Hashes => Self::Hashes,
        }
    }
}

// ============================================================================
// Biometric Text Policy
// ============================================================================

/// Biometric text redaction policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BiometricTextPolicy {
    /// Skip redaction
    Skip,
    /// Partial redaction (show metadata)
    Partial,
    /// Complete redaction (use type tokens)
    #[default]
    Complete,
    /// Anonymous redaction (generic `[REDACTED]`)
    Anonymous,
}

impl From<crate::primitives::identifiers::BiometricTextPolicy> for BiometricTextPolicy {
    fn from(p: crate::primitives::identifiers::BiometricTextPolicy) -> Self {
        use crate::primitives::identifiers::BiometricTextPolicy as P;
        match p {
            P::Skip => Self::Skip,
            P::Partial => Self::Partial,
            P::Complete => Self::Complete,
            P::Anonymous => Self::Anonymous,
        }
    }
}

impl From<BiometricTextPolicy> for crate::primitives::identifiers::BiometricTextPolicy {
    fn from(p: BiometricTextPolicy) -> Self {
        match p {
            BiometricTextPolicy::Skip => Self::Skip,
            BiometricTextPolicy::Partial => Self::Partial,
            BiometricTextPolicy::Complete => Self::Complete,
            BiometricTextPolicy::Anonymous => Self::Anonymous,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_fingerprint_default() {
        assert_eq!(
            FingerprintRedactionStrategy::default(),
            FingerprintRedactionStrategy::Token
        );
    }

    #[test]
    fn test_biometric_text_policy_default() {
        assert_eq!(
            BiometricTextPolicy::default(),
            BiometricTextPolicy::Complete
        );
    }

    #[test]
    fn test_dna_redaction_strategy_conversion() {
        let public = DnaRedactionStrategy::ShowMarkerCount;
        let primitive: crate::primitives::identifiers::DnaRedactionStrategy = public.into();
        let back: DnaRedactionStrategy = primitive.into();
        assert_eq!(back, DnaRedactionStrategy::ShowMarkerCount);
    }
}

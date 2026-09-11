//! Biometric PII scanning (fingerprint, face, voice, iris, DNA)
//!
//! Part of the PII scanner domain split (issue #411).

use super::super::super::types::PiiType;
use crate::primitives::identifiers::BiometricIdentifierBuilder;

/// Scan for biometric data (fingerprint, face, voice, iris, DNA)
pub(super) fn scan_biometric(text: &str, pii_types: &mut Vec<PiiType>) {
    let biometric = BiometricIdentifierBuilder::new();

    if biometric.is_biometric_present(text) {
        if !biometric.detect_fingerprints_in_text(text).is_empty() {
            pii_types.push(PiiType::FingerprintId);
        }
        if !biometric.detect_facial_data_in_text(text).is_empty() {
            pii_types.push(PiiType::FaceId);
        }
        if !biometric.detect_voice_prints_in_text(text).is_empty() {
            pii_types.push(PiiType::VoiceId);
        }
        if !biometric.detect_iris_scans_in_text(text).is_empty() {
            pii_types.push(PiiType::IrisId);
        }
        if !biometric.detect_dna_sequences_in_text(text).is_empty() {
            pii_types.push(PiiType::DnaId);
        }
        if !biometric
            .detect_biometric_templates_in_text(text)
            .is_empty()
        {
            pii_types.push(PiiType::BiometricTemplate);
        }
    }
}

/// Coarse pre-filter for the biometric domain.
pub(super) fn is_biometric_present(text: &str) -> bool {
    BiometricIdentifierBuilder::new().is_biometric_present(text)
}

//! Biometric data redaction functions
//!
//! Redacts fingerprints, facial data, voice prints, iris scans, and DNA sequences.

use super::super::config::RedactionProfile;
use crate::primitives::identifiers::{BiometricIdentifierBuilder, BiometricTextPolicy};

/// Get biometric text redaction policy from profile
fn policy_from_profile(profile: RedactionProfile) -> BiometricTextPolicy {
    match profile {
        RedactionProfile::ProductionStrict => BiometricTextPolicy::Complete,
        RedactionProfile::ProductionLenient => BiometricTextPolicy::Partial,
        RedactionProfile::Development => BiometricTextPolicy::Partial,
        RedactionProfile::Testing => BiometricTextPolicy::Skip,
    }
}

/// Redact fingerprints based on profile
pub(super) fn redact_fingerprints(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = BiometricIdentifierBuilder::new();
            let policy = policy_from_profile(profile);
            builder
                .redact_fingerprints_in_text(text, policy)
                .into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact facial data based on profile
pub(super) fn redact_facial_data(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = BiometricIdentifierBuilder::new();
            let policy = policy_from_profile(profile);
            builder
                .redact_facial_data_in_text(text, policy)
                .into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact voice prints based on profile
pub(super) fn redact_voice_prints(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = BiometricIdentifierBuilder::new();
            let policy = policy_from_profile(profile);
            builder
                .redact_voice_prints_in_text(text, policy)
                .into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact iris scans based on profile
pub(super) fn redact_iris_scans(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = BiometricIdentifierBuilder::new();
            let policy = policy_from_profile(profile);
            builder.redact_iris_scans_in_text(text, policy).into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact DNA sequences based on profile
pub(super) fn redact_dna_sequences(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = BiometricIdentifierBuilder::new();
            let policy = policy_from_profile(profile);
            builder
                .redact_dna_sequences_in_text(text, policy)
                .into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // ===== Fingerprints =====

    #[test]
    fn test_redact_fingerprints_strict() {
        let text = "User fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234";
        let result = redact_fingerprints(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[FINGERPRINT]"));
        assert!(!result.contains("a1b2c3d4"));
    }

    #[test]
    fn test_redact_fingerprints_testing_unchanged() {
        let text = "User fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234";
        let result = redact_fingerprints(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_fingerprints_no_pii() {
        let text = "Biometric enrollment completed";
        let result = redact_fingerprints(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    // ===== Facial Data =====

    #[test]
    fn test_redact_facial_data_strict() {
        let text = "face_encoding: dGhpc2lzYWZha2VmYWNlZW5jb2Rpbmc=";
        let result = redact_facial_data(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[FACIAL_DATA]"));
    }

    #[test]
    fn test_redact_facial_data_testing_unchanged() {
        let text = "face_encoding: dGhpc2lzYWZha2VmYWNlZW5jb2Rpbmc=";
        let result = redact_facial_data(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_facial_data_no_pii() {
        let text = "Face recognition system online";
        let result = redact_facial_data(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    // ===== Voice Prints =====

    #[test]
    fn test_redact_voice_prints_strict() {
        let text = "voiceprint: VP1234567890ABCDEF";
        let result = redact_voice_prints(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[VOICE_PRINT]"));
    }

    #[test]
    fn test_redact_voice_prints_testing_unchanged() {
        let text = "voiceprint: VP1234567890ABCDEF";
        let result = redact_voice_prints(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_voice_prints_no_pii() {
        let text = "Voice authentication enabled";
        let result = redact_voice_prints(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    // ===== Iris Scans =====

    #[test]
    fn test_redact_iris_scans_strict() {
        let text = "iris_id: IRIS1234567890ABCDEF";
        let result = redact_iris_scans(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[IRIS_SCAN]"));
    }

    #[test]
    fn test_redact_iris_scans_testing_unchanged() {
        let text = "iris_id: IRIS1234567890ABCDEF";
        let result = redact_iris_scans(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_iris_scans_no_pii() {
        let text = "Iris scanner calibrated";
        let result = redact_iris_scans(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    // ===== DNA Sequences =====

    #[test]
    fn test_redact_dna_sequences_strict() {
        let text = "Sequence: ATCGATCGATCGATCGATCG";
        let result = redact_dna_sequences(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[DNA_SEQUENCE]"));
    }

    #[test]
    fn test_redact_dna_sequences_testing_unchanged() {
        let text = "Sequence: ATCGATCGATCGATCGATCG";
        let result = redact_dna_sequences(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_dna_sequences_no_pii() {
        let text = "DNA analysis complete";
        let result = redact_dna_sequences(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }
}

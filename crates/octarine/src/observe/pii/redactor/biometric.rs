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

/// Redact biometric templates based on profile
pub(super) fn redact_biometric_templates(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = BiometricIdentifierBuilder::new();
            let policy = policy_from_profile(profile);
            builder
                .redact_biometric_templates_in_text(text, policy)
                .into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

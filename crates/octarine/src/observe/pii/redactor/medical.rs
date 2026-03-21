//! Medical (PHI) redaction functions
//!
//! Redacts MRNs, NPIs, insurance numbers, ICD codes, and prescriptions.

use super::super::config::RedactionProfile;
use crate::primitives::identifiers::{MedicalIdentifierBuilder, MedicalTextPolicy};

/// Get medical text redaction policy from profile
fn policy_from_profile(profile: RedactionProfile) -> MedicalTextPolicy {
    match profile {
        RedactionProfile::ProductionStrict => MedicalTextPolicy::Complete,
        RedactionProfile::ProductionLenient => MedicalTextPolicy::Partial,
        RedactionProfile::Development => MedicalTextPolicy::Partial,
        RedactionProfile::Testing => MedicalTextPolicy::Skip,
    }
}

/// Redact medical record numbers based on profile
pub(super) fn redact_medical_record_numbers(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = MedicalIdentifierBuilder::new();
            let policy = policy_from_profile(profile);
            builder.redact_mrn_in_text(text, policy).into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact provider IDs (NPI) based on profile
pub(super) fn redact_provider_ids(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = MedicalIdentifierBuilder::new();
            let policy = policy_from_profile(profile);
            builder
                .redact_provider_ids_in_text(text, policy)
                .into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact insurance numbers based on profile
pub(super) fn redact_insurance_numbers(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = MedicalIdentifierBuilder::new();
            let policy = policy_from_profile(profile);
            builder.redact_insurance_in_text(text, policy).into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact medical codes (ICD) based on profile
pub(super) fn redact_medical_codes(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = MedicalIdentifierBuilder::new();
            let policy = policy_from_profile(profile);
            builder
                .redact_medical_codes_in_text(text, policy)
                .into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact prescriptions based on profile
pub(super) fn redact_prescriptions(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = MedicalIdentifierBuilder::new();
            let policy = policy_from_profile(profile);
            builder
                .redact_prescriptions_in_text(text, policy)
                .into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

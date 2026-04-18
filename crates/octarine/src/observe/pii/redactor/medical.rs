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

/// Redact DEA numbers based on profile
pub(super) fn redact_dea_numbers(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = MedicalIdentifierBuilder::new();
            let policy = policy_from_profile(profile);
            builder
                .redact_dea_numbers_in_text(text, policy)
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

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // ===== Medical Record Numbers =====

    #[test]
    fn test_redact_mrn_strict() {
        let text = "Patient MRN: 12345678";
        let result = redact_medical_record_numbers(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[MEDICAL_RECORD]"));
        assert!(!result.contains("12345678"));
    }

    #[test]
    fn test_redact_mrn_testing_unchanged() {
        let text = "Patient MRN: 12345678";
        let result = redact_medical_record_numbers(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_mrn_no_pii() {
        let text = "No medical data here";
        let result = redact_medical_record_numbers(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    // ===== Provider IDs (NPI) =====

    #[test]
    fn test_redact_provider_ids_strict() {
        let text = "Doctor NPI: 1234567890";
        let result = redact_provider_ids(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[PROVIDER_ID]"));
        assert!(!result.contains("1234567890"));
    }

    #[test]
    fn test_redact_provider_ids_testing_unchanged() {
        let text = "Doctor NPI: 1234567890";
        let result = redact_provider_ids(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_provider_ids_no_pii() {
        let text = "Regular doctor visit notes";
        let result = redact_provider_ids(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    // ===== Insurance Numbers =====

    #[test]
    fn test_redact_insurance_strict() {
        let text = "Policy Number: ABC123456789";
        let result = redact_insurance_numbers(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[INSURANCE_INFO]"));
        assert!(!result.contains("ABC123456789"));
    }

    #[test]
    fn test_redact_insurance_testing_unchanged() {
        let text = "Policy Number: ABC123456789";
        let result = redact_insurance_numbers(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_insurance_no_pii() {
        let text = "Insurance claim filed successfully";
        let result = redact_insurance_numbers(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    // ===== Medical Codes =====

    #[test]
    fn test_redact_medical_codes_strict() {
        let text = "Diagnosis: A01.1, Procedure CPT: 99213";
        let result = redact_medical_codes(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[MEDICAL_CODE]"));
    }

    #[test]
    fn test_redact_medical_codes_testing_unchanged() {
        let text = "Diagnosis: A01.1, Procedure CPT: 99213";
        let result = redact_medical_codes(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_medical_codes_no_pii() {
        let text = "General health checkup completed";
        let result = redact_medical_codes(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    // ===== DEA Numbers =====

    #[test]
    fn test_redact_dea_numbers_strict() {
        let text = "DEA: AB1234563";
        let result = redact_dea_numbers(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[DEA_NUMBER]"));
        assert!(!result.contains("AB1234563"));
    }

    #[test]
    fn test_redact_dea_numbers_testing_unchanged() {
        let text = "DEA: AB1234563";
        let result = redact_dea_numbers(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_dea_numbers_no_pii() {
        let text = "Pharmacy compliance review complete";
        let result = redact_dea_numbers(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    // ===== Prescriptions =====

    #[test]
    fn test_redact_prescriptions_strict() {
        let text = "RX# 123456789";
        let result = redact_prescriptions(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[PRESCRIPTION]"));
        assert!(!result.contains("123456789"));
    }

    #[test]
    fn test_redact_prescriptions_testing_unchanged() {
        let text = "RX# 123456789";
        let result = redact_prescriptions(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_prescriptions_no_pii() {
        let text = "Prescription was picked up on time";
        let result = redact_prescriptions(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }
}

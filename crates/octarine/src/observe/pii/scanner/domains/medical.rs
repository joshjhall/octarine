//! Medical PII scanning (MRN, NPI, insurance, ICD codes, prescriptions)
//!
//! Part of the PII scanner domain split (issue #411).

use super::super::super::types::PiiType;
use crate::primitives::identifiers::MedicalIdentifierBuilder;

/// Scan for medical PII (MRN, NPI, insurance, ICD codes, prescriptions)
pub(super) fn scan_medical(text: &str, pii_types: &mut Vec<PiiType>) {
    let medical = MedicalIdentifierBuilder::new();

    if medical.is_medical_identifier_present(text) {
        if !medical.find_mrns_in_text(text).is_empty() {
            pii_types.push(PiiType::Mrn);
        }
        if !medical.find_provider_ids_in_text(text).is_empty() {
            pii_types.push(PiiType::Npi);
        }
        if !medical.find_insurance_ids_in_text(text).is_empty() {
            pii_types.push(PiiType::InsuranceNumber);
        }
        if !medical.find_medical_codes_in_text(text).is_empty() {
            pii_types.push(PiiType::IcdCode);
        }
        if !medical.find_prescriptions_in_text(text).is_empty() {
            pii_types.push(PiiType::PrescriptionNumber);
        }
        if !medical.find_dea_numbers_in_text(text).is_empty() {
            pii_types.push(PiiType::DeaNumber);
        }
        if !medical.find_us_clias_in_text(text).is_empty() {
            pii_types.push(PiiType::UsClia);
        }
    }
}

/// Coarse pre-filter for the medical domain.
pub(super) fn is_medical_present(text: &str) -> bool {
    MedicalIdentifierBuilder::new().is_medical_identifier_present(text)
}

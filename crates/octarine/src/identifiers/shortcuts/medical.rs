//! Medical identifier shortcuts (HIPAA — MRN, NPI, DEA, insurance, prescription, ICD/CPT codes).
//!
//! Convenience functions over [`MedicalBuilder`](super::super::MedicalBuilder).

use crate::observe::Problem;

use super::super::MedicalBuilder;
use super::super::types::IdentifierMatch;

/// Check if value is a medical record number
#[must_use]
pub fn is_medical_record_number(value: &str) -> bool {
    MedicalBuilder::new().is_mrn(value)
}

/// Check if value is a provider ID (NPI — National Provider Identifier)
#[must_use]
pub fn is_provider_id(value: &str) -> bool {
    MedicalBuilder::new().is_provider_id(value)
}

/// Check if value is a DEA number (format + checksum)
#[must_use]
pub fn is_dea_number(value: &str) -> bool {
    MedicalBuilder::new().is_dea_number(value)
}

/// Check if value is a health insurance number
#[must_use]
pub fn is_health_insurance(value: &str) -> bool {
    MedicalBuilder::new().is_insurance(value)
}

/// Check if value is a prescription number
#[must_use]
pub fn is_prescription(value: &str) -> bool {
    MedicalBuilder::new().is_prescription(value)
}

/// Check if value is a medical code (ICD-10, CPT)
#[must_use]
pub fn is_medical_code(value: &str) -> bool {
    MedicalBuilder::new().is_medical_code(value)
}

/// Validate a medical record number format
///
/// # Errors
///
/// Returns `Problem` if the MRN format is invalid.
pub fn validate_mrn(mrn: &str) -> Result<(), Problem> {
    MedicalBuilder::new().validate_mrn(mrn)
}

/// Validate an NPI (National Provider Identifier) format and checksum
///
/// # Errors
///
/// Returns `Problem` if the NPI format or checksum is invalid.
pub fn validate_npi(npi: &str) -> Result<(), Problem> {
    MedicalBuilder::new().validate_npi(npi)
}

/// Find all medical record numbers in text
#[must_use]
pub fn find_medical_records(text: &str) -> Vec<IdentifierMatch> {
    MedicalBuilder::new().find_mrns_in_text(text)
}

/// Redact all medical identifiers in text
#[must_use]
pub fn redact_medical(text: &str) -> String {
    MedicalBuilder::new().redact_all_in_text(text)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_medical_identifier_shortcuts() {
        assert!(is_provider_id("NPI: 1234567890"));
        assert!(!is_provider_id("NPI: 3123456789")); // must start with 1 or 2

        assert!(is_dea_number("AB1234563")); // valid checksum
        assert!(!is_dea_number("AB1234560")); // invalid checksum

        assert!(is_health_insurance("Policy Number: ABC123456789"));
        assert!(!is_health_insurance("not insurance"));

        assert!(is_prescription("RX# 123456789"));
        assert!(!is_prescription("not a prescription"));

        assert!(is_medical_code("A01.1")); // ICD-10
        assert!(is_medical_code("CPT: 99213"));
        assert!(!is_medical_code("not a code"));
    }

    #[test]
    fn test_validate_mrn_shortcut() {
        assert!(validate_mrn("MRN-123456").is_ok());
        assert!(validate_mrn("ABC").is_err()); // too short
        assert!(validate_mrn("MRN@123").is_err()); // invalid character
    }

    #[test]
    fn test_validate_npi_shortcut() {
        assert!(validate_npi("1245319599").is_ok()); // valid checksum
        assert!(validate_npi("1234567890").is_err()); // invalid checksum
        assert!(validate_npi("not-an-npi").is_err());
    }
}

//! Individual medical identifier redaction functions
//!
//! Domain-specific redaction for single medical identifiers.
//! Each identifier type has its own strategy enum with only valid options.
//!
//! # HIPAA Compliance
//!
//! All identifiers require redaction for de-identification under:
//! - 45 CFR 164.514(b)(2) - Safe Harbor method

use super::super::detection;
use super::super::redaction::{
    InsuranceRedactionStrategy, MedicalCodeRedactionStrategy, MrnRedactionStrategy,
    NpiRedactionStrategy, PrescriptionRedactionStrategy,
};
use crate::primitives::data::tokens::RedactionTokenCore;

/// Redact a medical record number (MRN) with explicit strategy
///
/// Provides type-safe MRN redaction with compile-time guarantees that only valid
/// MRN strategies can be applied. Protected Health Information under HIPAA Privacy Rule.
///
/// # Arguments
///
/// * `mrn` - Medical record number to redact
/// * `strategy` - MRN-specific redaction strategy (ShowPrefix, ShowFacility, Token, etc.)
///
/// # Returns
///
/// Redacted MRN string according to strategy:
/// - **None**: Returns MRN as-is (dev/qa only)
/// - **ShowPrefix**: `"MRN-12****"`
/// - **ShowFacility**: `"[MRN-HospitalA-****]"` (requires metadata)
/// - **Token**: `"[MEDICAL_RECORD]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"*********"` (length-preserving)
/// - **Hashes**: `"#########"` (length-preserving)
///
/// # Security
///
/// Invalid MRNs return full redaction token to avoid leaking partial information.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::{MrnRedactionStrategy, redact_mrn_with_strategy};
///
/// let mrn = "MRN-123456";
///
/// // Partial redaction - show prefix
/// assert_eq!(redact_mrn_with_strategy(mrn, MrnRedactionStrategy::ShowPrefix), "MRN-12****");
///
/// // Full redaction - type token
/// assert_eq!(redact_mrn_with_strategy(mrn, MrnRedactionStrategy::Token), "[MEDICAL_RECORD]");
///
/// // Invalid MRN - always fully redacted
/// assert_eq!(redact_mrn_with_strategy("invalid", MrnRedactionStrategy::ShowPrefix), "[MEDICAL_RECORD]");
/// ```
#[must_use]
pub fn redact_mrn_with_strategy(mrn: &str, strategy: MrnRedactionStrategy) -> String {
    // No redaction - return as-is (dev/qa)
    if matches!(strategy, MrnRedactionStrategy::Skip) {
        return mrn.to_string();
    }

    // Validate format first to prevent information leakage
    if !detection::is_medical_record_number(mrn) {
        return RedactionTokenCore::MedicalRecord.into();
    }

    match strategy {
        MrnRedactionStrategy::Skip => mrn.to_string(),

        MrnRedactionStrategy::ShowPrefix => {
            // Show first 2-6 characters: "MRN-12****" or "PAT-98****"
            if mrn.len() <= 6 {
                RedactionTokenCore::MedicalRecord.into()
            } else if mrn.contains("MRN") {
                format!("MRN-{}****", &mrn[4..6.min(mrn.len())])
            } else if mrn.contains("PAT") {
                format!("PAT-{}****", &mrn[4..6.min(mrn.len())])
            } else if mrn.starts_with("MR-") {
                format!("MR-{}****", &mrn[3..5.min(mrn.len())])
            } else {
                // Generic prefix
                format!("{}****", &mrn[0..4.min(mrn.len())])
            }
        }

        MrnRedactionStrategy::ShowFacility => {
            // Would require metadata - default to generic token
            "[MRN-****]".to_string()
        }

        MrnRedactionStrategy::Token => RedactionTokenCore::MedicalRecord.into(),
        MrnRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        MrnRedactionStrategy::Asterisks => "*".repeat(mrn.len()),
        MrnRedactionStrategy::Hashes => "#".repeat(mrn.len()),
    }
}

/// Redact a health insurance number with explicit strategy
///
/// Provides type-safe insurance number redaction. Protected under HIPAA and state privacy laws.
///
/// # Arguments
///
/// * `insurance` - Insurance number to redact
/// * `strategy` - Insurance-specific redaction strategy (ShowProvider, ShowLast4, Token, etc.)
///
/// # Returns
///
/// Redacted insurance string according to strategy:
/// - **None**: Returns insurance as-is (dev/qa only)
/// - **ShowProvider**: `"[INSURANCE-BCBS-****]"` (requires metadata)
/// - **ShowLast4**: `"******1234"` (similar to PCI-DSS)
/// - **Token**: `"[INSURANCE_INFO]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"*************"` (length-preserving)
/// - **Hashes**: `"#############"` (length-preserving)
///
/// # Security
///
/// Invalid insurance numbers return full redaction token to avoid information leakage.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::{InsuranceRedactionStrategy, redact_insurance_number_with_strategy};
///
/// let insurance = "Policy: ABC123456789";
///
/// // Partial - show last 4
/// assert_eq!(redact_insurance_number_with_strategy(insurance, InsuranceRedactionStrategy::ShowLast4), "******6789");
///
/// // Full - type token
/// assert_eq!(redact_insurance_number_with_strategy(insurance, InsuranceRedactionStrategy::Token), "[INSURANCE_INFO]");
/// ```
#[must_use]
pub fn redact_insurance_number_with_strategy(
    insurance: &str,
    strategy: InsuranceRedactionStrategy,
) -> String {
    // No redaction - return as-is (dev/qa)
    if matches!(strategy, InsuranceRedactionStrategy::Skip) {
        return insurance.to_string();
    }

    // Validate format to prevent information leakage
    if !detection::is_health_insurance(insurance) {
        return RedactionTokenCore::InsuranceInfo.into();
    }

    match strategy {
        InsuranceRedactionStrategy::Skip => insurance.to_string(),

        InsuranceRedactionStrategy::ShowProvider => {
            // Would require metadata - default to generic token
            "[INSURANCE-****]".to_string()
        }

        InsuranceRedactionStrategy::ShowLast4 => {
            // Show last 4 characters (PCI-DSS style)
            if insurance.len() <= 4 {
                RedactionTokenCore::InsuranceInfo.into()
            } else {
                let last4 = &insurance[insurance.len().saturating_sub(4)..];
                let prefix_len = insurance.len().saturating_sub(4).min(6);
                format!("{}****{}", "*".repeat(prefix_len), last4)
            }
        }

        InsuranceRedactionStrategy::Token => RedactionTokenCore::InsuranceInfo.into(),
        InsuranceRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        InsuranceRedactionStrategy::Asterisks => "*".repeat(insurance.len()),
        InsuranceRedactionStrategy::Hashes => "#".repeat(insurance.len()),
    }
}

/// Redact a prescription number with explicit strategy
///
/// Provides type-safe prescription number redaction. Protected Health Information under HIPAA.
///
/// # Arguments
///
/// * `prescription` - Prescription number to redact
/// * `strategy` - Prescription-specific redaction strategy (ShowPharmacy, Token, etc.)
///
/// # Returns
///
/// Redacted prescription string according to strategy:
/// - **None**: Returns prescription as-is (dev/qa only)
/// - **ShowPharmacy**: `"[RX-CVS-****]"` (requires metadata)
/// - **Token**: `"[PRESCRIPTION]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"*********"` (length-preserving)
/// - **Hashes**: `"#########"` (length-preserving)
///
/// # Security
///
/// Invalid prescriptions return full redaction token to avoid information leakage.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::{PrescriptionRedactionStrategy, redact_prescription_number_with_strategy};
///
/// let rx = "RX# 123456789";
///
/// // Full redaction - type token
/// assert_eq!(redact_prescription_number_with_strategy(rx, PrescriptionRedactionStrategy::Token), "[PRESCRIPTION]");
/// ```
#[must_use]
pub fn redact_prescription_number_with_strategy(
    prescription: &str,
    strategy: PrescriptionRedactionStrategy,
) -> String {
    // No redaction - return as-is (dev/qa)
    if matches!(strategy, PrescriptionRedactionStrategy::Skip) {
        return prescription.to_string();
    }

    // Validate format to prevent information leakage
    if !detection::is_prescription(prescription) {
        return RedactionTokenCore::Prescription.into();
    }

    match strategy {
        PrescriptionRedactionStrategy::Skip => prescription.to_string(),

        PrescriptionRedactionStrategy::ShowPharmacy => {
            // Would require metadata - default to generic token
            "[RX-****]".to_string()
        }

        PrescriptionRedactionStrategy::Token => RedactionTokenCore::Prescription.into(),
        PrescriptionRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        PrescriptionRedactionStrategy::Asterisks => "*".repeat(prescription.len()),
        PrescriptionRedactionStrategy::Hashes => "#".repeat(prescription.len()),
    }
}

/// Redact a National Provider Identifier (NPI) with explicit strategy
///
/// Provides type-safe NPI redaction. NPI is public information but may be redacted for privacy.
///
/// # Arguments
///
/// * `npi` - National Provider Identifier to redact
/// * `strategy` - NPI-specific redaction strategy (ShowFirst4, Token, etc.)
///
/// # Returns
///
/// Redacted NPI string according to strategy:
/// - **None**: Returns NPI as-is (NPI is public info)
/// - **ShowFirst4**: `"1234-***-***"`
/// - **Token**: `"[PROVIDER_ID]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"**********"` (length-preserving)
/// - **Hashes**: `"##########"` (length-preserving)
///
/// # Security
///
/// Invalid NPIs return full redaction token to avoid information leakage.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::{NpiRedactionStrategy, redact_npi_with_strategy};
///
/// let npi = "NPI: 1234567890";
///
/// // Partial - show first 4
/// assert_eq!(redact_npi_with_strategy(npi, NpiRedactionStrategy::ShowFirst4), "1234-***-***");
///
/// // Full - type token
/// assert_eq!(redact_npi_with_strategy(npi, NpiRedactionStrategy::Token), "[PROVIDER_ID]");
/// ```
#[must_use]
pub fn redact_npi_with_strategy(npi: &str, strategy: NpiRedactionStrategy) -> String {
    // No redaction - return as-is (NPI is public)
    if matches!(strategy, NpiRedactionStrategy::Skip) {
        return npi.to_string();
    }

    // Validate format to prevent information leakage
    if !detection::is_provider_id(npi) {
        return RedactionTokenCore::ProviderId.into();
    }

    match strategy {
        NpiRedactionStrategy::Skip => npi.to_string(),

        NpiRedactionStrategy::ShowFirst4 => {
            // Show first 4 digits: "1234-***-***"
            // Extract digits from NPI string (may have labels like "NPI: 1234567890")
            let digits: String = npi.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 4 {
                format!("{}-***-***", &digits[0..4])
            } else {
                RedactionTokenCore::ProviderId.into()
            }
        }

        NpiRedactionStrategy::Token => RedactionTokenCore::ProviderId.into(),
        NpiRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        NpiRedactionStrategy::Asterisks => "*".repeat(npi.len()),
        NpiRedactionStrategy::Hashes => "#".repeat(npi.len()),
    }
}

/// Redact a provider identifier with explicit strategy
///
/// Alias for `redact_npi_with_strategy()` since NPI is the standard provider identifier.
///
/// # Arguments
///
/// * `id` - Provider identifier to redact
/// * `strategy` - NPI-specific redaction strategy
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::{NpiRedactionStrategy, redact_provider_id_with_strategy};
///
/// assert_eq!(redact_provider_id_with_strategy("NPI: 1234567890", NpiRedactionStrategy::Token), "[PROVIDER_ID]");
/// ```
#[must_use]
pub fn redact_provider_id_with_strategy(id: &str, strategy: NpiRedactionStrategy) -> String {
    redact_npi_with_strategy(id, strategy)
}

/// Redact a medical code (ICD-10, CPT) with explicit strategy
///
/// Provides type-safe medical code redaction to prevent diagnosis disclosure.
///
/// # Arguments
///
/// * `code` - Medical code to redact (ICD-10, CPT)
/// * `strategy` - Medical code-specific redaction strategy (ShowCategory, Token, etc.)
///
/// # Returns
///
/// Redacted code string according to strategy:
/// - **None**: Returns code as-is (codes may not be PHI in some contexts)
/// - **ShowCategory**: `"[ICD10-E11.*]"` (diabetes category, specific code hidden)
/// - **Token**: `"[MEDICAL_CODE]"`
/// - **Anonymous**: `"[REDACTED]"`
/// - **Asterisks**: `"*****"` (length-preserving)
/// - **Hashes**: `"#####"` (length-preserving)
///
/// # Security
///
/// Invalid codes return full redaction token to avoid information leakage.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::medical::{MedicalCodeRedactionStrategy, redact_medical_code_with_strategy};
///
/// let code = "ICD-10: E11.9";
///
/// // Partial - show category
/// assert_eq!(redact_medical_code_with_strategy(code, MedicalCodeRedactionStrategy::ShowCategory), "[ICD10-E11.*]");
///
/// // Full - type token
/// assert_eq!(redact_medical_code_with_strategy(code, MedicalCodeRedactionStrategy::Token), "[MEDICAL_CODE]");
/// ```
#[must_use]
pub fn redact_medical_code_with_strategy(
    code: &str,
    strategy: MedicalCodeRedactionStrategy,
) -> String {
    // No redaction - return as-is
    if matches!(strategy, MedicalCodeRedactionStrategy::Skip) {
        return code.to_string();
    }

    // Validate format to prevent information leakage
    if !detection::is_medical_code(code) {
        return RedactionTokenCore::MedicalCode.into();
    }

    match strategy {
        MedicalCodeRedactionStrategy::Skip => code.to_string(),

        MedicalCodeRedactionStrategy::ShowCategory => {
            // Show code category: "E11.9" -> "[ICD10-E11.*]"
            let digits: String = code
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '.')
                .collect();

            // ICD-10: Letter + 2 digits + optional decimal/digits
            if digits.len() >= 3
                && let Some(first_char) = digits.chars().next()
                && first_char.is_alphabetic()
            {
                let category = &digits[0..3]; // e.g., "E11"
                return format!("[ICD10-{}.*]", category);
            }

            // CPT or other: generic category
            "[MEDICAL_CODE-****]".to_string()
        }

        MedicalCodeRedactionStrategy::Token => RedactionTokenCore::MedicalCode.into(),
        MedicalCodeRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        MedicalCodeRedactionStrategy::Asterisks => "*".repeat(code.len()),
        MedicalCodeRedactionStrategy::Hashes => "#".repeat(code.len()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_redact_mrn_with_strategy() {
        // Valid MRN patterns with Token strategy
        assert_eq!(
            redact_mrn_with_strategy("MRN: 12345678", MrnRedactionStrategy::Token),
            "[MEDICAL_RECORD]"
        );
        assert_eq!(
            redact_mrn_with_strategy("Patient ID: 987654321", MrnRedactionStrategy::Token),
            "[MEDICAL_RECORD]"
        );
        assert_eq!(
            redact_mrn_with_strategy("Medical Record: 123456", MrnRedactionStrategy::Token),
            "[MEDICAL_RECORD]"
        );

        // Invalid input still gets redacted for safety
        assert_eq!(
            redact_mrn_with_strategy("invalid", MrnRedactionStrategy::Token),
            "[MEDICAL_RECORD]"
        );
        assert_eq!(
            redact_mrn_with_strategy("", MrnRedactionStrategy::Token),
            "[MEDICAL_RECORD]"
        );
    }

    #[test]
    fn test_redact_insurance_number_with_strategy() {
        // Valid insurance patterns with Token strategy
        assert_eq!(
            redact_insurance_number_with_strategy(
                "Policy Number: ABC123456789",
                InsuranceRedactionStrategy::Token
            ),
            "[INSURANCE_INFO]"
        );
        assert_eq!(
            redact_insurance_number_with_strategy(
                "Member ID: XYZ987654",
                InsuranceRedactionStrategy::Token
            ),
            "[INSURANCE_INFO]"
        );

        // Invalid input still gets redacted
        assert_eq!(
            redact_insurance_number_with_strategy("invalid", InsuranceRedactionStrategy::Token),
            "[INSURANCE_INFO]"
        );
        assert_eq!(
            redact_insurance_number_with_strategy("", InsuranceRedactionStrategy::Token),
            "[INSURANCE_INFO]"
        );
    }

    #[test]
    fn test_redact_prescription_number_with_strategy() {
        // Valid prescription patterns with Token strategy
        assert_eq!(
            redact_prescription_number_with_strategy(
                "RX# 123456789",
                PrescriptionRedactionStrategy::Token
            ),
            "[PRESCRIPTION]"
        );
        assert_eq!(
            redact_prescription_number_with_strategy(
                "Prescription Number: 987654",
                PrescriptionRedactionStrategy::Token
            ),
            "[PRESCRIPTION]"
        );

        // Invalid input still gets redacted
        assert_eq!(
            redact_prescription_number_with_strategy(
                "invalid",
                PrescriptionRedactionStrategy::Token
            ),
            "[PRESCRIPTION]"
        );
        assert_eq!(
            redact_prescription_number_with_strategy("", PrescriptionRedactionStrategy::Token),
            "[PRESCRIPTION]"
        );
    }

    #[test]
    fn test_redact_npi_with_strategy() {
        // Valid NPI patterns with Token strategy
        assert_eq!(
            redact_npi_with_strategy("NPI: 1234567890", NpiRedactionStrategy::Token),
            "[PROVIDER_ID]"
        );
        assert_eq!(
            redact_npi_with_strategy("1234567893", NpiRedactionStrategy::Token),
            "[PROVIDER_ID]"
        );

        // Invalid input still gets redacted
        assert_eq!(
            redact_npi_with_strategy("invalid", NpiRedactionStrategy::Token),
            "[PROVIDER_ID]"
        );
        assert_eq!(
            redact_npi_with_strategy("", NpiRedactionStrategy::Token),
            "[PROVIDER_ID]"
        );
        assert_eq!(
            redact_npi_with_strategy("NPI: 3123456789", NpiRedactionStrategy::Token),
            "[PROVIDER_ID]"
        ); // Invalid - must start with 1 or 2
    }

    #[test]
    fn test_redact_provider_id_with_strategy() {
        // Should be alias for redact_npi_with_strategy with Token strategy
        assert_eq!(
            redact_provider_id_with_strategy("NPI: 1234567890", NpiRedactionStrategy::Token),
            "[PROVIDER_ID]"
        );
        assert_eq!(
            redact_provider_id_with_strategy("1234567893", NpiRedactionStrategy::Token),
            "[PROVIDER_ID]"
        );

        // Invalid input
        assert_eq!(
            redact_provider_id_with_strategy("invalid", NpiRedactionStrategy::Token),
            "[PROVIDER_ID]"
        );
    }

    #[test]
    fn test_redact_medical_code_with_strategy() {
        // Valid medical code patterns with Token strategy
        assert_eq!(
            redact_medical_code_with_strategy("A01.1", MedicalCodeRedactionStrategy::Token),
            "[MEDICAL_CODE]"
        );
        assert_eq!(
            redact_medical_code_with_strategy("CPT: 99213", MedicalCodeRedactionStrategy::Token),
            "[MEDICAL_CODE]"
        );
        assert_eq!(
            redact_medical_code_with_strategy(
                "ICD-10: Z00.00",
                MedicalCodeRedactionStrategy::Token
            ),
            "[MEDICAL_CODE]"
        );

        // Invalid input still gets redacted
        assert_eq!(
            redact_medical_code_with_strategy("invalid", MedicalCodeRedactionStrategy::Token),
            "[MEDICAL_CODE]"
        );
        assert_eq!(
            redact_medical_code_with_strategy("", MedicalCodeRedactionStrategy::Token),
            "[MEDICAL_CODE]"
        );
    }
}

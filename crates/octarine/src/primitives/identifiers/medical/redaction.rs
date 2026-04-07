//! Redaction strategy types for medical identifiers
//!
//! This module provides type-safe redaction strategies with two tiers:
//! 1. **Domain-specific enums** - Strict, type-safe strategies for single identifiers
//! 2. **Generic policy enum** - Simple, consistent policy for text scanning
//!
//! # Domain-Specific Strategies
//!
//! Each identifier type has its own strategy enum with only valid options:
//! - `MrnRedactionStrategy` - ShowPrefix, ShowFacility, Token, etc.
//! - `InsuranceRedactionStrategy` - ShowProvider, ShowLast4, Token, etc.
//! - `PrescriptionRedactionStrategy` - ShowPharmacy, Token, etc.
//! - `NpiRedactionStrategy` - ShowFirst4, Token, etc.
//! - `MedicalCodeRedactionStrategy` - ShowCategory, Token, etc.
//!
//! # Text Redaction Policy
//!
//! For scanning text with multiple identifier types, use `TextRedactionPolicy`:
//! - `None` - Skip redaction
//! - `Partial` - Show some information (sensible defaults per type)
//! - `Complete` - Full token redaction (<MEDICAL_RECORD>, <INSURANCE_INFO>, etc.)
//! - `Anonymous` - Generic [REDACTED] for everything
//!
//! Each `*_in_text()` function internally maps the policy to appropriate domain strategies.

/// Medical Record Number (MRN) redaction strategies
///
/// Protected Health Information (PHI) under HIPAA Privacy Rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MrnRedactionStrategy {
    /// Skip redaction - return as-is (dev/qa only)
    Skip,
    /// Show prefix only: MRN-12****
    ShowPrefix,
    /// Show facility code: [MRN-HospitalA-****]
    ShowFacility,
    /// Replace with <MEDICAL_RECORD> token
    Token,
    /// Replace with generic [REDACTED]
    Anonymous,
    /// Replace with asterisks matching length
    Asterisks,
    /// Replace with hashes matching length
    Hashes,
}

/// Health insurance number redaction strategies
///
/// Protected under HIPAA and various state privacy laws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsuranceRedactionStrategy {
    /// Skip redaction - return as-is (dev/qa only)
    Skip,
    /// Show insurance provider: [INSURANCE-BCBS-****]
    ShowProvider,
    /// Show last 4 digits: ******1234 (similar to PCI-DSS)
    ShowLast4,
    /// Replace with <INSURANCE_INFO> token
    Token,
    /// Replace with generic [REDACTED]
    Anonymous,
    /// Replace with asterisks matching length
    Asterisks,
    /// Replace with hashes matching length
    Hashes,
}

/// Prescription number redaction strategies
///
/// Protected Health Information under HIPAA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrescriptionRedactionStrategy {
    /// Skip redaction - return as-is (dev/qa only)
    Skip,
    /// Show pharmacy identifier: [RX-CVS-****]
    ShowPharmacy,
    /// Replace with <PRESCRIPTION> token
    Token,
    /// Replace with generic [REDACTED]
    Anonymous,
    /// Replace with asterisks matching length
    Asterisks,
    /// Replace with hashes matching length
    Hashes,
}

/// National Provider Identifier (NPI) redaction strategies
///
/// NPI is public information but may be redacted for privacy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpiRedactionStrategy {
    /// Skip redaction - return as-is (NPI is public info)
    Skip,
    /// Show first 4 digits: 1234-***-***
    ShowFirst4,
    /// Replace with <PROVIDER_ID> token
    Token,
    /// Replace with generic [REDACTED]
    Anonymous,
    /// Replace with asterisks matching length
    Asterisks,
    /// Replace with hashes matching length
    Hashes,
}

/// Medical code redaction strategies
///
/// ICD-10, CPT codes may be redacted to prevent diagnosis disclosure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MedicalCodeRedactionStrategy {
    /// Skip redaction - return as-is (codes may not be PHI in some contexts)
    Skip,
    /// Show code category: [ICD10-E11.*] (diabetes category, specific code hidden)
    ShowCategory,
    /// Replace with <MEDICAL_CODE> token
    Token,
    /// Replace with generic [REDACTED]
    Anonymous,
    /// Replace with asterisks matching length
    Asterisks,
    /// Replace with hashes matching length
    Hashes,
}

/// Generic redaction policy for text scanning across multiple identifier types
///
/// This simple enum provides a consistent policy when scanning text that may contain
/// multiple types of medical identifiers. Each `*_in_text()` function maps the policy
/// to appropriate domain-specific strategies.
///
/// # Policy Mappings
///
/// - `Partial` maps to sensible defaults per identifier:
///   - MRN: `ShowPrefix` (MRN-12****)
///   - Insurance: `ShowLast4` (******1234)
///   - Prescription: `Token` (`<PRESCRIPTION>`)
///   - NPI: `ShowFirst4` (1234-\*\*\*-\*\*\*)
///   - Medical Code: `ShowCategory` (`[ICD10-E11.*]`)
///
/// - `Complete` maps to token variants:
///   - `<MEDICAL_RECORD>`, `<INSURANCE_INFO>`, `<PRESCRIPTION>`, `<PROVIDER_ID>`, `<MEDICAL_CODE>`
///
/// - `Anonymous` maps to generic `[REDACTED]` for all types
///
/// - `None` passes through unchanged
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextRedactionPolicy {
    /// Skip redaction - pass through unchanged
    Skip,
    /// Partial redaction with sensible defaults (show some information)
    Partial,
    /// Complete redaction with type-specific tokens (<MEDICAL_RECORD>, etc.)
    #[default]
    Complete,
    /// Anonymous redaction with generic [REDACTED] for all types
    Anonymous,
}

impl TextRedactionPolicy {
    /// Map text policy to MRN strategy
    #[must_use]
    pub const fn to_mrn_strategy(self) -> MrnRedactionStrategy {
        match self {
            Self::Skip => MrnRedactionStrategy::Skip,
            Self::Partial => MrnRedactionStrategy::ShowPrefix,
            Self::Complete => MrnRedactionStrategy::Token,
            Self::Anonymous => MrnRedactionStrategy::Anonymous,
        }
    }

    /// Map text policy to insurance strategy
    #[must_use]
    pub const fn to_insurance_strategy(self) -> InsuranceRedactionStrategy {
        match self {
            Self::Skip => InsuranceRedactionStrategy::Skip,
            Self::Partial => InsuranceRedactionStrategy::ShowLast4,
            Self::Complete => InsuranceRedactionStrategy::Token,
            Self::Anonymous => InsuranceRedactionStrategy::Anonymous,
        }
    }

    /// Map text policy to prescription strategy
    #[must_use]
    pub const fn to_prescription_strategy(self) -> PrescriptionRedactionStrategy {
        match self {
            Self::Skip => PrescriptionRedactionStrategy::Skip,
            Self::Partial => PrescriptionRedactionStrategy::Token,
            Self::Complete => PrescriptionRedactionStrategy::Token,
            Self::Anonymous => PrescriptionRedactionStrategy::Anonymous,
        }
    }

    /// Map text policy to NPI strategy
    #[must_use]
    pub const fn to_npi_strategy(self) -> NpiRedactionStrategy {
        match self {
            Self::Skip => NpiRedactionStrategy::Skip,
            Self::Partial => NpiRedactionStrategy::ShowFirst4,
            Self::Complete => NpiRedactionStrategy::Token,
            Self::Anonymous => NpiRedactionStrategy::Anonymous,
        }
    }

    /// Map text policy to medical code strategy
    #[must_use]
    pub const fn to_medical_code_strategy(self) -> MedicalCodeRedactionStrategy {
        match self {
            Self::Skip => MedicalCodeRedactionStrategy::Skip,
            Self::Partial => MedicalCodeRedactionStrategy::ShowCategory,
            Self::Complete => MedicalCodeRedactionStrategy::Token,
            Self::Anonymous => MedicalCodeRedactionStrategy::Anonymous,
        }
    }
}

//! Compliance context enrichment
//!
//! Adds compliance-specific fields and handles PII/PHI detection.

/// Compliance context for audit events
#[derive(Debug, Clone)]
pub(super) struct ComplianceContext {
    /// SOC2 compliance fields
    pub soc2_control: Option<String>,
    pub soc2_evidence: bool,

    /// HIPAA compliance fields
    pub hipaa_safeguard: Option<String>, // administrative, physical, technical
    pub contains_phi: bool,

    /// GDPR compliance fields
    pub gdpr_lawful_basis: Option<String>,
    pub contains_pii: bool,

    /// General compliance
    pub data_classification: DataClassification,
    pub retention_days: u32,
}

/// Data classification levels
#[derive(Debug, Clone, Copy)]
pub(super) enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl Default for ComplianceContext {
    fn default() -> Self {
        Self {
            soc2_control: None,
            soc2_evidence: false,
            hipaa_safeguard: None,
            contains_phi: false,
            gdpr_lawful_basis: None,
            contains_pii: false,
            data_classification: DataClassification::Internal,
            retention_days: 90, // Default retention
        }
    }
}

/// Check if a string contains potential PII
///
/// Internal function for use within the observe module.
pub(super) fn is_pii_present(text: &str) -> bool {
    use crate::primitives::identifiers::PersonalIdentifierBuilder;

    // Use the primitives module's detection capabilities via builder (no security dependency)
    let builder = PersonalIdentifierBuilder::new();
    builder.is_pii_present(text)
}

/// Check if a string contains potential PHI
///
/// Internal function for use within the observe module.
pub(super) fn is_phi_present(text: &str) -> bool {
    // Healthcare-specific patterns
    let phi_keywords = [
        "diagnosis",
        "prescription",
        "medical",
        "patient",
        "treatment",
    ];

    let lower = text.to_lowercase();
    phi_keywords.iter().any(|k| lower.contains(k))
}

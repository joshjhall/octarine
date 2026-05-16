//! `PiiScanResult` — output type for PII scanning operations.
//!
//! Carries the redacted text, detected PII types, and the PHI compliance
//! flag.

use super::PiiType;

/// Result of PII scanning operation
#[derive(Debug, Clone)]
pub(crate) struct PiiScanResult {
    /// Types of PII found in the input
    pub pii_types: Vec<PiiType>,

    /// Redacted output
    pub redacted: String,

    /// Whether any PII was found
    pub contains_pii: bool,

    /// Compliance flags
    pub contains_phi: bool, // Protected Health Information (future: medical record numbers, etc.)
}

impl PiiScanResult {
    /// Create a result with no PII detected
    pub fn no_pii(original: String) -> Self {
        Self {
            pii_types: Vec::new(),
            redacted: original,
            contains_pii: false,
            contains_phi: false,
        }
    }

    /// Create a result with PII detected and redacted
    pub fn with_pii(pii_types: Vec<PiiType>, redacted: String) -> Self {
        // Check if any PII types are HIPAA-protected (PHI)
        let contains_phi = pii_types.iter().any(|t| t.is_hipaa_protected());
        Self {
            pii_types,
            redacted,
            contains_pii: true,
            contains_phi,
        }
    }
}

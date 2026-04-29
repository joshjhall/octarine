//! Biometric identifier shortcuts (BIPA).
//!
//! Convenience functions over [`BiometricBuilder`](super::super::BiometricBuilder).

use super::super::BiometricBuilder;
use super::super::types::IdentifierMatch;

/// Detect all biometric identifiers in text
#[must_use]
pub fn detect_biometric_ids(text: &str) -> Vec<IdentifierMatch> {
    BiometricBuilder::new().detect_all_in_text(text)
}

/// Redact all biometric identifiers in text
#[must_use]
pub fn redact_biometric(text: &str) -> String {
    BiometricBuilder::new().redact_all_in_text(text)
}

//! Credential pair correlation shortcuts.
//!
//! Convenience functions over [`CorrelationBuilder`](super::super::CorrelationBuilder)
//! for detecting paired credentials (e.g., AWS key + secret, username + password).

use super::super::CorrelationBuilder;
use super::super::types::{CorrelationMatch, CredentialPairType, IdentifierMatch};

/// Detect credential pairs in text using default configuration.
///
/// Scans for all identifier types, finds proximate pairs, and classifies
/// known credential pair patterns (e.g., AWS key + secret, username + password).
#[must_use]
pub fn detect_credential_pairs(text: &str) -> Vec<CorrelationMatch> {
    CorrelationBuilder::new().detect_pairs(text)
}

/// Check if two identifier matches form a known credential pair.
///
/// Order-independent: `(A, B)` and `(B, A)` both match.
#[must_use]
pub fn is_credential_pair(
    primary: &IdentifierMatch,
    secondary: &IdentifierMatch,
) -> Option<CredentialPairType> {
    CorrelationBuilder::new().is_credential_pair(primary, secondary)
}

//! Credential pair correlation builder (Layer 1).
//!
//! Stateless builder wrapping the correlation detection and rules API.
//! Follows the same pattern as other identifier builders (e.g., `PersonalIdentifierBuilder`).

use super::super::types::{IdentifierMatch, IdentifierType};
use super::detection;
use super::rules;
use super::types::{CorrelationConfig, CorrelationMatch, CredentialPairType};

/// Builder for credential pair correlation operations.
///
/// Detects pairs of related credentials (e.g., AWS access key + secret key)
/// that appear near each other in text. Uses proximity scanning and pair
/// recognition rules to classify matches with `High` confidence.
///
/// # Examples
///
/// ```rust,ignore
/// use crate::primitives::identifiers::correlation::CorrelationBuilder;
///
/// let builder = CorrelationBuilder::new();
/// let pairs = builder.detect_pairs("AWS_ACCESS_KEY=AKIA... AWS_SECRET=...");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct CorrelationBuilder;

impl CorrelationBuilder {
    /// Create a new correlation builder.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Detect credential pairs in text using default configuration.
    ///
    /// Scans for all identifier types, finds proximate pairs within the
    /// default window (5 lines / 500 chars), and classifies known pairs.
    #[must_use]
    pub fn detect_pairs(&self, text: &str) -> Vec<CorrelationMatch> {
        detection::detect_credential_pairs(text)
    }

    /// Detect credential pairs in text with custom configuration.
    ///
    /// Allows customizing the proximity window and which pair types to scan for.
    #[must_use]
    pub fn detect_pairs_with_config(
        &self,
        text: &str,
        config: &CorrelationConfig,
    ) -> Vec<CorrelationMatch> {
        detection::detect_credential_pairs_with_config(text, config)
    }

    /// Check if two identifier matches form a known credential pair.
    ///
    /// Order-independent: `(A, B)` and `(B, A)` both match.
    #[must_use]
    pub fn is_credential_pair(
        &self,
        primary: &IdentifierMatch,
        secondary: &IdentifierMatch,
    ) -> Option<CredentialPairType> {
        rules::is_credential_pair(primary, secondary)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]

    use super::*;
    use crate::primitives::identifiers::types::DetectionConfidence;

    #[test]
    fn test_builder_creation() {
        let _builder = CorrelationBuilder::new();
        let _default: CorrelationBuilder = Default::default();
    }

    #[test]
    fn test_detect_pairs_empty_text() {
        let builder = CorrelationBuilder::new();
        assert!(builder.detect_pairs("").is_empty());
    }

    #[test]
    fn test_detect_pairs_with_config() {
        let builder = CorrelationBuilder::new();
        let config = CorrelationConfig::default();
        assert!(builder.detect_pairs_with_config("", &config).is_empty());
    }

    #[test]
    fn test_is_credential_pair_delegates() {
        let builder = CorrelationBuilder::new();
        let a = IdentifierMatch::new(
            0,
            5,
            "admin".to_string(),
            IdentifierType::Username,
            DetectionConfidence::Medium,
        );
        let b = IdentifierMatch::new(
            10,
            20,
            "secret123!".to_string(),
            IdentifierType::Password,
            DetectionConfidence::High,
        );
        assert_eq!(
            builder.is_credential_pair(&a, &b),
            Some(CredentialPairType::UsernamePasswordPair)
        );
    }

    #[test]
    fn test_is_credential_pair_none() {
        let builder = CorrelationBuilder::new();
        let a = IdentifierMatch::new(
            0,
            11,
            "192.168.1.1".to_string(),
            IdentifierType::IpAddress,
            DetectionConfidence::High,
        );
        let b = IdentifierMatch::new(
            20,
            32,
            "+15551234567".to_string(),
            IdentifierType::PhoneNumber,
            DetectionConfidence::Medium,
        );
        assert_eq!(builder.is_credential_pair(&a, &b), None);
    }
}

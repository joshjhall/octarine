//! Crypto identifier types
//!
//! Types for classifying cryptographic artifacts (keys, certificates, algorithms).
//! This is the CLASSIFICATION concern - answering "What type of crypto artifact is this?"
//!
//! `KeyType`, `KeyFormat`, and `SignatureAlgorithm` are shared with the FORMAT
//! (`data::crypto`) and THREATS (`security::crypto`) concerns, so they are defined
//! centrally in `primitives::types` and re-exported here. See
//! `primitives/types/mod.rs` for the re-export pattern.

use serde::{Deserialize, Serialize};
use std::fmt;

pub use crate::primitives::types::{KeyFormat, KeyType, SignatureAlgorithm};

/// Type of X.509 certificate
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CertificateType {
    /// CA certificate (can sign other certificates)
    CertificateAuthority,
    /// End-entity certificate (server, client, etc.)
    EndEntity,
    /// Intermediate CA certificate
    Intermediate,
    /// Self-signed certificate
    SelfSigned,
    /// Unknown certificate type
    Unknown,
}

impl fmt::Display for CertificateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CertificateAuthority => write!(f, "CA"),
            Self::EndEntity => write!(f, "End-Entity"),
            Self::Intermediate => write!(f, "Intermediate"),
            Self::SelfSigned => write!(f, "Self-Signed"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Result of crypto artifact detection
#[derive(Debug, Clone, PartialEq)]
pub struct CryptoDetectionResult {
    /// Detected key type (if any)
    pub key_type: Option<KeyType>,
    /// Detected format
    pub format: KeyFormat,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    /// Whether this appears to be a private key
    pub is_private: bool,
    /// Whether this appears to be a certificate
    pub is_certificate: bool,
    /// PEM label if detected (e.g., "RSA PUBLIC KEY", "CERTIFICATE")
    pub pem_label: Option<String>,
}

impl Default for CryptoDetectionResult {
    fn default() -> Self {
        Self {
            key_type: None,
            format: KeyFormat::Unknown,
            confidence: 0.0,
            is_private: false,
            is_certificate: false,
            pem_label: None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_certificate_type_display() {
        assert_eq!(CertificateType::CertificateAuthority.to_string(), "CA");
        assert_eq!(CertificateType::EndEntity.to_string(), "End-Entity");
        assert_eq!(CertificateType::Intermediate.to_string(), "Intermediate");
        assert_eq!(CertificateType::SelfSigned.to_string(), "Self-Signed");
        assert_eq!(CertificateType::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_crypto_detection_result_default() {
        let result = CryptoDetectionResult::default();
        assert_eq!(result.key_type, None);
        assert_eq!(result.format, KeyFormat::Unknown);
        assert!(!result.is_private);
        assert!(!result.is_certificate);
        assert_eq!(result.pem_label, None);
    }
}

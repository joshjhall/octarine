//! Parsed crypto data types
//!
//! Types representing parsed cryptographic artifacts.
//! This is the FORMAT concern - structured representations of crypto data.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::primitives::identifiers::crypto::{KeyFormat, KeyType, SignatureAlgorithm};

/// Parsed PEM block
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPem {
    /// The PEM label (e.g., "RSA PUBLIC KEY", "CERTIFICATE")
    pub label: String,
    /// The decoded binary data (base64-decoded contents)
    pub data: Vec<u8>,
    /// Any headers present in the PEM block
    pub headers: Vec<(String, String)>,
}

impl ParsedPem {
    /// Create a new parsed PEM block
    #[must_use]
    pub fn new(label: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            label: label.into(),
            data,
            headers: Vec::new(),
        }
    }

    /// Check if this is an encrypted private key
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.label.contains("ENCRYPTED")
            || self
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("Proc-Type"))
    }
}

/// Parsed public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPublicKey {
    /// The type of key
    pub key_type: KeyType,
    /// The format the key was parsed from
    pub source_format: KeyFormat,
    /// Raw key bytes (algorithm-specific encoding)
    pub raw_bytes: Vec<u8>,
    /// Key size in bits (if determinable)
    pub bit_size: Option<usize>,
    /// Algorithm OID (for PKCS#8/SPKI keys)
    pub algorithm_oid: Option<String>,
}

impl ParsedPublicKey {
    /// Create a new parsed public key
    #[must_use]
    pub fn new(key_type: KeyType, format: KeyFormat, raw_bytes: Vec<u8>) -> Self {
        let bit_size = key_type.bit_length();
        Self {
            key_type,
            source_format: format,
            raw_bytes,
            bit_size,
            algorithm_oid: None,
        }
    }
}

/// Parsed X.509 certificate
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedCertificate {
    /// Certificate version (1, 2, or 3)
    pub version: u8,
    /// Serial number (as hex string)
    pub serial_number: String,
    /// Subject distinguished name
    pub subject: String,
    /// Issuer distinguished name
    pub issuer: String,
    /// Validity start time
    pub not_before: DateTime<Utc>,
    /// Validity end time
    pub not_after: DateTime<Utc>,
    /// Subject public key type
    pub public_key_type: KeyType,
    /// Signature algorithm used
    pub signature_algorithm: SignatureAlgorithm,
    /// Whether this is a CA certificate
    pub is_ca: bool,
    /// Key usage extensions (if present)
    pub key_usage: Vec<String>,
    /// Extended key usage (if present)
    pub extended_key_usage: Vec<String>,
    /// Subject alternative names (if present)
    pub subject_alt_names: Vec<String>,
    /// Whether subject and issuer are the same
    pub is_self_signed: bool,
}

impl ParsedCertificate {
    /// Check if the certificate is currently valid
    #[must_use]
    pub fn is_valid_now(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now <= self.not_after
    }

    /// Check if the certificate is expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }

    /// Check if the certificate is not yet valid
    #[must_use]
    pub fn is_not_yet_valid(&self) -> bool {
        Utc::now() < self.not_before
    }

    /// Get the number of days until expiration (negative if expired)
    #[must_use]
    pub fn days_until_expiry(&self) -> i64 {
        let now = Utc::now();
        #[allow(clippy::arithmetic_side_effects)] // DateTime subtraction is safe
        (self.not_after - now).num_days()
    }
}

/// Parsed SSH public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSshPublicKey {
    /// The key type (e.g., SshRsa, SshEd25519)
    pub key_type: KeyType,
    /// The key algorithm identifier from the key (e.g., "ssh-rsa", "ssh-ed25519")
    pub algorithm: String,
    /// The raw key data (base64-decoded)
    pub key_data: Vec<u8>,
    /// Optional comment (user@host)
    pub comment: Option<String>,
}

impl ParsedSshPublicKey {
    /// Create a new parsed SSH public key
    #[must_use]
    pub fn new(key_type: KeyType, algorithm: impl Into<String>, key_data: Vec<u8>) -> Self {
        Self {
            key_type,
            algorithm: algorithm.into(),
            key_data,
            comment: None,
        }
    }

    /// Set the comment
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }
}

/// Result of parsing cryptographic data
#[derive(Debug, Clone)]
pub enum ParsedCryptoData {
    /// Parsed PEM block(s)
    Pem(Vec<ParsedPem>),
    /// Parsed public key
    PublicKey(ParsedPublicKey),
    /// Parsed X.509 certificate
    Certificate(ParsedCertificate),
    /// Parsed SSH public key
    SshPublicKey(ParsedSshPublicKey),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_parsed_pem() {
        let pem = ParsedPem::new("RSA PUBLIC KEY", vec![1, 2, 3]);
        assert_eq!(pem.label, "RSA PUBLIC KEY");
        assert!(!pem.is_encrypted());
    }

    #[test]
    fn test_parsed_pem_encrypted() {
        let mut pem = ParsedPem::new("ENCRYPTED PRIVATE KEY", vec![1, 2, 3]);
        assert!(pem.is_encrypted());

        pem.label = "PRIVATE KEY".to_string();
        pem.headers
            .push(("Proc-Type".to_string(), "4,ENCRYPTED".to_string()));
        assert!(pem.is_encrypted());
    }

    #[test]
    fn test_parsed_public_key() {
        let key = ParsedPublicKey::new(KeyType::Rsa2048, KeyFormat::Pem, vec![1, 2, 3]);
        assert_eq!(key.key_type, KeyType::Rsa2048);
        assert_eq!(key.bit_size, Some(2048));
    }

    #[test]
    fn test_parsed_ssh_key() {
        let key = ParsedSshPublicKey::new(KeyType::SshEd25519, "ssh-ed25519", vec![1, 2, 3])
            .with_comment("user@host");
        assert_eq!(key.key_type, KeyType::SshEd25519);
        assert_eq!(key.comment, Some("user@host".to_string()));
    }
}

//! Crypto identifier types
//!
//! Types for classifying cryptographic artifacts (keys, certificates, algorithms).
//! This is the CLASSIFICATION concern - answering "What type of crypto artifact is this?"

use serde::{Deserialize, Serialize};
use std::fmt;

/// Type of cryptographic key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    // RSA keys
    /// RSA 2048-bit key
    Rsa2048,
    /// RSA 3072-bit key
    Rsa3072,
    /// RSA 4096-bit key
    Rsa4096,
    /// RSA key of other size
    RsaOther(usize),

    // Elliptic curve keys
    /// NIST P-256 (secp256r1) key
    P256,
    /// NIST P-384 (secp384r1) key
    P384,
    /// NIST P-521 (secp521r1) key
    P521,
    /// Ed25519 key
    Ed25519,
    /// Ed448 key
    Ed448,
    /// X25519 key (for key exchange)
    X25519,

    // Post-quantum keys
    /// ML-KEM-768 (Kyber768) key
    MlKem768,
    /// ML-KEM-1024 (Kyber1024) key
    MlKem1024,

    // SSH-specific types
    /// SSH RSA key
    SshRsa,
    /// SSH Ed25519 key
    SshEd25519,
    /// SSH ECDSA key
    SshEcdsa,
    /// SSH DSA key (deprecated)
    SshDsa,

    /// Unknown or unrecognized key type
    Unknown,
}

impl KeyType {
    /// Get the bit length for this key type
    #[must_use]
    pub fn bit_length(&self) -> Option<usize> {
        match self {
            Self::Rsa2048 | Self::SshRsa => Some(2048),
            Self::Rsa3072 => Some(3072),
            Self::Rsa4096 => Some(4096),
            Self::RsaOther(bits) => Some(*bits),
            Self::P256 => Some(256),
            Self::P384 => Some(384),
            Self::P521 => Some(521),
            Self::Ed25519 | Self::SshEd25519 | Self::X25519 => Some(256),
            Self::Ed448 => Some(448),
            Self::MlKem768 => Some(768),
            Self::MlKem1024 => Some(1024),
            Self::SshEcdsa => Some(256), // Typically P-256
            Self::SshDsa => Some(1024),
            Self::Unknown => None,
        }
    }

    /// Check if this is an RSA key type
    #[must_use]
    pub fn is_rsa(&self) -> bool {
        matches!(
            self,
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 | Self::RsaOther(_) | Self::SshRsa
        )
    }

    /// Check if this is an elliptic curve key type
    #[must_use]
    pub fn is_ec(&self) -> bool {
        matches!(
            self,
            Self::P256
                | Self::P384
                | Self::P521
                | Self::Ed25519
                | Self::Ed448
                | Self::X25519
                | Self::SshEd25519
                | Self::SshEcdsa
        )
    }

    /// Check if this is a post-quantum key type
    #[must_use]
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, Self::MlKem768 | Self::MlKem1024)
    }

    /// Check if this is an SSH key type
    #[must_use]
    pub fn is_ssh(&self) -> bool {
        matches!(
            self,
            Self::SshRsa | Self::SshEd25519 | Self::SshEcdsa | Self::SshDsa
        )
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa2048 => write!(f, "RSA-2048"),
            Self::Rsa3072 => write!(f, "RSA-3072"),
            Self::Rsa4096 => write!(f, "RSA-4096"),
            Self::RsaOther(bits) => write!(f, "RSA-{bits}"),
            Self::P256 => write!(f, "P-256"),
            Self::P384 => write!(f, "P-384"),
            Self::P521 => write!(f, "P-521"),
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::Ed448 => write!(f, "Ed448"),
            Self::X25519 => write!(f, "X25519"),
            Self::MlKem768 => write!(f, "ML-KEM-768"),
            Self::MlKem1024 => write!(f, "ML-KEM-1024"),
            Self::SshRsa => write!(f, "SSH-RSA"),
            Self::SshEd25519 => write!(f, "SSH-Ed25519"),
            Self::SshEcdsa => write!(f, "SSH-ECDSA"),
            Self::SshDsa => write!(f, "SSH-DSA"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Format of a cryptographic key or certificate
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyFormat {
    /// PEM-encoded (Base64 with header/footer)
    Pem,
    /// DER-encoded (binary ASN.1)
    Der,
    /// SSH public key format (one-line Base64)
    Ssh,
    /// OpenSSH private key format
    OpenSshPrivate,
    /// PKCS#8 format (private key)
    Pkcs8,
    /// PKCS#12/PFX format (certificate + key bundle)
    Pkcs12,
    /// Raw bytes (no encoding)
    Raw,
    /// Unknown format
    Unknown,
}

impl fmt::Display for KeyFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pem => write!(f, "PEM"),
            Self::Der => write!(f, "DER"),
            Self::Ssh => write!(f, "SSH"),
            Self::OpenSshPrivate => write!(f, "OpenSSH-Private"),
            Self::Pkcs8 => write!(f, "PKCS#8"),
            Self::Pkcs12 => write!(f, "PKCS#12"),
            Self::Raw => write!(f, "Raw"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Signature algorithm identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    // RSA signatures
    /// RSA PKCS#1 v1.5 with SHA-256
    RsaPkcs1Sha256,
    /// RSA PKCS#1 v1.5 with SHA-384
    RsaPkcs1Sha384,
    /// RSA PKCS#1 v1.5 with SHA-512
    RsaPkcs1Sha512,
    /// RSA PKCS#1 v1.5 with SHA-1 (deprecated)
    RsaPkcs1Sha1,
    /// RSA PKCS#1 v1.5 with MD5 (insecure)
    RsaPkcs1Md5,
    /// RSA-PSS with SHA-256
    RsaPssSha256,
    /// RSA-PSS with SHA-384
    RsaPssSha384,
    /// RSA-PSS with SHA-512
    RsaPssSha512,

    // ECDSA signatures
    /// ECDSA with P-256 and SHA-256
    EcdsaP256Sha256,
    /// ECDSA with P-384 and SHA-384
    EcdsaP384Sha384,
    /// ECDSA with P-521 and SHA-512
    EcdsaP521Sha512,

    // EdDSA signatures
    /// Ed25519 signature
    Ed25519,
    /// Ed448 signature
    Ed448,

    /// Unknown or unrecognized algorithm
    Unknown,
}

impl SignatureAlgorithm {
    /// Check if this algorithm is deprecated
    #[must_use]
    pub fn is_deprecated(&self) -> bool {
        matches!(self, Self::RsaPkcs1Sha1 | Self::RsaPkcs1Md5)
    }

    /// Check if this algorithm uses RSA
    #[must_use]
    pub fn is_rsa(&self) -> bool {
        matches!(
            self,
            Self::RsaPkcs1Sha256
                | Self::RsaPkcs1Sha384
                | Self::RsaPkcs1Sha512
                | Self::RsaPkcs1Sha1
                | Self::RsaPkcs1Md5
                | Self::RsaPssSha256
                | Self::RsaPssSha384
                | Self::RsaPssSha512
        )
    }

    /// Check if this algorithm uses ECDSA
    #[must_use]
    pub fn is_ecdsa(&self) -> bool {
        matches!(
            self,
            Self::EcdsaP256Sha256 | Self::EcdsaP384Sha384 | Self::EcdsaP521Sha512
        )
    }

    /// Check if this algorithm uses EdDSA
    #[must_use]
    pub fn is_eddsa(&self) -> bool {
        matches!(self, Self::Ed25519 | Self::Ed448)
    }

    /// Get the hash algorithm used (if applicable)
    #[must_use]
    pub fn hash_algorithm(&self) -> Option<&'static str> {
        match self {
            Self::RsaPkcs1Sha256 | Self::RsaPssSha256 | Self::EcdsaP256Sha256 => Some("SHA-256"),
            Self::RsaPkcs1Sha384 | Self::RsaPssSha384 | Self::EcdsaP384Sha384 => Some("SHA-384"),
            Self::RsaPkcs1Sha512 | Self::RsaPssSha512 | Self::EcdsaP521Sha512 => Some("SHA-512"),
            Self::RsaPkcs1Sha1 => Some("SHA-1"),
            Self::RsaPkcs1Md5 => Some("MD5"),
            Self::Ed25519 | Self::Ed448 => None, // EdDSA uses internal hash
            Self::Unknown => None,
        }
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RsaPkcs1Sha256 => write!(f, "RSA-PKCS1-SHA256"),
            Self::RsaPkcs1Sha384 => write!(f, "RSA-PKCS1-SHA384"),
            Self::RsaPkcs1Sha512 => write!(f, "RSA-PKCS1-SHA512"),
            Self::RsaPkcs1Sha1 => write!(f, "RSA-PKCS1-SHA1"),
            Self::RsaPkcs1Md5 => write!(f, "RSA-PKCS1-MD5"),
            Self::RsaPssSha256 => write!(f, "RSA-PSS-SHA256"),
            Self::RsaPssSha384 => write!(f, "RSA-PSS-SHA384"),
            Self::RsaPssSha512 => write!(f, "RSA-PSS-SHA512"),
            Self::EcdsaP256Sha256 => write!(f, "ECDSA-P256-SHA256"),
            Self::EcdsaP384Sha384 => write!(f, "ECDSA-P384-SHA384"),
            Self::EcdsaP521Sha512 => write!(f, "ECDSA-P521-SHA512"),
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::Ed448 => write!(f, "Ed448"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

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
    fn test_key_type_bit_length() {
        assert_eq!(KeyType::Rsa2048.bit_length(), Some(2048));
        assert_eq!(KeyType::P256.bit_length(), Some(256));
        assert_eq!(KeyType::Ed25519.bit_length(), Some(256));
        assert_eq!(KeyType::Unknown.bit_length(), None);
    }

    #[test]
    fn test_key_type_classification() {
        assert!(KeyType::Rsa2048.is_rsa());
        assert!(!KeyType::Rsa2048.is_ec());
        assert!(KeyType::P256.is_ec());
        assert!(!KeyType::P256.is_rsa());
        assert!(KeyType::MlKem768.is_post_quantum());
        assert!(KeyType::SshRsa.is_ssh());
    }

    #[test]
    fn test_signature_algorithm_deprecated() {
        assert!(SignatureAlgorithm::RsaPkcs1Sha1.is_deprecated());
        assert!(SignatureAlgorithm::RsaPkcs1Md5.is_deprecated());
        assert!(!SignatureAlgorithm::RsaPkcs1Sha256.is_deprecated());
    }

    #[test]
    fn test_display() {
        assert_eq!(KeyType::Rsa2048.to_string(), "RSA-2048");
        assert_eq!(KeyFormat::Pem.to_string(), "PEM");
        assert_eq!(SignatureAlgorithm::Ed25519.to_string(), "Ed25519");
    }
}

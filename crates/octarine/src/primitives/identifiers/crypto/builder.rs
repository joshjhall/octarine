//! Crypto identifier builder
//!
//! Builder for detecting and classifying cryptographic artifacts.
//! This is Layer 1 (primitives) - no observe dependencies.

use super::detection;
use super::types::{
    CertificateType, CryptoDetectionResult, KeyFormat, KeyType, SignatureAlgorithm,
};

/// Builder for crypto artifact identification operations
///
/// Provides a unified interface for detecting and classifying cryptographic
/// artifacts (keys, certificates, signatures).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::crypto::CryptoIdentifierBuilder;
///
/// let builder = CryptoIdentifierBuilder::new();
///
/// // Quick detection
/// if builder.is_pem_format(data) {
///     println!("PEM-encoded data detected");
/// }
///
/// // Comprehensive detection
/// let result = builder.detect(data);
/// if let Some(key_type) = result.key_type {
///     println!("Detected key type: {}", key_type);
/// }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptoIdentifierBuilder;

impl CryptoIdentifierBuilder {
    /// Create a new crypto identifier builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // ========================================================================
    // Format Detection (is_* functions returning bool)
    // ========================================================================

    /// Check if data appears to be PEM-encoded
    #[must_use]
    pub fn is_pem_format(&self, data: &str) -> bool {
        detection::is_pem_format(data)
    }

    /// Check if data appears to be DER-encoded
    #[must_use]
    pub fn is_der_format(&self, data: &[u8]) -> bool {
        detection::is_der_format(data)
    }

    /// Check if data appears to be an SSH public key
    #[must_use]
    pub fn is_ssh_key_format(&self, data: &str) -> bool {
        detection::is_ssh_key_format(data)
    }

    /// Check if data appears to be an OpenSSH private key
    #[must_use]
    pub fn is_openssh_private_key_format(&self, data: &str) -> bool {
        detection::is_openssh_private_key_format(data)
    }

    // ========================================================================
    // Key Type Detection (is_* functions returning bool)
    // ========================================================================

    /// Check if data appears to be an RSA key
    #[must_use]
    pub fn is_rsa_key(&self, data: &str) -> bool {
        detection::is_rsa_key(data)
    }

    /// Check if data appears to be an EC key
    #[must_use]
    pub fn is_ec_key(&self, data: &str) -> bool {
        detection::is_ec_key(data)
    }

    /// Check if data appears to be an X.509 certificate
    #[must_use]
    pub fn is_x509_certificate(&self, data: &str) -> bool {
        detection::is_x509_certificate(data)
    }

    /// Check if data appears to be a private key
    #[must_use]
    pub fn is_private_key(&self, data: &str) -> bool {
        detection::is_private_key(data)
    }

    /// Check if data appears to be a public key
    #[must_use]
    pub fn is_public_key(&self, data: &str) -> bool {
        detection::is_public_key(data)
    }

    // ========================================================================
    // Detection Functions (detect_* returning structured results)
    // ========================================================================

    /// Detect the format of cryptographic string data
    #[must_use]
    pub fn detect_key_format(&self, data: &str) -> KeyFormat {
        detection::detect_key_format(data)
    }

    /// Detect the format of binary cryptographic data
    #[must_use]
    pub fn detect_key_format_binary(&self, data: &[u8]) -> KeyFormat {
        detection::detect_key_format_binary(data)
    }

    /// Detect the key type from SSH public key format
    #[must_use]
    pub fn detect_ssh_key_type(&self, data: &str) -> Option<KeyType> {
        detection::detect_ssh_key_type(data)
    }

    /// Detect key type from PEM label
    #[must_use]
    pub fn detect_key_type_from_pem(&self, data: &str) -> Option<KeyType> {
        detection::detect_key_type_from_pem(data)
    }

    /// Comprehensive crypto artifact detection
    ///
    /// Analyzes input data and returns detailed information about what type
    /// of cryptographic artifact it appears to be.
    #[must_use]
    pub fn detect(&self, data: &str) -> CryptoDetectionResult {
        detection::detect_crypto_artifact(data)
    }

    /// Detect signature algorithm from OID string
    #[must_use]
    pub fn detect_signature_algorithm_from_oid(&self, oid: &str) -> SignatureAlgorithm {
        detection::detect_signature_algorithm_from_oid(oid)
    }

    // ========================================================================
    // Convenience Methods
    // ========================================================================

    /// Detect the type of key (any format)
    ///
    /// This tries to detect the key type from various formats (SSH, PEM, etc.)
    #[must_use]
    pub fn detect_key_type(&self, data: &str) -> Option<KeyType> {
        let result = self.detect(data);
        result.key_type
    }

    /// Check if the data is any type of cryptographic artifact
    #[must_use]
    pub fn is_crypto_artifact(&self, data: &str) -> bool {
        let result = self.detect(data);
        result.format != KeyFormat::Unknown || result.key_type.is_some() || result.is_certificate
    }

    /// Classify a certificate type (requires parsing for accurate results)
    ///
    /// Note: This is a basic heuristic. For accurate classification,
    /// use the data/crypto module to parse the certificate first.
    #[must_use]
    pub fn classify_certificate_type(&self, _data: &str) -> CertificateType {
        // Basic classification - real implementation needs X.509 parsing
        // This is just a placeholder that indicates certificate detection
        CertificateType::Unknown
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Fake content - tests only check format detection, not parsing
    const SAMPLE_RSA_PEM: &str = r#"-----BEGIN RSA PUBLIC KEY-----
FAKE_TEST_DATA_NOT_A_REAL_RSA_KEY
-----END RSA PUBLIC KEY-----"#;

    // Fake content - tests only check format detection, not parsing
    const SAMPLE_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
FAKE_TEST_DATA_NOT_A_REAL_CERTIFICATE
-----END CERTIFICATE-----"#;

    const SAMPLE_SSH_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG user@host";

    #[test]
    fn test_builder_creation() {
        let builder = CryptoIdentifierBuilder::new();
        let _ = builder; // Just verify it compiles
    }

    #[test]
    fn test_format_detection() {
        let builder = CryptoIdentifierBuilder::new();

        assert!(builder.is_pem_format(SAMPLE_RSA_PEM));
        assert!(builder.is_ssh_key_format(SAMPLE_SSH_KEY));
        assert!(!builder.is_pem_format(SAMPLE_SSH_KEY));
    }

    #[test]
    fn test_key_type_detection() {
        let builder = CryptoIdentifierBuilder::new();

        assert!(builder.is_rsa_key(SAMPLE_RSA_PEM));
        assert!(builder.is_ec_key(SAMPLE_SSH_KEY));
        assert!(!builder.is_rsa_key(SAMPLE_SSH_KEY));
    }

    #[test]
    fn test_certificate_detection() {
        let builder = CryptoIdentifierBuilder::new();

        assert!(builder.is_x509_certificate(SAMPLE_CERT_PEM));
        assert!(!builder.is_x509_certificate(SAMPLE_RSA_PEM));
    }

    #[test]
    fn test_comprehensive_detection() {
        let builder = CryptoIdentifierBuilder::new();

        let result = builder.detect(SAMPLE_SSH_KEY);
        assert_eq!(result.format, KeyFormat::Ssh);
        assert_eq!(result.key_type, Some(KeyType::SshEd25519));
        assert!(!result.is_certificate);

        let result = builder.detect(SAMPLE_CERT_PEM);
        assert!(result.is_certificate);
    }

    #[test]
    fn test_is_crypto_artifact() {
        let builder = CryptoIdentifierBuilder::new();

        assert!(builder.is_crypto_artifact(SAMPLE_RSA_PEM));
        assert!(builder.is_crypto_artifact(SAMPLE_SSH_KEY));
        assert!(builder.is_crypto_artifact(SAMPLE_CERT_PEM));
        assert!(!builder.is_crypto_artifact("just some random text"));
    }

    #[test]
    fn test_signature_algorithm_detection() {
        let builder = CryptoIdentifierBuilder::new();

        let algo = builder.detect_signature_algorithm_from_oid("1.2.840.113549.1.1.11");
        assert_eq!(algo, SignatureAlgorithm::RsaPkcs1Sha256);

        let algo = builder.detect_signature_algorithm_from_oid("1.3.101.112");
        assert_eq!(algo, SignatureAlgorithm::Ed25519);
    }
}

//! Crypto identifier builder with observability
//!
//! Wraps `primitives::identifiers::CryptoIdentifierBuilder` with observe instrumentation.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.

use std::time::Instant;

use crate::observe::Problem;
use crate::observe::metrics::{MetricName, increment_by, record};
use crate::primitives::identifiers::{
    CertificateType, CryptoDetectionResult, CryptoIdentifierBuilder, KeyFormat, KeyType,
    SignatureAlgorithm,
};

#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn detect_ms() -> MetricName {
        MetricName::new("data.identifiers.crypto.detect_ms").expect("valid metric name")
    }

    pub fn validate_ms() -> MetricName {
        MetricName::new("data.identifiers.crypto.validate_ms").expect("valid metric name")
    }

    pub fn detected() -> MetricName {
        MetricName::new("data.identifiers.crypto.detected").expect("valid metric name")
    }

    pub fn crypto_data_found() -> MetricName {
        MetricName::new("data.identifiers.crypto.crypto_data_found").expect("valid metric name")
    }
}

/// Crypto identifier builder with observability
///
/// Provides detection, validation, and classification for cryptographic
/// artifacts (keys, certificates, signatures) with audit trail via observe.
///
/// # Example
///
/// ```ignore
/// use octarine::identifiers::CryptoBuilder;
///
/// let builder = CryptoBuilder::new();
///
/// // Detection
/// if builder.is_private_key(data) {
///     println!("Private key detected!");
/// }
///
/// // Validation
/// builder.validate_pem_format(data)?;
///
/// // Silent mode (no events)
/// let silent = CryptoBuilder::silent();
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptoBuilder {
    inner: CryptoIdentifierBuilder,
    emit_events: bool,
}

impl CryptoBuilder {
    /// Create a new CryptoBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: CryptoIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: CryptoIdentifierBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // Format Detection
    // ========================================================================

    /// Check if data appears to be PEM-encoded
    #[must_use]
    pub fn is_pem_format(&self, data: &str) -> bool {
        self.inner.is_pem_format(data)
    }

    /// Check if data appears to be DER-encoded
    #[must_use]
    pub fn is_der_format(&self, data: &[u8]) -> bool {
        self.inner.is_der_format(data)
    }

    /// Check if data appears to be an SSH public key
    #[must_use]
    pub fn is_ssh_key_format(&self, data: &str) -> bool {
        self.inner.is_ssh_key_format(data)
    }

    /// Check if data appears to be an OpenSSH private key
    #[must_use]
    pub fn is_openssh_private_key_format(&self, data: &str) -> bool {
        self.inner.is_openssh_private_key_format(data)
    }

    // ========================================================================
    // Key Type Detection
    // ========================================================================

    /// Check if data appears to be an RSA key
    #[must_use]
    pub fn is_rsa_key(&self, data: &str) -> bool {
        self.inner.is_rsa_key(data)
    }

    /// Check if data appears to be an EC key
    #[must_use]
    pub fn is_ec_key(&self, data: &str) -> bool {
        self.inner.is_ec_key(data)
    }

    /// Check if data appears to be an X.509 certificate
    #[must_use]
    pub fn is_x509_certificate(&self, data: &str) -> bool {
        self.inner.is_x509_certificate(data)
    }

    /// Check if data appears to be a private key
    #[must_use]
    pub fn is_private_key(&self, data: &str) -> bool {
        let result = self.inner.is_private_key(data);

        if self.emit_events && result {
            increment_by(metric_names::crypto_data_found(), 1);
        }

        result
    }

    /// Check if data appears to be a public key
    #[must_use]
    pub fn is_public_key(&self, data: &str) -> bool {
        self.inner.is_public_key(data)
    }

    /// Check if the data is any type of cryptographic artifact
    #[must_use]
    pub fn is_crypto_artifact(&self, data: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_crypto_artifact(data);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::detected(), 1);
                increment_by(metric_names::crypto_data_found(), 1);
            }
        }

        result
    }

    // ========================================================================
    // Validation
    // ========================================================================

    /// Validate PEM format structure
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the PEM structure is invalid
    pub fn validate_pem_format(&self, data: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_pem_format(data);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }

        result
    }

    /// Validate DER format structure
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the DER structure is invalid
    pub fn validate_der_format(&self, data: &[u8]) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_der_format(data);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }

        result
    }

    /// Validate SSH public key format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the SSH key format is invalid
    pub fn validate_ssh_key_format(&self, data: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_ssh_key_format(data);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }

        result
    }

    /// Validate OpenSSH private key format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the format is invalid
    pub fn validate_openssh_private_key_format(&self, data: &str) -> Result<(), Problem> {
        self.inner.validate_openssh_private_key_format(data)
    }

    /// Validate RSA key format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the key is not a valid RSA key format
    pub fn validate_rsa_key(&self, data: &str) -> Result<(), Problem> {
        self.inner.validate_rsa_key(data)
    }

    /// Validate EC key format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the key is not a valid EC key format
    pub fn validate_ec_key(&self, data: &str) -> Result<(), Problem> {
        self.inner.validate_ec_key(data)
    }

    /// Validate X.509 certificate format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the certificate format is invalid
    pub fn validate_x509_certificate(&self, data: &str) -> Result<(), Problem> {
        self.inner.validate_x509_certificate(data)
    }

    /// Validate private key format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the data is not a valid private key format
    pub fn validate_private_key(&self, data: &str) -> Result<(), Problem> {
        self.inner.validate_private_key(data)
    }

    /// Validate public key format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the data is not a valid public key format
    pub fn validate_public_key(&self, data: &str) -> Result<(), Problem> {
        self.inner.validate_public_key(data)
    }

    // ========================================================================
    // Detection (structured results)
    // ========================================================================

    /// Comprehensive crypto artifact detection
    #[must_use]
    pub fn detect(&self, data: &str) -> CryptoDetectionResult {
        let start = Instant::now();
        let result = self.inner.detect(data);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.key_type.is_some() || result.is_certificate {
                increment_by(metric_names::detected(), 1);
            }
        }

        result
    }

    /// Detect the format of cryptographic string data
    #[must_use]
    pub fn detect_key_format(&self, data: &str) -> KeyFormat {
        self.inner.detect_key_format(data)
    }

    /// Detect the format of binary cryptographic data
    #[must_use]
    pub fn detect_key_format_binary(&self, data: &[u8]) -> KeyFormat {
        self.inner.detect_key_format_binary(data)
    }

    /// Detect the key type (any format)
    #[must_use]
    pub fn detect_key_type(&self, data: &str) -> Option<KeyType> {
        self.inner.detect_key_type(data)
    }

    /// Detect SSH key type from SSH public key format
    #[must_use]
    pub fn detect_ssh_key_type(&self, data: &str) -> Option<KeyType> {
        self.inner.detect_ssh_key_type(data)
    }

    /// Detect key type from PEM label
    #[must_use]
    pub fn detect_key_type_from_pem(&self, data: &str) -> Option<KeyType> {
        self.inner.detect_key_type_from_pem(data)
    }

    /// Detect signature algorithm from OID string
    #[must_use]
    pub fn detect_signature_algorithm_from_oid(&self, oid: &str) -> SignatureAlgorithm {
        self.inner.detect_signature_algorithm_from_oid(oid)
    }

    /// Classify certificate type (basic heuristic)
    #[must_use]
    pub fn classify_certificate_type(&self, data: &str) -> CertificateType {
        self.inner.classify_certificate_type(data)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    const SAMPLE_SSH_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG user@host";

    #[test]
    fn test_builder_creation() {
        let builder = CryptoBuilder::new();
        assert!(builder.emit_events);

        let silent = CryptoBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = CryptoBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_ssh_key_detection() {
        let builder = CryptoBuilder::new();
        assert!(builder.is_ssh_key_format(SAMPLE_SSH_KEY));
        assert!(builder.is_ec_key(SAMPLE_SSH_KEY));
        assert!(builder.is_public_key(SAMPLE_SSH_KEY));
        assert!(builder.is_crypto_artifact(SAMPLE_SSH_KEY));
    }

    #[test]
    fn test_comprehensive_detection() {
        let builder = CryptoBuilder::new();
        let result = builder.detect(SAMPLE_SSH_KEY);
        assert_eq!(result.format, KeyFormat::Ssh);
        assert_eq!(result.key_type, Some(KeyType::SshEd25519));
    }

    #[test]
    fn test_not_crypto() {
        let builder = CryptoBuilder::silent();
        assert!(!builder.is_crypto_artifact("just some text"));
        assert!(!builder.is_pem_format("not pem"));
    }

    #[test]
    fn test_ssh_key_validation() {
        let builder = CryptoBuilder::new();
        assert!(builder.validate_ssh_key_format(SAMPLE_SSH_KEY).is_ok());
        assert!(builder.validate_ssh_key_format("not a key").is_err());
    }

    #[test]
    fn test_der_detection() {
        let builder = CryptoBuilder::silent();
        assert!(builder.is_der_format(&[0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]));
        assert!(!builder.is_der_format(&[0x02, 0x05]));
    }

    #[test]
    fn test_der_validation() {
        let builder = CryptoBuilder::new();
        assert!(
            builder
                .validate_der_format(&[0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05])
                .is_ok()
        );
        assert!(builder.validate_der_format(&[]).is_err());
    }
}

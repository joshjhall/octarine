//! Crypto data parsing builder
//!
//! Builder for parsing cryptographic data formats.
//! This is Layer 1 (primitives) - no observe dependencies.

use crate::primitives::types::Problem;

use super::pem;
use super::ssh;
use super::types::{ParsedCertificate, ParsedPem, ParsedSshPublicKey};
use super::x509;

/// Builder for crypto data parsing operations
///
/// Provides a unified interface for parsing various cryptographic data formats.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::data::crypto::CryptoDataBuilder;
///
/// let builder = CryptoDataBuilder::new();
///
/// // Parse PEM data
/// let pem = builder.parse_pem(pem_data)?;
///
/// // Parse SSH public key
/// let ssh_key = builder.parse_ssh_public_key(ssh_data)?;
///
/// // Parse X.509 certificate
/// let cert = builder.parse_certificate_pem(cert_data)?;
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptoDataBuilder;

impl CryptoDataBuilder {
    /// Create a new crypto data builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // ========================================================================
    // PEM Parsing
    // ========================================================================

    /// Parse a single PEM block
    ///
    /// # Errors
    /// Returns an error if the data is not valid PEM
    pub fn parse_pem(&self, data: &str) -> Result<ParsedPem, Problem> {
        pem::parse_pem(data)
    }

    /// Parse multiple PEM blocks
    ///
    /// # Errors
    /// Returns an error if any block is not valid PEM
    pub fn parse_pem_many(&self, data: &str) -> Result<Vec<ParsedPem>, Problem> {
        pem::parse_pem_many(data)
    }

    /// Validate PEM format
    ///
    /// # Errors
    /// Returns an error if the data is not valid PEM
    pub fn validate_pem_format(&self, data: &str) -> Result<(), Problem> {
        pem::validate_pem_format(data)
    }

    /// Normalize PEM formatting
    ///
    /// Ensures consistent line endings and wrapping.
    ///
    /// # Errors
    /// Returns an error if the data is not valid PEM
    pub fn normalize_pem(&self, data: &str) -> Result<String, Problem> {
        pem::normalize_pem(data)
    }

    /// Encode data as PEM
    #[must_use]
    pub fn encode_pem(&self, label: &str, data: &[u8]) -> String {
        pem::encode_pem(label, data)
    }

    // ========================================================================
    // SSH Key Parsing
    // ========================================================================

    /// Parse an SSH public key
    ///
    /// # Errors
    /// Returns an error if the data is not a valid SSH public key
    pub fn parse_ssh_public_key(&self, data: &str) -> Result<ParsedSshPublicKey, Problem> {
        ssh::parse_ssh_public_key(data)
    }

    /// Validate SSH public key format
    ///
    /// # Errors
    /// Returns an error if the data is not a valid SSH public key
    pub fn validate_ssh_public_key_format(&self, data: &str) -> Result<(), Problem> {
        ssh::validate_ssh_public_key_format(data)
    }

    /// Get SSH key fingerprint
    ///
    /// Returns the SHA-256 fingerprint in standard format.
    ///
    /// # Errors
    /// Returns an error if the data is not a valid SSH public key
    pub fn ssh_key_fingerprint(&self, data: &str) -> Result<String, Problem> {
        ssh::ssh_key_fingerprint(data)
    }

    // ========================================================================
    // X.509 Certificate Parsing
    // ========================================================================

    /// Parse an X.509 certificate from PEM format
    ///
    /// # Errors
    /// Returns an error if the data is not a valid certificate
    pub fn parse_certificate_pem(&self, data: &str) -> Result<ParsedCertificate, Problem> {
        x509::parse_certificate_pem(data)
    }

    /// Parse an X.509 certificate from DER format
    ///
    /// # Errors
    /// Returns an error if the data is not a valid certificate
    pub fn parse_certificate_der(&self, data: &[u8]) -> Result<ParsedCertificate, Problem> {
        x509::parse_certificate_der(data)
    }

    /// Validate X.509 certificate format (PEM)
    ///
    /// # Errors
    /// Returns an error if the data is not a valid certificate
    pub fn validate_certificate_format_pem(&self, data: &str) -> Result<(), Problem> {
        x509::validate_certificate_format_pem(data)
    }

    /// Validate X.509 certificate format (DER)
    ///
    /// # Errors
    /// Returns an error if the data is not a valid certificate
    pub fn validate_certificate_format_der(&self, data: &[u8]) -> Result<(), Problem> {
        x509::validate_certificate_format_der(data)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = CryptoDataBuilder::new();
        let _ = builder; // Just verify it compiles
    }

    #[test]
    fn test_pem_validation_invalid() {
        let builder = CryptoDataBuilder::new();
        let result = builder.validate_pem_format("not valid pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_ssh_validation_invalid() {
        let builder = CryptoDataBuilder::new();
        let result = builder.validate_ssh_public_key_format("not a key");
        assert!(result.is_err());
    }

    #[test]
    fn test_certificate_validation_invalid() {
        let builder = CryptoDataBuilder::new();
        let result = builder.validate_certificate_format_pem("not a cert");
        assert!(result.is_err());
    }
}

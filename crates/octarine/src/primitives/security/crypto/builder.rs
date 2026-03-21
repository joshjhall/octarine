//! Crypto security builder
//!
//! Builder pattern for cryptographic security validation.

use crate::primitives::identifiers::crypto::{KeyType, SignatureAlgorithm};
use crate::primitives::types::Problem;

use super::detection;
use super::types::{CryptoAuditResult, CryptoPolicy, CryptoThreat};
use super::validation;

#[cfg(feature = "crypto-validation")]
use crate::primitives::data::crypto::{ParsedCertificate, ParsedPublicKey, ParsedSshPublicKey};

/// Builder for cryptographic security operations
///
/// Provides a unified interface for detecting and validating
/// security threats in cryptographic data.
///
/// # Example
///
/// ```ignore
/// use octarine::primitives::security::crypto::{CryptoSecurityBuilder, CryptoPolicy};
///
/// let builder = CryptoSecurityBuilder::with_policy(CryptoPolicy::strict());
///
/// // Validate a key type
/// builder.validate_key_strength(&key_type)?;
///
/// // Check if an algorithm is deprecated
/// if builder.is_deprecated_algorithm(&algo) {
///     // Handle deprecated algorithm
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CryptoSecurityBuilder {
    policy: CryptoPolicy,
}

impl Default for CryptoSecurityBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoSecurityBuilder {
    /// Create a new builder with standard policy
    pub fn new() -> Self {
        Self {
            policy: CryptoPolicy::standard(),
        }
    }

    /// Create a builder with a specific policy
    pub fn with_policy(policy: CryptoPolicy) -> Self {
        Self { policy }
    }

    /// Create a builder with strict policy
    pub fn strict() -> Self {
        Self {
            policy: CryptoPolicy::strict(),
        }
    }

    /// Create a builder with legacy policy
    pub fn legacy() -> Self {
        Self {
            policy: CryptoPolicy::legacy(),
        }
    }

    /// Create a builder for development/testing
    pub fn development() -> Self {
        Self {
            policy: CryptoPolicy::development(),
        }
    }

    /// Get the current policy
    pub fn policy(&self) -> &CryptoPolicy {
        &self.policy
    }

    // ========================================================================
    // Key Operations
    // ========================================================================

    /// Check if a key type is considered weak under current policy
    pub fn is_weak_key(&self, key_type: &KeyType) -> bool {
        detection::is_weak_key_type(key_type, &self.policy)
    }

    /// Validate that a key type meets minimum strength requirements
    pub fn validate_key_strength(&self, key_type: &KeyType) -> Result<(), Problem> {
        validation::validate_key_strength(key_type, &self.policy)
    }

    /// Validate a parsed public key
    #[cfg(feature = "crypto-validation")]
    pub fn validate_public_key(&self, key: &ParsedPublicKey) -> Result<(), Problem> {
        validation::validate_public_key(key, &self.policy)
    }

    /// Detect all threats in a public key
    #[cfg(feature = "crypto-validation")]
    pub fn detect_key_threats(&self, key: &ParsedPublicKey) -> Vec<CryptoThreat> {
        detection::detect_key_threats(key, &self.policy)
    }

    /// Audit a public key and return full results
    #[cfg(feature = "crypto-validation")]
    pub fn audit_key(&self, key: &ParsedPublicKey) -> CryptoAuditResult {
        detection::audit_key(key, &self.policy)
    }

    // ========================================================================
    // SSH Key Operations
    // ========================================================================

    /// Validate an SSH public key
    #[cfg(feature = "crypto-validation")]
    pub fn validate_ssh_key(&self, key: &ParsedSshPublicKey) -> Result<(), Problem> {
        validation::validate_ssh_public_key(key, &self.policy)
    }

    /// Detect all threats in an SSH key
    #[cfg(feature = "crypto-validation")]
    pub fn detect_ssh_key_threats(&self, key: &ParsedSshPublicKey) -> Vec<CryptoThreat> {
        detection::detect_ssh_key_threats(key, &self.policy)
    }

    /// Audit an SSH key and return full results
    #[cfg(feature = "crypto-validation")]
    pub fn audit_ssh_key(&self, key: &ParsedSshPublicKey) -> CryptoAuditResult {
        detection::audit_ssh_key(key, &self.policy)
    }

    // ========================================================================
    // Certificate Operations
    // ========================================================================

    /// Validate a certificate against security policy
    #[cfg(feature = "crypto-validation")]
    pub fn validate_certificate(&self, cert: &ParsedCertificate) -> Result<(), Problem> {
        validation::validate_certificate(cert, &self.policy)
    }

    /// Detect all threats in a certificate
    #[cfg(feature = "crypto-validation")]
    pub fn detect_cert_threats(&self, cert: &ParsedCertificate) -> Vec<CryptoThreat> {
        detection::detect_cert_threats(cert, &self.policy)
    }

    /// Audit a certificate and return full results
    #[cfg(feature = "crypto-validation")]
    pub fn audit_certificate(&self, cert: &ParsedCertificate) -> CryptoAuditResult {
        detection::audit_certificate(cert, &self.policy)
    }

    /// Check if a certificate is expired
    #[cfg(feature = "crypto-validation")]
    pub fn is_certificate_expired(&self, cert: &ParsedCertificate) -> bool {
        detection::is_certificate_expired(cert)
    }

    /// Check if a certificate is self-signed
    #[cfg(feature = "crypto-validation")]
    pub fn is_self_signed(&self, cert: &ParsedCertificate) -> bool {
        detection::is_self_signed(cert)
    }

    // ========================================================================
    // Algorithm Operations
    // ========================================================================

    /// Check if a signature algorithm is deprecated
    pub fn is_deprecated_algorithm(&self, algo: &SignatureAlgorithm) -> bool {
        detection::is_deprecated_signature_algorithm(algo)
    }

    /// Validate a signature algorithm
    pub fn validate_signature_algorithm(&self, algo: &SignatureAlgorithm) -> Result<(), Problem> {
        validation::validate_signature_algorithm(algo, &self.policy)
    }

    /// Check if a hash algorithm is insecure
    pub fn is_insecure_hash(&self, algorithm: &str) -> bool {
        detection::is_insecure_hash(algorithm)
    }

    /// Validate a hash algorithm
    pub fn validate_hash_algorithm(&self, algorithm: &str) -> Result<(), Problem> {
        validation::validate_hash_algorithm(algorithm, &self.policy)
    }

    // ========================================================================
    // Size Validation
    // ========================================================================

    /// Validate certificate data size
    pub fn validate_certificate_size(&self, data: &[u8]) -> Result<(), Problem> {
        validation::validate_certificate_size(data, &self.policy)
    }

    /// Validate key data size
    pub fn validate_key_size(&self, data: &[u8]) -> Result<(), Problem> {
        validation::validate_key_size(data, &self.policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_policies() {
        let standard = CryptoSecurityBuilder::new();
        assert_eq!(standard.policy().min_rsa_bits, 2048);

        let strict = CryptoSecurityBuilder::strict();
        assert_eq!(strict.policy().min_rsa_bits, 3072);

        let legacy = CryptoSecurityBuilder::legacy();
        assert_eq!(legacy.policy().min_rsa_bits, 1024);
    }

    #[test]
    fn test_weak_key_detection() {
        let strict = CryptoSecurityBuilder::strict();

        // RSA 2048 is weak under strict
        assert!(strict.is_weak_key(&KeyType::Rsa2048));

        // RSA 4096 is fine
        assert!(!strict.is_weak_key(&KeyType::Rsa4096));
    }

    #[test]
    fn test_algorithm_checks() {
        let builder = CryptoSecurityBuilder::new();

        assert!(builder.is_deprecated_algorithm(&SignatureAlgorithm::RsaPkcs1Md5));
        assert!(!builder.is_deprecated_algorithm(&SignatureAlgorithm::RsaPkcs1Sha256));

        assert!(builder.is_insecure_hash("MD5"));
        assert!(!builder.is_insecure_hash("SHA-256"));
    }

    #[test]
    fn test_size_validation() {
        let builder = CryptoSecurityBuilder::new();

        // Small data should pass
        let small_data = vec![0u8; 1000];
        assert!(builder.validate_key_size(&small_data).is_ok());

        // Large data should fail
        let large_data = vec![0u8; 2_000_000];
        assert!(builder.validate_key_size(&large_data).is_err());
    }
}

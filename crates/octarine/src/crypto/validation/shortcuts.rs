//! Crypto validation shortcuts
//!
//! Convenience functions for common crypto validation operations.

use super::{CryptoPolicy, KeyType, SignatureAlgorithm};
use crate::primitives::types::Problem;

#[cfg(feature = "crypto-validation")]
use super::CryptoAuditResult;
#[cfg(feature = "crypto-validation")]
use super::builder::CryptoValidationBuilder;
#[cfg(feature = "crypto-validation")]
use super::types::{ValidatedCertificate, ValidatedSshKey, ValidationSummary};

// ============================================================================
// Certificate Validation Shortcuts
// ============================================================================

/// Validate a PEM-encoded certificate with standard policy
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::validation::validate_certificate_pem;
///
/// let cert = validate_certificate_pem(pem_data)?;
/// println!("Subject: {}", cert.subject);
/// ```
#[cfg(feature = "crypto-validation")]
pub fn validate_certificate_pem(pem_data: &str) -> Result<ValidatedCertificate, Problem> {
    CryptoValidationBuilder::new().validate_certificate_pem(pem_data)
}

/// Validate a DER-encoded certificate with standard policy
#[cfg(feature = "crypto-validation")]
pub fn validate_certificate_der(der_data: &[u8]) -> Result<ValidatedCertificate, Problem> {
    CryptoValidationBuilder::new().validate_certificate_der(der_data)
}

/// Audit a certificate and return all issues (blocking and warnings)
#[cfg(feature = "crypto-validation")]
pub fn audit_certificate_pem(pem_data: &str) -> Result<CryptoAuditResult, Problem> {
    CryptoValidationBuilder::new().audit_certificate_pem(pem_data)
}

/// Get a summary of certificate validation issues
#[cfg(feature = "crypto-validation")]
pub fn summarize_certificate(pem_data: &str) -> Result<ValidationSummary, Problem> {
    CryptoValidationBuilder::new().summarize_certificate(pem_data)
}

// ============================================================================
// SSH Key Validation Shortcuts
// ============================================================================

/// Validate an SSH public key with standard policy
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::validation::validate_ssh_key;
///
/// let key = validate_ssh_key(ssh_data)?;
/// println!("Fingerprint: {}", key.fingerprint);
/// ```
#[cfg(feature = "crypto-validation")]
pub fn validate_ssh_key(ssh_data: &str) -> Result<ValidatedSshKey, Problem> {
    CryptoValidationBuilder::new().validate_ssh_key(ssh_data)
}

/// Audit an SSH key and return all issues
#[cfg(feature = "crypto-validation")]
pub fn audit_ssh_key(ssh_data: &str) -> Result<CryptoAuditResult, Problem> {
    CryptoValidationBuilder::new().audit_ssh_key(ssh_data)
}

/// Get a summary of SSH key validation issues
#[cfg(feature = "crypto-validation")]
pub fn summarize_ssh_key(ssh_data: &str) -> Result<ValidationSummary, Problem> {
    CryptoValidationBuilder::new().summarize_ssh_key(ssh_data)
}

// ============================================================================
// Format Validation Shortcuts
// ============================================================================

/// Validate PEM format
#[cfg(feature = "crypto-validation")]
pub fn validate_pem_format(pem_data: &str) -> Result<(), Problem> {
    CryptoValidationBuilder::new().validate_pem_format(pem_data)
}

/// Check if data looks like PEM format
#[cfg(feature = "crypto-validation")]
pub fn is_pem_format(data: &str) -> bool {
    CryptoValidationBuilder::new().is_pem_format(data)
}

/// Check if data looks like SSH key format
#[cfg(feature = "crypto-validation")]
pub fn is_ssh_key_format(data: &str) -> bool {
    CryptoValidationBuilder::new().is_ssh_key_format(data)
}

// ============================================================================
// Key Strength Shortcuts
// ============================================================================

/// Check if a key type meets standard strength requirements
pub fn is_strong_key(key_type: &KeyType) -> bool {
    !CryptoValidationBuilder::new().is_weak_key(key_type)
}

/// Check if a key type meets strict strength requirements
pub fn is_strong_key_strict(key_type: &KeyType) -> bool {
    !CryptoValidationBuilder::strict().is_weak_key(key_type)
}

/// Validate key strength with standard policy
pub fn validate_key_strength(key_type: &KeyType) -> Result<(), Problem> {
    CryptoValidationBuilder::new().validate_key_strength(key_type)
}

/// Validate key strength with strict policy
pub fn validate_key_strength_strict(key_type: &KeyType) -> Result<(), Problem> {
    CryptoValidationBuilder::strict().validate_key_strength(key_type)
}

// ============================================================================
// Algorithm Validation Shortcuts
// ============================================================================

/// Check if a signature algorithm is safe to use
pub fn is_safe_signature_algorithm(algo: &SignatureAlgorithm) -> bool {
    !CryptoValidationBuilder::new().is_deprecated_algorithm(algo)
}

/// Validate a signature algorithm with standard policy
pub fn validate_signature_algorithm(algo: &SignatureAlgorithm) -> Result<(), Problem> {
    CryptoValidationBuilder::new().validate_signature_algorithm(algo)
}

/// Check if a hash algorithm is secure
pub fn is_secure_hash(algorithm: &str) -> bool {
    !CryptoValidationBuilder::new().is_insecure_hash(algorithm)
}

/// Validate a hash algorithm with standard policy
pub fn validate_hash_algorithm(algorithm: &str) -> Result<(), Problem> {
    CryptoValidationBuilder::new().validate_hash_algorithm(algorithm)
}

// ============================================================================
// Policy Shortcuts
// ============================================================================

/// Get the standard crypto policy
pub fn standard_policy() -> CryptoPolicy {
    CryptoPolicy::standard()
}

/// Get the strict crypto policy
pub fn strict_policy() -> CryptoPolicy {
    CryptoPolicy::strict()
}

/// Get the legacy crypto policy
pub fn legacy_policy() -> CryptoPolicy {
    CryptoPolicy::legacy()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_strength_shortcuts() {
        // RSA 4096 is strong under any policy
        assert!(is_strong_key(&KeyType::Rsa4096));
        assert!(is_strong_key_strict(&KeyType::Rsa4096));

        // RSA 2048 is standard strength but weak under strict
        assert!(is_strong_key(&KeyType::Rsa2048));
        assert!(!is_strong_key_strict(&KeyType::Rsa2048));
    }

    #[test]
    fn test_algorithm_shortcuts() {
        // SHA-256 is safe
        assert!(is_safe_signature_algorithm(
            &SignatureAlgorithm::RsaPkcs1Sha256
        ));
        assert!(is_secure_hash("SHA-256"));

        // MD5 is not safe
        assert!(!is_safe_signature_algorithm(
            &SignatureAlgorithm::RsaPkcs1Md5
        ));
        assert!(!is_secure_hash("MD5"));
    }

    #[test]
    fn test_policy_shortcuts() {
        let standard = standard_policy();
        assert_eq!(standard.min_rsa_bits, 2048);

        let strict = strict_policy();
        assert_eq!(strict.min_rsa_bits, 3072);

        let legacy = legacy_policy();
        assert_eq!(legacy.min_rsa_bits, 1024);
    }
}

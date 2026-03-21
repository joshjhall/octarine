//! Crypto validation functions
//!
//! Validation functions that return Result types for security checks.

use crate::primitives::types::Problem;

use super::detection::{
    check_signature_algorithm, detect_hash_threats, is_deprecated_signature_algorithm,
    is_weak_key_type,
};
use super::types::CryptoPolicy;
use crate::primitives::identifiers::crypto::{KeyType, SignatureAlgorithm};

#[cfg(feature = "crypto-validation")]
use super::detection::{detect_cert_threats, detect_key_threats, detect_ssh_key_threats};
#[cfg(feature = "crypto-validation")]
use crate::primitives::data::crypto::{ParsedCertificate, ParsedPublicKey, ParsedSshPublicKey};

// ============================================================================
// Key Validation
// ============================================================================

/// Validate that a key type meets minimum strength requirements
///
/// # Arguments
/// * `key_type` - The type of key to validate
/// * `policy` - Security policy to apply
///
/// # Returns
/// `Ok(())` if key meets requirements, error otherwise
pub fn validate_key_strength(key_type: &KeyType, policy: &CryptoPolicy) -> Result<(), Problem> {
    if is_weak_key_type(key_type, policy) {
        return Err(Problem::validation(format!(
            "Key type {:?} does not meet minimum strength requirements",
            key_type
        )));
    }
    Ok(())
}

/// Validate a parsed public key against security policy
///
/// Checks for:
/// - Minimum key size
/// - Deprecated algorithms
/// - Size limits
///
/// # Arguments
/// * `key` - Parsed public key
/// * `policy` - Security policy to apply
///
/// # Returns
/// `Ok(())` if key passes all checks, error with first blocking threat otherwise
#[cfg(feature = "crypto-validation")]
pub fn validate_public_key(key: &ParsedPublicKey, policy: &CryptoPolicy) -> Result<(), Problem> {
    let threats = detect_key_threats(key, policy);

    for threat in threats {
        if threat.is_blocking() {
            return Err(Problem::validation(threat.description()));
        }
    }

    Ok(())
}

/// Validate an SSH public key against security policy
#[cfg(feature = "crypto-validation")]
pub fn validate_ssh_public_key(
    key: &ParsedSshPublicKey,
    policy: &CryptoPolicy,
) -> Result<(), Problem> {
    let threats = detect_ssh_key_threats(key, policy);

    for threat in threats {
        if threat.is_blocking() {
            return Err(Problem::validation(threat.description()));
        }
    }

    Ok(())
}

// ============================================================================
// Certificate Validation
// ============================================================================

/// Validate a certificate against security policy
///
/// Checks for:
/// - Valid dates (not expired, not future-dated)
/// - Self-signed status
/// - Signature algorithm strength
/// - Public key strength
/// - Validity period length
///
/// # Arguments
/// * `cert` - Parsed certificate
/// * `policy` - Security policy to apply
///
/// # Returns
/// `Ok(())` if certificate passes all checks
#[cfg(feature = "crypto-validation")]
pub fn validate_certificate(
    cert: &ParsedCertificate,
    policy: &CryptoPolicy,
) -> Result<(), Problem> {
    let threats = detect_cert_threats(cert, policy);

    for threat in threats {
        if threat.is_blocking() {
            return Err(Problem::validation(threat.description()));
        }
    }

    Ok(())
}

/// Validate that a certificate is not expired
#[cfg(feature = "crypto-validation")]
pub fn validate_certificate_not_expired(cert: &ParsedCertificate) -> Result<(), Problem> {
    if cert.is_expired() {
        return Err(Problem::validation(format!(
            "Certificate expired on {}",
            cert.not_after
        )));
    }
    Ok(())
}

/// Validate that a certificate is currently valid (not expired and not future-dated)
#[cfg(feature = "crypto-validation")]
pub fn validate_certificate_validity(cert: &ParsedCertificate) -> Result<(), Problem> {
    if cert.is_not_yet_valid() {
        return Err(Problem::validation(format!(
            "Certificate not valid until {}",
            cert.not_before
        )));
    }
    if cert.is_expired() {
        return Err(Problem::validation(format!(
            "Certificate expired on {}",
            cert.not_after
        )));
    }
    Ok(())
}

// ============================================================================
// Algorithm Validation
// ============================================================================

/// Validate that a signature algorithm is not deprecated
pub fn validate_signature_algorithm_not_deprecated(
    algo: &SignatureAlgorithm,
) -> Result<(), Problem> {
    if is_deprecated_signature_algorithm(algo) {
        return Err(Problem::validation(format!(
            "Signature algorithm {:?} is deprecated",
            algo
        )));
    }
    Ok(())
}

/// Validate a signature algorithm against policy
pub fn validate_signature_algorithm(
    algo: &SignatureAlgorithm,
    policy: &CryptoPolicy,
) -> Result<(), Problem> {
    if let Some(threat) = check_signature_algorithm(algo, policy) {
        return Err(Problem::validation(threat.description()));
    }
    Ok(())
}

/// Validate that a hash algorithm is secure
pub fn validate_hash_algorithm(algorithm: &str, policy: &CryptoPolicy) -> Result<(), Problem> {
    if let Some(threat) = detect_hash_threats(algorithm, policy) {
        return Err(Problem::validation(threat.description()));
    }
    Ok(())
}

// ============================================================================
// Size Validation
// ============================================================================

/// Validate that data does not exceed size limits
///
/// # Arguments
/// * `size` - Actual size in bytes
/// * `max_size` - Maximum allowed size
/// * `data_type` - Description of what is being validated (for error message)
pub fn validate_data_size(size: usize, max_size: usize, data_type: &str) -> Result<(), Problem> {
    if size > max_size {
        return Err(Problem::validation(format!(
            "{} size ({} bytes) exceeds maximum ({} bytes)",
            data_type, size, max_size
        )));
    }
    Ok(())
}

/// Validate certificate data size
pub fn validate_certificate_size(data: &[u8], policy: &CryptoPolicy) -> Result<(), Problem> {
    validate_data_size(data.len(), policy.max_cert_size, "Certificate")
}

/// Validate key data size
pub fn validate_key_size(data: &[u8], policy: &CryptoPolicy) -> Result<(), Problem> {
    validate_data_size(data.len(), policy.max_key_size, "Key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_key_strength() {
        let policy = CryptoPolicy::strict();

        // RSA 2048 fails strict policy
        let result = validate_key_strength(&KeyType::Rsa2048, &policy);
        assert!(result.is_err());

        // RSA 4096 passes
        let result = validate_key_strength(&KeyType::Rsa4096, &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_signature_algorithm() {
        // MD5 is always rejected
        let result = validate_signature_algorithm_not_deprecated(&SignatureAlgorithm::RsaPkcs1Md5);
        assert!(result.is_err());

        // SHA-256 is fine
        let result =
            validate_signature_algorithm_not_deprecated(&SignatureAlgorithm::RsaPkcs1Sha256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_hash_algorithm() {
        let policy = CryptoPolicy::standard();

        // MD5 fails
        let result = validate_hash_algorithm("MD5", &policy);
        assert!(result.is_err());

        // SHA-256 passes
        let result = validate_hash_algorithm("SHA256", &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_data_size() {
        let result = validate_data_size(100, 200, "Test");
        assert!(result.is_ok());

        let result = validate_data_size(300, 200, "Test");
        assert!(result.is_err());
    }
}

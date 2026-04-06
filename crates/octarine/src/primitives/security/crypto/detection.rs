//! Crypto threat detection
//!
//! Pure functions for detecting security threats in cryptographic data.

use chrono::Utc;

use crate::primitives::identifiers::crypto::{KeyType, SignatureAlgorithm};

use super::types::{CryptoAuditResult, CryptoPolicy, CryptoThreat};

// Import data types when feature is enabled
#[cfg(feature = "crypto-validation")]
use crate::primitives::data::crypto::{ParsedCertificate, ParsedPublicKey, ParsedSshPublicKey};

// ============================================================================
// Key Threat Detection
// ============================================================================

/// Detect threats in a parsed public key
#[cfg(feature = "crypto-validation")]
pub fn detect_key_threats(key: &ParsedPublicKey, policy: &CryptoPolicy) -> Vec<CryptoThreat> {
    let mut threats = Vec::new();

    // Check key size
    if let Some(threat) = detect_key_size_threat(&key.key_type, policy) {
        threats.push(threat);
    }

    // Check for deprecated key algorithms
    if let Some(threat) = detect_deprecated_key_algorithm(&key.key_type) {
        threats.push(threat);
    }

    // Check raw data size
    if key.raw_bytes.len() > policy.max_key_size {
        threats.push(CryptoThreat::SuspiciouslyLargeData {
            size: key.raw_bytes.len(),
            threshold: policy.max_key_size,
        });
    }

    threats
}

/// Detect threats in an SSH public key
#[cfg(feature = "crypto-validation")]
pub fn detect_ssh_key_threats(
    key: &ParsedSshPublicKey,
    policy: &CryptoPolicy,
) -> Vec<CryptoThreat> {
    let mut threats = Vec::new();

    // Check key size based on algorithm
    if let Some(threat) = detect_key_size_threat(&key.key_type, policy) {
        threats.push(threat);
    }

    // Check for deprecated algorithms
    if let Some(threat) = detect_deprecated_key_algorithm(&key.key_type) {
        threats.push(threat);
    }

    // Check data size
    if key.key_data.len() > policy.max_key_size {
        threats.push(CryptoThreat::SuspiciouslyLargeData {
            size: key.key_data.len(),
            threshold: policy.max_key_size,
        });
    }

    threats
}

// ============================================================================
// Certificate Threat Detection
// ============================================================================

/// Detect threats in a parsed certificate
#[cfg(feature = "crypto-validation")]
pub fn detect_cert_threats(cert: &ParsedCertificate, policy: &CryptoPolicy) -> Vec<CryptoThreat> {
    let mut threats = Vec::new();

    // Check validity dates
    if policy.require_valid_dates {
        let _now = Utc::now(); // Keep for potential future use

        if cert.is_expired() {
            threats.push(CryptoThreat::ExpiredCertificate {
                expired_at: cert.not_after,
            });
        }

        if cert.is_not_yet_valid() {
            threats.push(CryptoThreat::NotYetValidCertificate {
                valid_from: cert.not_before,
            });
        }

        // Check for expiring soon
        let days_remaining = cert.days_until_expiry();
        if days_remaining > 0 && days_remaining <= policy.expiry_warning_days && !cert.is_expired()
        {
            threats.push(CryptoThreat::CertificateExpiringSoon {
                days_remaining,
                threshold: policy.expiry_warning_days,
            });
        }

        // Check validity period length
        #[allow(clippy::arithmetic_side_effects)] // DateTime subtraction is safe
        let validity_days = (cert.not_after - cert.not_before).num_days();
        if validity_days > policy.max_validity_days {
            threats.push(CryptoThreat::ExcessiveValidityPeriod {
                days: validity_days,
                maximum: policy.max_validity_days,
            });
        }
    }

    // Check self-signed
    if cert.is_self_signed && !policy.allow_self_signed {
        threats.push(CryptoThreat::SelfSignedCertificate);
    }

    // Check signature algorithm
    if let Some(threat) = detect_signature_algorithm_threat(&cert.signature_algorithm, policy) {
        threats.push(threat);
    }

    // Check public key
    if let Some(threat) = detect_key_size_threat(&cert.public_key_type, policy) {
        threats.push(threat);
    }

    threats
}

// ============================================================================
// Algorithm Threat Detection
// ============================================================================

/// Check if a signature algorithm is weak or deprecated
pub fn detect_signature_algorithm_threat(
    algo: &SignatureAlgorithm,
    policy: &CryptoPolicy,
) -> Option<CryptoThreat> {
    match algo {
        SignatureAlgorithm::RsaPkcs1Md5 => Some(CryptoThreat::InsecureHashFunction {
            algorithm: "MD5".to_string(),
        }),
        SignatureAlgorithm::RsaPkcs1Sha1 if !policy.allow_sha1_signatures => {
            Some(CryptoThreat::WeakSignatureAlgorithm {
                algorithm: "RSA-SHA1".to_string(),
                reason: "SHA-1 is deprecated for signatures".to_string(),
            })
        }
        SignatureAlgorithm::Unknown => Some(CryptoThreat::DeprecatedKeyAlgorithm {
            algorithm: "Unknown".to_string(),
            reason: "Unrecognized signature algorithm".to_string(),
        }),
        _ => None,
    }
}

/// Check if a hash algorithm is insecure
pub fn is_insecure_hash(algorithm: &str) -> bool {
    let algo_lower = algorithm.to_lowercase();
    algo_lower == "md5" || algo_lower == "md4" || algo_lower == "sha1" || algo_lower == "sha-1"
}

/// Detect hash algorithm threats
pub fn detect_hash_threats(algorithm: &str, policy: &CryptoPolicy) -> Option<CryptoThreat> {
    let algo_lower = algorithm.to_lowercase();

    if (algo_lower == "md5" || algo_lower == "md4") && !policy.allow_md5 {
        return Some(CryptoThreat::InsecureHashFunction {
            algorithm: algorithm.to_string(),
        });
    }

    if (algo_lower == "sha1" || algo_lower == "sha-1") && !policy.allow_sha1_signatures {
        return Some(CryptoThreat::InsecureHashFunction {
            algorithm: algorithm.to_string(),
        });
    }

    None
}

// ============================================================================
// Quick Check Functions (is_*)
// ============================================================================

/// Check if a key type represents a weak key
pub fn is_weak_key_type(key_type: &KeyType, policy: &CryptoPolicy) -> bool {
    detect_key_size_threat(key_type, policy).is_some()
}

/// Check if a signature algorithm is deprecated
pub fn is_deprecated_signature_algorithm(algo: &SignatureAlgorithm) -> bool {
    matches!(
        algo,
        SignatureAlgorithm::RsaPkcs1Md5
            | SignatureAlgorithm::RsaPkcs1Sha1
            | SignatureAlgorithm::Unknown
    )
}

/// Check if a certificate is expired
#[cfg(feature = "crypto-validation")]
pub fn is_certificate_expired(cert: &ParsedCertificate) -> bool {
    cert.is_expired()
}

/// Check if a certificate is not yet valid
#[cfg(feature = "crypto-validation")]
pub fn is_certificate_not_yet_valid(cert: &ParsedCertificate) -> bool {
    cert.is_not_yet_valid()
}

/// Check if a certificate is self-signed
#[cfg(feature = "crypto-validation")]
pub fn is_self_signed(cert: &ParsedCertificate) -> bool {
    cert.is_self_signed
}

// ============================================================================
// Audit Functions
// ============================================================================

/// Perform a full security audit on a public key
#[cfg(feature = "crypto-validation")]
pub fn audit_key(key: &ParsedPublicKey, policy: &CryptoPolicy) -> CryptoAuditResult {
    let mut result = CryptoAuditResult::new();
    for threat in detect_key_threats(key, policy) {
        result.add_threat(threat);
    }
    result
}

/// Perform a full security audit on a certificate
#[cfg(feature = "crypto-validation")]
pub fn audit_certificate(cert: &ParsedCertificate, policy: &CryptoPolicy) -> CryptoAuditResult {
    let mut result = CryptoAuditResult::new();
    for threat in detect_cert_threats(cert, policy) {
        result.add_threat(threat);
    }
    result
}

/// Perform a full security audit on an SSH key
#[cfg(feature = "crypto-validation")]
pub fn audit_ssh_key(key: &ParsedSshPublicKey, policy: &CryptoPolicy) -> CryptoAuditResult {
    let mut result = CryptoAuditResult::new();
    for threat in detect_ssh_key_threats(key, policy) {
        result.add_threat(threat);
    }
    result
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check key size against policy
fn detect_key_size_threat(key_type: &KeyType, policy: &CryptoPolicy) -> Option<CryptoThreat> {
    match key_type {
        KeyType::Rsa2048 if policy.min_rsa_bits > 2048 => Some(CryptoThreat::WeakRsaKeySize {
            bits: 2048,
            minimum: policy.min_rsa_bits,
        }),
        KeyType::Rsa3072 if policy.min_rsa_bits > 3072 => Some(CryptoThreat::WeakRsaKeySize {
            bits: 3072,
            minimum: policy.min_rsa_bits,
        }),
        KeyType::Rsa4096 if policy.min_rsa_bits > 4096 => Some(CryptoThreat::WeakRsaKeySize {
            bits: 4096,
            minimum: policy.min_rsa_bits,
        }),
        KeyType::RsaOther(bits) if *bits < policy.min_rsa_bits => {
            Some(CryptoThreat::WeakRsaKeySize {
                bits: *bits,
                minimum: policy.min_rsa_bits,
            })
        }
        KeyType::P256 if policy.min_ec_bits > 256 => Some(CryptoThreat::WeakEcKeySize {
            bits: 256,
            minimum: policy.min_ec_bits,
        }),
        KeyType::P384 if policy.min_ec_bits > 384 => Some(CryptoThreat::WeakEcKeySize {
            bits: 384,
            minimum: policy.min_ec_bits,
        }),
        KeyType::P521 if policy.min_ec_bits > 521 => Some(CryptoThreat::WeakEcKeySize {
            bits: 521,
            minimum: policy.min_ec_bits,
        }),
        KeyType::SshRsa => {
            // SSH RSA keys don't carry size info in the type, would need to check data
            None
        }
        _ => None,
    }
}

/// Check for deprecated key algorithms
fn detect_deprecated_key_algorithm(key_type: &KeyType) -> Option<CryptoThreat> {
    match key_type {
        KeyType::SshDsa => Some(CryptoThreat::DeprecatedKeyAlgorithm {
            algorithm: "DSA".to_string(),
            reason: "DSA keys are deprecated and should not be used".to_string(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_key_detection() {
        let policy = CryptoPolicy::strict();

        // RSA 2048 is weak under strict policy (requires 3072)
        assert!(is_weak_key_type(&KeyType::Rsa2048, &policy));

        // RSA 4096 is fine
        assert!(!is_weak_key_type(&KeyType::Rsa4096, &policy));

        // P-256 is weak under strict policy (requires 384)
        assert!(is_weak_key_type(&KeyType::P256, &policy));
    }

    #[test]
    fn test_deprecated_algorithms() {
        assert!(is_deprecated_signature_algorithm(
            &SignatureAlgorithm::RsaPkcs1Md5
        ));
        assert!(is_deprecated_signature_algorithm(
            &SignatureAlgorithm::RsaPkcs1Sha1
        ));
        assert!(!is_deprecated_signature_algorithm(
            &SignatureAlgorithm::RsaPkcs1Sha256
        ));
    }

    #[test]
    fn test_insecure_hash() {
        assert!(is_insecure_hash("MD5"));
        assert!(is_insecure_hash("SHA1"));
        assert!(is_insecure_hash("sha-1"));
        assert!(!is_insecure_hash("SHA256"));
        assert!(!is_insecure_hash("SHA-384"));
    }

    #[test]
    fn test_hash_threat_detection() {
        let policy = CryptoPolicy::standard();

        let md5_threat = detect_hash_threats("MD5", &policy);
        assert!(md5_threat.is_some());

        let sha256_threat = detect_hash_threats("SHA256", &policy);
        assert!(sha256_threat.is_none());
    }
}

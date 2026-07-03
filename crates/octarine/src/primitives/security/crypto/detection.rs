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
    #![allow(clippy::panic, clippy::expect_used)]
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

    // ========================================================================
    // Signature algorithm threat detection
    // ========================================================================

    #[test]
    fn test_signature_algorithm_threat_md5_always_insecure() {
        // MD5 is flagged regardless of policy allowances.
        let policy = CryptoPolicy::legacy();
        let threat = detect_signature_algorithm_threat(&SignatureAlgorithm::RsaPkcs1Md5, &policy);
        assert!(matches!(
            threat,
            Some(CryptoThreat::InsecureHashFunction { algorithm }) if algorithm == "MD5"
        ));
    }

    #[test]
    fn test_signature_algorithm_threat_sha1_policy_gated() {
        // SHA-1 is a threat under standard policy...
        let standard = CryptoPolicy::standard();
        assert!(matches!(
            detect_signature_algorithm_threat(&SignatureAlgorithm::RsaPkcs1Sha1, &standard),
            Some(CryptoThreat::WeakSignatureAlgorithm { .. })
        ));

        // ...but permitted under legacy policy (allow_sha1_signatures = true).
        let legacy = CryptoPolicy::legacy();
        assert!(
            detect_signature_algorithm_threat(&SignatureAlgorithm::RsaPkcs1Sha1, &legacy).is_none()
        );
    }

    #[test]
    fn test_signature_algorithm_threat_unknown() {
        let policy = CryptoPolicy::standard();
        assert!(matches!(
            detect_signature_algorithm_threat(&SignatureAlgorithm::Unknown, &policy),
            Some(CryptoThreat::DeprecatedKeyAlgorithm { .. })
        ));
    }

    #[test]
    fn test_signature_algorithm_threat_secure_none() {
        let policy = CryptoPolicy::strict();
        for algo in [
            SignatureAlgorithm::RsaPkcs1Sha256,
            SignatureAlgorithm::EcdsaP256Sha256,
            SignatureAlgorithm::Ed25519,
        ] {
            assert!(
                detect_signature_algorithm_threat(&algo, &policy).is_none(),
                "{algo:?} should be considered secure"
            );
        }
    }

    // ========================================================================
    // is_insecure_hash edge cases
    // ========================================================================

    #[test]
    fn test_is_insecure_hash_table() {
        // (input, expected_insecure)
        let cases = [
            ("MD5", true),
            ("md5", true),
            ("MD4", true),
            ("SHA1", true),
            ("sha-1", true),
            ("SHA-1", true),
            ("SHA256", false),
            ("SHA-256", false),
            ("SHA512", false),
            ("BLAKE2", false),
            ("", false),
        ];
        for (input, expected) in cases {
            assert_eq!(
                is_insecure_hash(input),
                expected,
                "is_insecure_hash({input:?})"
            );
        }
    }

    #[test]
    fn test_detect_hash_threats_policy_allowances() {
        // Legacy policy allows SHA-1 but NOT MD5 ("MD5 is never acceptable").
        let legacy = CryptoPolicy::legacy();
        assert!(
            detect_hash_threats("md5", &legacy).is_some(),
            "MD5 must be flagged even under legacy policy"
        );
        assert!(
            detect_hash_threats("sha1", &legacy).is_none(),
            "SHA-1 is permitted under legacy policy"
        );

        // Development policy explicitly allows MD5.
        let dev = CryptoPolicy::development();
        assert!(detect_hash_threats("md5", &dev).is_none());
        assert!(detect_hash_threats("sha1", &dev).is_none());

        // Standard policy flags both MD-family and SHA-1.
        let standard = CryptoPolicy::standard();
        assert!(detect_hash_threats("md4", &standard).is_some());
        assert!(detect_hash_threats("SHA-1", &standard).is_some());
        // Unknown/secure hashes never flagged.
        assert!(detect_hash_threats("sha384", &standard).is_none());
    }

    // ========================================================================
    // Key size / EC / deprecated key type detection
    // ========================================================================

    #[test]
    fn test_weak_ec_key_detection() {
        let strict = CryptoPolicy::strict(); // min_ec_bits = 384
        // P-256 (256 bits) is below the strict EC minimum.
        assert!(is_weak_key_type(&KeyType::P256, &strict));
        // P-384 meets it; P-521 exceeds it.
        assert!(!is_weak_key_type(&KeyType::P384, &strict));
        assert!(!is_weak_key_type(&KeyType::P521, &strict));

        let standard = CryptoPolicy::standard(); // min_ec_bits = 256
        assert!(!is_weak_key_type(&KeyType::P256, &standard));
    }

    #[test]
    fn test_rsa_other_weak_when_below_minimum() {
        let standard = CryptoPolicy::standard(); // min_rsa_bits = 2048
        assert!(is_weak_key_type(&KeyType::RsaOther(1024), &standard));
        assert!(!is_weak_key_type(&KeyType::RsaOther(4096), &standard));
    }

    #[test]
    fn test_deprecated_ssh_dsa_algorithm() {
        // DSA SSH keys are always flagged as deprecated.
        assert!(matches!(
            detect_deprecated_key_algorithm(&KeyType::SshDsa),
            Some(CryptoThreat::DeprecatedKeyAlgorithm { algorithm, .. }) if algorithm == "DSA"
        ));
        // Non-DSA keys are not.
        assert!(detect_deprecated_key_algorithm(&KeyType::SshEd25519).is_none());
        assert!(detect_deprecated_key_algorithm(&KeyType::Rsa2048).is_none());
    }

    #[test]
    fn test_is_deprecated_signature_algorithm_table() {
        let cases = [
            (SignatureAlgorithm::RsaPkcs1Md5, true),
            (SignatureAlgorithm::RsaPkcs1Sha1, true),
            (SignatureAlgorithm::Unknown, true),
            (SignatureAlgorithm::RsaPkcs1Sha256, false),
            (SignatureAlgorithm::EcdsaP256Sha256, false),
            (SignatureAlgorithm::Ed25519, false),
        ];
        for (algo, expected) in cases {
            assert_eq!(
                is_deprecated_signature_algorithm(&algo),
                expected,
                "{algo:?}"
            );
        }
    }

    // ========================================================================
    // Feature-gated: parsed-key / certificate threat detection + audits
    // ========================================================================

    #[cfg(feature = "crypto-validation")]
    mod gated {
        use super::*;
        use crate::primitives::data::crypto::{
            ParsedCertificate, ParsedPublicKey, ParsedSshPublicKey,
        };
        use crate::primitives::identifiers::crypto::KeyFormat;
        use chrono::{Duration, Utc};

        fn cert_with_validity(
            not_before: chrono::DateTime<Utc>,
            not_after: chrono::DateTime<Utc>,
            self_signed: bool,
            sig: SignatureAlgorithm,
            key: KeyType,
        ) -> ParsedCertificate {
            ParsedCertificate {
                version: 3,
                serial_number: "01".to_string(),
                subject: "CN=test".to_string(),
                issuer: if self_signed {
                    "CN=test".to_string()
                } else {
                    "CN=ca".to_string()
                },
                not_before,
                not_after,
                public_key_type: key,
                signature_algorithm: sig,
                is_ca: false,
                key_usage: Vec::new(),
                extended_key_usage: Vec::new(),
                subject_alt_names: Vec::new(),
                is_self_signed: self_signed,
            }
        }

        #[test]
        fn test_detect_key_threats_weak_rsa() {
            let policy = CryptoPolicy::strict(); // requires RSA 3072+
            let key = ParsedPublicKey::new(KeyType::Rsa2048, KeyFormat::Pem, vec![1, 2, 3]);
            let threats = detect_key_threats(&key, &policy);
            assert!(
                threats
                    .iter()
                    .any(|t| matches!(t, CryptoThreat::WeakRsaKeySize { .. }))
            );
        }

        #[test]
        fn test_detect_key_threats_oversized_data() {
            let mut policy = CryptoPolicy::standard();
            policy.max_key_size = 4;
            let key = ParsedPublicKey::new(KeyType::Rsa4096, KeyFormat::Pem, vec![0u8; 100]);
            let threats = detect_key_threats(&key, &policy);
            assert!(threats.iter().any(|t| matches!(
                t,
                CryptoThreat::SuspiciouslyLargeData {
                    size: 100,
                    threshold: 4
                }
            )));
        }

        #[test]
        fn test_detect_ssh_key_threats_deprecated_dsa() {
            let policy = CryptoPolicy::standard();
            let key = ParsedSshPublicKey::new(KeyType::SshDsa, "ssh-dss", vec![1, 2, 3]);
            let threats = detect_ssh_key_threats(&key, &policy);
            assert!(threats.iter().any(|t| matches!(
                t,
                CryptoThreat::DeprecatedKeyAlgorithm { algorithm, .. } if algorithm == "DSA"
            )));
        }

        #[test]
        fn test_detect_cert_threats_expired() {
            let policy = CryptoPolicy::standard();
            let now = Utc::now();
            let cert = cert_with_validity(
                now - Duration::days(400),
                now - Duration::days(1), // expired yesterday
                false,
                SignatureAlgorithm::RsaPkcs1Sha256,
                KeyType::Rsa2048,
            );
            assert!(is_certificate_expired(&cert));
            let threats = detect_cert_threats(&cert, &policy);
            assert!(
                threats
                    .iter()
                    .any(|t| matches!(t, CryptoThreat::ExpiredCertificate { .. }))
            );
        }

        #[test]
        fn test_detect_cert_threats_not_yet_valid() {
            let policy = CryptoPolicy::standard();
            let now = Utc::now();
            let cert = cert_with_validity(
                now + Duration::days(5), // valid in the future
                now + Duration::days(400),
                false,
                SignatureAlgorithm::RsaPkcs1Sha256,
                KeyType::Rsa2048,
            );
            assert!(is_certificate_not_yet_valid(&cert));
            let threats = detect_cert_threats(&cert, &policy);
            assert!(
                threats
                    .iter()
                    .any(|t| matches!(t, CryptoThreat::NotYetValidCertificate { .. }))
            );
        }

        #[test]
        fn test_detect_cert_threats_expiring_soon() {
            let policy = CryptoPolicy::standard(); // expiry_warning_days = 30
            let now = Utc::now();
            let cert = cert_with_validity(
                now - Duration::days(10),
                now + Duration::days(10), // expires within the warning window
                false,
                SignatureAlgorithm::RsaPkcs1Sha256,
                KeyType::Rsa2048,
            );
            let threats = detect_cert_threats(&cert, &policy);
            assert!(
                threats
                    .iter()
                    .any(|t| matches!(t, CryptoThreat::CertificateExpiringSoon { .. }))
            );
        }

        #[test]
        fn test_detect_cert_threats_excessive_validity_and_self_signed() {
            let policy = CryptoPolicy::standard(); // max_validity_days = 825, no self-signed
            let now = Utc::now();
            let cert = cert_with_validity(
                now - Duration::days(1),
                now + Duration::days(3650), // 10 years > 825
                true,                       // self-signed
                SignatureAlgorithm::RsaPkcs1Sha256,
                KeyType::Rsa2048,
            );
            assert!(is_self_signed(&cert));
            let threats = detect_cert_threats(&cert, &policy);
            assert!(
                threats
                    .iter()
                    .any(|t| matches!(t, CryptoThreat::ExcessiveValidityPeriod { .. }))
            );
            assert!(
                threats
                    .iter()
                    .any(|t| matches!(t, CryptoThreat::SelfSignedCertificate))
            );
        }

        #[test]
        fn test_valid_cert_produces_no_threats() {
            let policy = CryptoPolicy::standard();
            let now = Utc::now();
            let cert = cert_with_validity(
                now - Duration::days(10),
                now + Duration::days(200), // well inside limits, not expiring soon
                false,
                SignatureAlgorithm::RsaPkcs1Sha256,
                KeyType::Rsa2048,
            );
            let threats = detect_cert_threats(&cert, &policy);
            assert!(
                threats.is_empty(),
                "unexpected threats for a healthy cert: {threats:?}"
            );
        }

        #[test]
        fn test_audit_certificate_blocking() {
            let policy = CryptoPolicy::standard();
            let now = Utc::now();
            // Expired (severity 8, blocking) => audit fails.
            let cert = cert_with_validity(
                now - Duration::days(400),
                now - Duration::days(1),
                false,
                SignatureAlgorithm::RsaPkcs1Sha256,
                KeyType::Rsa2048,
            );
            let result = audit_certificate(&cert, &policy);
            assert!(!result.passed());
            assert!(!result.blocking_threats().is_empty());
        }

        #[test]
        fn test_audit_key_and_ssh_key() {
            let policy = CryptoPolicy::strict();
            let key = ParsedPublicKey::new(KeyType::Rsa2048, KeyFormat::Pem, vec![1, 2, 3]);
            let audit = audit_key(&key, &policy);
            // WeakRsaKeySize at 2048 has severity 5 (non-blocking) => audit passes
            // but records a warning.
            assert!(!audit.warnings().is_empty());

            let ssh = ParsedSshPublicKey::new(KeyType::SshDsa, "ssh-dss", vec![1, 2, 3]);
            let ssh_audit = audit_ssh_key(&ssh, &policy);
            assert!(!ssh_audit.threats.is_empty());
        }
    }
}

//! Crypto security types
//!
//! Types for cryptographic threat detection and policy configuration.

use chrono::{DateTime, Utc};

/// Cryptographic threats detected in keys, certificates, or algorithms
///
/// These are security-relevant issues found during crypto validation.
#[derive(Debug, Clone, PartialEq)]
pub enum CryptoThreat {
    // ========================================================================
    // Key Threats
    // ========================================================================
    /// RSA key with insufficient bit length
    WeakRsaKeySize {
        /// Actual key size in bits
        bits: usize,
        /// Minimum recommended size
        minimum: usize,
    },

    /// EC key with insufficient curve size
    WeakEcKeySize {
        /// Actual curve bits
        bits: usize,
        /// Minimum recommended size
        minimum: usize,
    },

    /// Key uses a deprecated or insecure algorithm
    DeprecatedKeyAlgorithm {
        /// The algorithm name
        algorithm: String,
        /// Why it's deprecated
        reason: String,
    },

    /// Key parameters are invalid or malformed
    InvalidKeyParameters {
        /// Description of the issue
        description: String,
    },

    // ========================================================================
    // Certificate Threats
    // ========================================================================
    /// Certificate has expired
    ExpiredCertificate {
        /// When the certificate expired
        expired_at: DateTime<Utc>,
    },

    /// Certificate is not yet valid
    NotYetValidCertificate {
        /// When the certificate becomes valid
        valid_from: DateTime<Utc>,
    },

    /// Certificate is self-signed (may be acceptable in some contexts)
    SelfSignedCertificate,

    /// Certificate uses weak signature algorithm
    WeakSignatureAlgorithm {
        /// The algorithm name
        algorithm: String,
        /// Why it's weak
        reason: String,
    },

    /// Certificate validity period is too long
    ExcessiveValidityPeriod {
        /// Validity period in days
        days: i64,
        /// Maximum recommended
        maximum: i64,
    },

    /// Certificate is about to expire
    CertificateExpiringSoon {
        /// Days until expiration
        days_remaining: i64,
        /// Threshold that triggered this warning
        threshold: i64,
    },

    // ========================================================================
    // Algorithm Threats
    // ========================================================================
    /// Insecure hash function used (MD5, SHA1)
    InsecureHashFunction {
        /// The hash function name
        algorithm: String,
    },

    /// Cryptographic nonce or IV is too short
    ShortNonce {
        /// Actual length in bytes
        length: usize,
        /// Minimum recommended length
        minimum: usize,
    },

    /// Algorithm is known to be broken
    BrokenAlgorithm {
        /// The algorithm name
        algorithm: String,
        /// CVE or reference if applicable
        reference: Option<String>,
    },

    // ========================================================================
    // Format/Structure Threats
    // ========================================================================
    /// PEM data contains multiple blocks of different types
    MixedPemBlocks {
        /// Labels found in the PEM data
        labels: Vec<String>,
    },

    /// Private key appears to be unencrypted
    UnencryptedPrivateKey,

    /// Key or certificate data is suspiciously large
    SuspiciouslyLargeData {
        /// Actual size in bytes
        size: usize,
        /// Threshold exceeded
        threshold: usize,
    },
}

impl CryptoThreat {
    /// Get a severity level for this threat
    ///
    /// Returns a value from 1-10, where 10 is most severe.
    pub fn severity(&self) -> u8 {
        match self {
            // Critical (8-10): Active security vulnerabilities
            Self::BrokenAlgorithm { .. } => 10,
            Self::InsecureHashFunction { algorithm } if algorithm == "MD5" => 9,
            Self::ExpiredCertificate { .. } => 8,

            // High (6-7): Significant security concerns
            Self::WeakRsaKeySize { bits, .. } if *bits < 1024 => 7,
            Self::WeakSignatureAlgorithm { .. } => 7,
            Self::InsecureHashFunction { .. } => 6,
            Self::UnencryptedPrivateKey => 6,

            // Medium (4-5): Policy violations, best practice issues
            Self::WeakRsaKeySize { .. } => 5,
            Self::WeakEcKeySize { .. } => 5,
            Self::DeprecatedKeyAlgorithm { .. } => 5,
            Self::NotYetValidCertificate { .. } => 4,
            Self::ExcessiveValidityPeriod { .. } => 4,
            Self::CertificateExpiringSoon { .. } => 4,
            Self::ShortNonce { .. } => 4,

            // Low (1-3): Informational, context-dependent
            Self::SelfSignedCertificate => 3,
            Self::MixedPemBlocks { .. } => 2,
            Self::InvalidKeyParameters { .. } => 3,
            Self::SuspiciouslyLargeData { .. } => 2,
        }
    }

    /// Check if this threat should block operations by default
    pub fn is_blocking(&self) -> bool {
        self.severity() >= 6
    }

    /// Get a human-readable description of this threat
    pub fn description(&self) -> String {
        match self {
            Self::WeakRsaKeySize { bits, minimum } => {
                format!("RSA key size ({bits} bits) is below minimum ({minimum} bits)")
            }
            Self::WeakEcKeySize { bits, minimum } => {
                format!("EC key size ({bits} bits) is below minimum ({minimum} bits)")
            }
            Self::DeprecatedKeyAlgorithm { algorithm, reason } => {
                format!("Algorithm '{algorithm}' is deprecated: {reason}")
            }
            Self::InvalidKeyParameters { description } => {
                format!("Invalid key parameters: {description}")
            }
            Self::ExpiredCertificate { expired_at } => {
                format!("Certificate expired on {expired_at}")
            }
            Self::NotYetValidCertificate { valid_from } => {
                format!("Certificate not valid until {valid_from}")
            }
            Self::SelfSignedCertificate => "Certificate is self-signed".to_string(),
            Self::WeakSignatureAlgorithm { algorithm, reason } => {
                format!("Weak signature algorithm '{algorithm}': {reason}")
            }
            Self::ExcessiveValidityPeriod { days, maximum } => {
                format!(
                    "Certificate validity period ({days} days) exceeds maximum ({maximum} days)"
                )
            }
            Self::CertificateExpiringSoon {
                days_remaining,
                threshold,
            } => {
                format!(
                    "Certificate expires in {days_remaining} days (threshold: {threshold} days)"
                )
            }
            Self::InsecureHashFunction { algorithm } => {
                format!("Insecure hash function: {algorithm}")
            }
            Self::ShortNonce { length, minimum } => {
                format!("Nonce length ({length} bytes) is below minimum ({minimum} bytes)")
            }
            Self::BrokenAlgorithm {
                algorithm,
                reference,
            } => {
                let ref_str = reference
                    .as_ref()
                    .map(|r| format!(" ({r})"))
                    .unwrap_or_default();
                format!("Broken algorithm: {algorithm}{ref_str}")
            }
            Self::MixedPemBlocks { labels } => {
                format!("PEM contains mixed block types: {}", labels.join(", "))
            }
            Self::UnencryptedPrivateKey => "Private key is not encrypted".to_string(),
            Self::SuspiciouslyLargeData { size, threshold } => {
                format!("Data size ({size} bytes) exceeds threshold ({threshold} bytes)")
            }
        }
    }
}

/// Policy configuration for cryptographic validation
///
/// Defines minimum requirements and allowed/disallowed practices.
#[derive(Debug, Clone)]
pub struct CryptoPolicy {
    // Key size requirements
    /// Minimum RSA key size in bits (default: 2048)
    pub min_rsa_bits: usize,
    /// Minimum EC key size in bits (default: 256)
    pub min_ec_bits: usize,

    // Algorithm policies
    /// Allow SHA-1 for signatures (default: false)
    pub allow_sha1_signatures: bool,
    /// Allow MD5 for any purpose (default: false)
    pub allow_md5: bool,

    // Certificate policies
    /// Allow self-signed certificates (default: false)
    pub allow_self_signed: bool,
    /// Require certificates to have valid dates (default: true)
    pub require_valid_dates: bool,
    /// Maximum certificate validity period in days (default: 825 = ~27 months)
    pub max_validity_days: i64,
    /// Days before expiry to warn (default: 30)
    pub expiry_warning_days: i64,

    // Data size limits
    /// Maximum certificate size in bytes (default: 1MB)
    pub max_cert_size: usize,
    /// Maximum key size in bytes (default: 100KB)
    pub max_key_size: usize,
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

impl CryptoPolicy {
    /// Standard policy following current NIST recommendations
    ///
    /// - RSA: 2048+ bits
    /// - EC: 256+ bits (P-256)
    /// - No SHA-1 or MD5
    /// - No self-signed certs
    /// - Max validity: 825 days
    pub fn standard() -> Self {
        Self {
            min_rsa_bits: 2048,
            min_ec_bits: 256,
            allow_sha1_signatures: false,
            allow_md5: false,
            allow_self_signed: false,
            require_valid_dates: true,
            max_validity_days: 825, // ~27 months (CA/Browser Forum standard)
            expiry_warning_days: 30,
            max_cert_size: 1_048_576, // 1 MB
            max_key_size: 102_400,    // 100 KB
        }
    }

    /// Strict policy for high-security environments
    ///
    /// - RSA: 3072+ bits
    /// - EC: 384+ bits (P-384)
    /// - No SHA-1 or MD5
    /// - No self-signed certs
    /// - Max validity: 398 days
    pub fn strict() -> Self {
        Self {
            min_rsa_bits: 3072,
            min_ec_bits: 384,
            allow_sha1_signatures: false,
            allow_md5: false,
            allow_self_signed: false,
            require_valid_dates: true,
            max_validity_days: 398, // ~13 months (stricter limit)
            expiry_warning_days: 60,
            max_cert_size: 524_288, // 512 KB
            max_key_size: 51_200,   // 50 KB
        }
    }

    /// Legacy policy for backwards compatibility
    ///
    /// WARNING: Only use when interacting with legacy systems.
    ///
    /// - RSA: 1024+ bits (weak!)
    /// - EC: 224+ bits
    /// - SHA-1 allowed
    /// - Self-signed allowed
    pub fn legacy() -> Self {
        Self {
            min_rsa_bits: 1024, // Weak but sometimes required for legacy
            min_ec_bits: 224,
            allow_sha1_signatures: true,
            allow_md5: false, // MD5 is never acceptable
            allow_self_signed: true,
            require_valid_dates: true,
            max_validity_days: 3650, // 10 years
            expiry_warning_days: 90,
            max_cert_size: 2_097_152, // 2 MB
            max_key_size: 204_800,    // 200 KB
        }
    }

    /// Development policy for testing
    ///
    /// WARNING: Never use in production!
    ///
    /// Very permissive settings for development and testing.
    pub fn development() -> Self {
        Self {
            min_rsa_bits: 1024,
            min_ec_bits: 192,
            allow_sha1_signatures: true,
            allow_md5: true,
            allow_self_signed: true,
            require_valid_dates: false,
            max_validity_days: 36500,  // 100 years
            expiry_warning_days: 0,    // No warnings
            max_cert_size: 10_485_760, // 10 MB
            max_key_size: 1_048_576,   // 1 MB
        }
    }

    // Builder methods for customization

    /// Set minimum RSA key size
    pub fn with_min_rsa_bits(mut self, bits: usize) -> Self {
        self.min_rsa_bits = bits;
        self
    }

    /// Set minimum EC key size
    pub fn with_min_ec_bits(mut self, bits: usize) -> Self {
        self.min_ec_bits = bits;
        self
    }

    /// Allow or disallow self-signed certificates
    pub fn with_allow_self_signed(mut self, allow: bool) -> Self {
        self.allow_self_signed = allow;
        self
    }

    /// Set expiry warning threshold
    pub fn with_expiry_warning_days(mut self, days: i64) -> Self {
        self.expiry_warning_days = days;
        self
    }
}

/// Result of a crypto security audit
#[derive(Debug, Clone, Default)]
pub struct CryptoAuditResult {
    /// Threats found during audit
    pub threats: Vec<CryptoThreat>,
    /// Whether any blocking threats were found
    pub has_blocking_threats: bool,
    /// Maximum severity level found
    pub max_severity: u8,
}

impl CryptoAuditResult {
    /// Create a new empty audit result
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a threat to the audit result
    pub fn add_threat(&mut self, threat: CryptoThreat) {
        let severity = threat.severity();
        if threat.is_blocking() {
            self.has_blocking_threats = true;
        }
        if severity > self.max_severity {
            self.max_severity = severity;
        }
        self.threats.push(threat);
    }

    /// Check if the audit passed (no blocking threats)
    pub fn passed(&self) -> bool {
        !self.has_blocking_threats
    }

    /// Get all blocking threats
    pub fn blocking_threats(&self) -> Vec<&CryptoThreat> {
        self.threats.iter().filter(|t| t.is_blocking()).collect()
    }

    /// Get all warning-level threats
    pub fn warnings(&self) -> Vec<&CryptoThreat> {
        self.threats.iter().filter(|t| !t.is_blocking()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_severity() {
        let critical = CryptoThreat::BrokenAlgorithm {
            algorithm: "DES".to_string(),
            reference: None,
        };
        assert_eq!(critical.severity(), 10);
        assert!(critical.is_blocking());

        let warning = CryptoThreat::SelfSignedCertificate;
        assert_eq!(warning.severity(), 3);
        assert!(!warning.is_blocking());
    }

    #[test]
    fn test_policy_presets() {
        let standard = CryptoPolicy::standard();
        assert_eq!(standard.min_rsa_bits, 2048);
        assert!(!standard.allow_sha1_signatures);

        let strict = CryptoPolicy::strict();
        assert_eq!(strict.min_rsa_bits, 3072);

        let legacy = CryptoPolicy::legacy();
        assert_eq!(legacy.min_rsa_bits, 1024);
        assert!(legacy.allow_sha1_signatures);
    }

    #[test]
    fn test_audit_result() {
        let mut result = CryptoAuditResult::new();
        assert!(result.passed());

        result.add_threat(CryptoThreat::SelfSignedCertificate);
        assert!(result.passed()); // Not blocking

        result.add_threat(CryptoThreat::ExpiredCertificate {
            expired_at: Utc::now(),
        });
        assert!(!result.passed()); // Blocking
        assert_eq!(result.blocking_threats().len(), 1);
    }
}

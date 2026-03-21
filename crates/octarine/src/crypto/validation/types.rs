//! Crypto validation types
//!
//! High-level types for crypto validation results.

use crate::primitives::identifiers::crypto::{KeyFormat, KeyType, SignatureAlgorithm};
use crate::primitives::security::crypto::{CryptoAuditResult, CryptoThreat};

#[cfg(feature = "crypto-validation")]
use crate::primitives::data::crypto::{ParsedCertificate, ParsedPublicKey, ParsedSshPublicKey};
#[cfg(feature = "crypto-validation")]
use chrono::{DateTime, Utc};

/// A validated public key with security metadata
#[cfg(feature = "crypto-validation")]
#[derive(Debug, Clone)]
pub struct ValidatedKey {
    /// The key type detected
    pub key_type: KeyType,
    /// The format the key was parsed from
    pub format: KeyFormat,
    /// Raw key bytes
    pub raw_bytes: Vec<u8>,
    /// Non-blocking warnings found during validation
    pub warnings: Vec<CryptoThreat>,
}

#[cfg(feature = "crypto-validation")]
impl ValidatedKey {
    /// Create from a parsed public key with audit results
    pub fn from_parsed(key: ParsedPublicKey, audit: CryptoAuditResult) -> Self {
        Self {
            key_type: key.key_type,
            format: key.source_format,
            raw_bytes: key.raw_bytes,
            warnings: audit.warnings().into_iter().cloned().collect(),
        }
    }

    /// Check if there were any warnings
    pub fn is_warning_present(&self) -> bool {
        !self.warnings.is_empty()
    }
}

/// A validated SSH key with security metadata
#[cfg(feature = "crypto-validation")]
#[derive(Debug, Clone)]
pub struct ValidatedSshKey {
    /// The key type detected
    pub key_type: KeyType,
    /// Algorithm string from SSH format
    pub algorithm: String,
    /// Key data bytes
    pub key_data: Vec<u8>,
    /// Optional comment
    pub comment: Option<String>,
    /// SHA-256 fingerprint
    pub fingerprint: String,
    /// Non-blocking warnings
    pub warnings: Vec<CryptoThreat>,
}

#[cfg(feature = "crypto-validation")]
impl ValidatedSshKey {
    /// Create from parsed SSH key with audit results and fingerprint
    pub fn from_parsed(
        key: ParsedSshPublicKey,
        audit: CryptoAuditResult,
        fingerprint: String,
    ) -> Self {
        Self {
            key_type: key.key_type,
            algorithm: key.algorithm,
            key_data: key.key_data,
            comment: key.comment,
            fingerprint,
            warnings: audit.warnings().into_iter().cloned().collect(),
        }
    }
}

/// A validated certificate with security metadata
#[cfg(feature = "crypto-validation")]
#[derive(Debug, Clone)]
pub struct ValidatedCertificate {
    /// Certificate version (1, 2, or 3)
    pub version: u8,
    /// Serial number as hex string
    pub serial_number: String,
    /// Subject distinguished name
    pub subject: String,
    /// Issuer distinguished name
    pub issuer: String,
    /// Valid from date
    pub not_before: DateTime<Utc>,
    /// Valid until date
    pub not_after: DateTime<Utc>,
    /// Public key type
    pub public_key_type: KeyType,
    /// Signature algorithm used
    pub signature_algorithm: SignatureAlgorithm,
    /// Whether this is a CA certificate
    pub is_ca: bool,
    /// Whether the certificate is self-signed
    pub is_self_signed: bool,
    /// Days until expiration
    pub days_until_expiry: i64,
    /// Non-blocking warnings
    pub warnings: Vec<CryptoThreat>,
}

#[cfg(feature = "crypto-validation")]
impl ValidatedCertificate {
    /// Create from parsed certificate with audit results
    pub fn from_parsed(cert: ParsedCertificate, audit: CryptoAuditResult) -> Self {
        Self {
            version: cert.version,
            serial_number: cert.serial_number.clone(),
            subject: cert.subject.clone(),
            issuer: cert.issuer.clone(),
            not_before: cert.not_before,
            not_after: cert.not_after,
            public_key_type: cert.public_key_type,
            signature_algorithm: cert.signature_algorithm,
            is_ca: cert.is_ca,
            is_self_signed: cert.is_self_signed,
            days_until_expiry: cert.days_until_expiry(),
            warnings: audit.warnings().into_iter().cloned().collect(),
        }
    }

    /// Check if certificate is expiring soon
    pub fn is_expiring_soon(&self, days: i64) -> bool {
        self.days_until_expiry > 0 && self.days_until_expiry <= days
    }
}

/// Summary result for quick validation checks
#[derive(Debug, Clone)]
pub struct ValidationSummary {
    /// Whether validation passed (no blocking threats)
    pub passed: bool,
    /// Number of blocking threats
    pub blocking_count: usize,
    /// Number of warnings
    pub warning_count: usize,
    /// Maximum severity level found
    pub max_severity: u8,
    /// Brief description of issues
    pub issues: Vec<String>,
}

impl ValidationSummary {
    /// Create from audit result
    pub fn from_audit(audit: &CryptoAuditResult) -> Self {
        Self {
            passed: audit.passed(),
            blocking_count: audit.blocking_threats().len(),
            warning_count: audit.warnings().len(),
            max_severity: audit.max_severity,
            issues: audit.threats.iter().map(|t| t.description()).collect(),
        }
    }
}

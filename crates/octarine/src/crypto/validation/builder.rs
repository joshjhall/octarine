//! Crypto validation builder
//!
//! Unified API for crypto validation that combines all three concerns:
//! - CLASSIFICATION (identifiers)
//! - FORMAT (data parsing)
//! - THREATS (security)
//!
//! # Observability
//!
//! All validation methods are instrumented with:
//! - **Timing metrics**: Duration of each validation operation
//! - **Counter metrics**: Validated items, blocked threats, warnings
//! - **Events**: Security-relevant logging for audit trails
//!
//! Use `.silent()` or `.with_events(false)` to disable event logging
//! while still recording metrics.

use std::time::Instant;

use crate::observe;
use crate::observe::Problem;
use crate::observe::ProblemExt;
use crate::observe::metrics::{increment_by, record};
use crate::primitives::identifiers::crypto::{KeyFormat, KeyType, SignatureAlgorithm};
use crate::primitives::security::crypto::{CryptoAuditResult, CryptoPolicy, CryptoSecurityBuilder};

crate::define_metrics! {
    validate_cert_ms => "crypto.validation.validate_cert_ms",
    validate_ssh_ms => "crypto.validation.ssh_key_ms",
    audit_ms => "crypto.validation.audit_ms",
    validated_count => "crypto.validation.validated",
    threats_blocked => "crypto.validation.threats_blocked",
    warnings_count => "crypto.validation.warnings",
}

#[cfg(feature = "crypto-validation")]
use super::types::{ValidatedCertificate, ValidatedSshKey, ValidationSummary};
#[cfg(feature = "crypto-validation")]
use crate::primitives::data::crypto::CryptoDataBuilder;
#[cfg(feature = "crypto-validation")]
use crate::primitives::identifiers::crypto::CryptoIdentifierBuilder;

/// Unified crypto validation builder
///
/// Combines all three crypto validation concerns:
/// - **Classification** (identifiers): What type of key/cert is this?
/// - **Format** (data): Can I parse it correctly?
/// - **Threats** (security): Is it dangerous?
///
/// # Example
///
/// Pre-existing example - ignored at compile until adapted.
/// ```ignore
/// use octarine::crypto::validation::{CryptoValidationBuilder, CryptoPolicy};
///
/// let validator = CryptoValidationBuilder::new();
///
/// // Validate PEM certificate data
/// let cert = validator.validate_certificate_pem(pem_data)?;
/// println!("Subject: {}", cert.subject);
/// println!("Expires in {} days", cert.days_until_expiry);
///
/// // Validate SSH key
/// let ssh_key = validator.validate_ssh_key(ssh_data)?;
/// println!("Fingerprint: {}", ssh_key.fingerprint);
///
/// // Use strict policy for high-security environments
/// let strict = CryptoValidationBuilder::strict();
/// let result = strict.audit_certificate_pem(pem_data);
/// if !result.passed() {
///     for threat in result.blocking_threats() {
///         eprintln!("BLOCKED: {}", threat.description());
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CryptoValidationBuilder {
    security: CryptoSecurityBuilder,
    #[cfg(feature = "crypto-validation")]
    data: CryptoDataBuilder,
    #[cfg(feature = "crypto-validation")]
    identifiers: CryptoIdentifierBuilder,
    /// Whether to emit events (logging). Metrics are always recorded.
    emit_events: bool,
}

impl Default for CryptoValidationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoValidationBuilder {
    /// Create a new validation builder with standard policy
    pub fn new() -> Self {
        Self {
            security: CryptoSecurityBuilder::new(),
            #[cfg(feature = "crypto-validation")]
            data: CryptoDataBuilder::new(),
            #[cfg(feature = "crypto-validation")]
            identifiers: CryptoIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a silent builder (no event logging, but metrics are still recorded)
    ///
    /// Use this for batch operations or internal validation where logging
    /// would be too noisy.
    pub fn silent() -> Self {
        Self {
            security: CryptoSecurityBuilder::new(),
            #[cfg(feature = "crypto-validation")]
            data: CryptoDataBuilder::new(),
            #[cfg(feature = "crypto-validation")]
            identifiers: CryptoIdentifierBuilder::new(),
            emit_events: false,
        }
    }

    /// Create with a specific security policy
    pub fn with_policy(policy: CryptoPolicy) -> Self {
        Self {
            security: CryptoSecurityBuilder::with_policy(policy),
            #[cfg(feature = "crypto-validation")]
            data: CryptoDataBuilder::new(),
            #[cfg(feature = "crypto-validation")]
            identifiers: CryptoIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create with strict security policy
    pub fn strict() -> Self {
        Self {
            security: CryptoSecurityBuilder::strict(),
            #[cfg(feature = "crypto-validation")]
            data: CryptoDataBuilder::new(),
            #[cfg(feature = "crypto-validation")]
            identifiers: CryptoIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create with legacy security policy
    pub fn legacy() -> Self {
        Self {
            security: CryptoSecurityBuilder::legacy(),
            #[cfg(feature = "crypto-validation")]
            data: CryptoDataBuilder::new(),
            #[cfg(feature = "crypto-validation")]
            identifiers: CryptoIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create with development policy (permissive, for testing)
    pub fn development() -> Self {
        Self {
            security: CryptoSecurityBuilder::development(),
            #[cfg(feature = "crypto-validation")]
            data: CryptoDataBuilder::new(),
            #[cfg(feature = "crypto-validation")]
            identifiers: CryptoIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Enable or disable event logging
    ///
    /// Metrics are always recorded regardless of this setting.
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    /// Get the current security policy
    pub fn policy(&self) -> &CryptoPolicy {
        self.security.policy()
    }

    // ========================================================================
    // Certificate Validation
    // ========================================================================

    /// Validate a PEM-encoded certificate
    ///
    /// Parses the certificate, checks for security threats, and returns
    /// a validated certificate with any non-blocking warnings.
    ///
    /// # Arguments
    /// * `pem_data` - PEM-encoded certificate string
    ///
    /// # Returns
    /// Validated certificate or error if parsing fails or blocking threats found
    ///
    /// # Metrics
    /// - `crypto.validation.validate_cert_ms` - Validation duration
    /// - `crypto.validation.validated` - Incremented on success
    /// - `crypto.validation.threats_blocked` - Count of blocking threats
    /// - `crypto.validation.warnings` - Count of warnings
    #[cfg(feature = "crypto-validation")]
    pub fn validate_certificate_pem(
        &self,
        pem_data: &str,
    ) -> Result<ValidatedCertificate, Problem> {
        let start = Instant::now();

        // 1. Parse the certificate
        let cert = self.data.parse_certificate_pem(pem_data)?;

        // 2. Check for security threats
        let audit = self.security.audit_certificate(&cert);

        // 3. Record timing metric (always)
        let elapsed_ms = start.elapsed().as_micros() as f64 / 1000.0;
        record(metric_names::validate_cert_ms(), elapsed_ms);

        // 4. Handle blocking threats
        if !audit.passed() {
            let threat_count = audit.blocking_threats().len();
            increment_by(metric_names::threats_blocked(), threat_count as u64);

            if self.emit_events {
                observe::warn(
                    "crypto_validation_failed",
                    format!("Certificate validation failed with {threat_count} blocking threats",),
                );
            }
            return Err(Problem::validation(format!(
                "Certificate has {threat_count} security issues",
            )));
        }

        // 5. Record success and any warnings
        increment_by(metric_names::validated_count(), 1);

        if !audit.warnings().is_empty() {
            let warning_count = audit.warnings().len();
            increment_by(metric_names::warnings_count(), warning_count as u64);

            if self.emit_events {
                observe::info(
                    "crypto_validation_warning",
                    format!("Certificate validated with {warning_count} warnings"),
                );
            }
        }

        Ok(ValidatedCertificate::from_parsed(cert, audit))
    }

    /// Validate a DER-encoded certificate
    ///
    /// # Metrics
    /// - `crypto.validation.validate_cert_ms` - Validation duration
    /// - `crypto.validation.validated` - Incremented on success
    /// - `crypto.validation.threats_blocked` - Count of blocking threats
    #[cfg(feature = "crypto-validation")]
    pub fn validate_certificate_der(
        &self,
        der_data: &[u8],
    ) -> Result<ValidatedCertificate, Problem> {
        let start = Instant::now();

        let cert = self.data.parse_certificate_der(der_data)?;
        let audit = self.security.audit_certificate(&cert);

        // Record timing
        let elapsed_ms = start.elapsed().as_micros() as f64 / 1000.0;
        record(metric_names::validate_cert_ms(), elapsed_ms);

        if !audit.passed() {
            let threat_count = audit.blocking_threats().len();
            increment_by(metric_names::threats_blocked(), threat_count as u64);

            if self.emit_events {
                observe::warn(
                    "crypto_validation_failed",
                    format!("DER certificate validation failed with {threat_count} threats",),
                );
            }
            return Err(Problem::validation(format!(
                "Certificate has {threat_count} security issues",
            )));
        }

        increment_by(metric_names::validated_count(), 1);
        Ok(ValidatedCertificate::from_parsed(cert, audit))
    }

    /// Audit a PEM certificate without failing on threats
    ///
    /// Returns full audit results instead of failing. Use this when you
    /// want to inspect all issues before deciding how to proceed.
    ///
    /// # Metrics
    /// - `crypto.validation.audit_ms` - Audit duration
    #[cfg(feature = "crypto-validation")]
    pub fn audit_certificate_pem(&self, pem_data: &str) -> Result<CryptoAuditResult, Problem> {
        let start = Instant::now();

        let cert = self.data.parse_certificate_pem(pem_data)?;
        let audit = self.security.audit_certificate(&cert);

        // Record timing
        let elapsed_ms = start.elapsed().as_micros() as f64 / 1000.0;
        record(metric_names::audit_ms(), elapsed_ms);

        if self.emit_events {
            observe::info(
                "crypto_audit",
                format!(
                    "Certificate audit completed with {} threats, max severity {}",
                    audit.threats.len(),
                    audit.max_severity
                ),
            );
        }

        Ok(audit)
    }

    // ========================================================================
    // SSH Key Validation
    // ========================================================================

    /// Validate an SSH public key
    ///
    /// Parses the SSH key, checks for security threats, and returns
    /// a validated key with fingerprint and any warnings.
    ///
    /// # Metrics
    /// - `crypto.validation.ssh_key_ms` - Validation duration
    /// - `crypto.validation.validated` - Incremented on success
    /// - `crypto.validation.threats_blocked` - Count of blocking threats
    /// - `crypto.validation.warnings` - Count of warnings
    #[cfg(feature = "crypto-validation")]
    pub fn validate_ssh_key(&self, ssh_data: &str) -> Result<ValidatedSshKey, Problem> {
        let start = Instant::now();

        // 1. Parse the SSH key
        let key = self.data.parse_ssh_public_key(ssh_data)?;

        // 2. Get fingerprint
        let fingerprint = self.data.ssh_key_fingerprint(ssh_data)?;

        // 3. Check for security threats
        let audit = self.security.audit_ssh_key(&key);

        // 4. Record timing
        let elapsed_ms = start.elapsed().as_micros() as f64 / 1000.0;
        record(metric_names::validate_ssh_ms(), elapsed_ms);

        // 5. Handle blocking threats
        if !audit.passed() {
            let threat_count = audit.blocking_threats().len();
            increment_by(metric_names::threats_blocked(), threat_count as u64);

            if self.emit_events {
                observe::warn(
                    "crypto_validation_failed",
                    format!("SSH key validation failed with {threat_count} threats"),
                );
            }
            return Err(Problem::validation(format!(
                "SSH key has {threat_count} security issues",
            )));
        }

        // 6. Record success and warnings
        increment_by(metric_names::validated_count(), 1);

        if !audit.warnings().is_empty() {
            let warning_count = audit.warnings().len();
            increment_by(metric_names::warnings_count(), warning_count as u64);
        }

        Ok(ValidatedSshKey::from_parsed(key, audit, fingerprint))
    }

    /// Audit an SSH key without failing on threats
    ///
    /// # Metrics
    /// - `crypto.validation.audit_ms` - Audit duration
    #[cfg(feature = "crypto-validation")]
    pub fn audit_ssh_key(&self, ssh_data: &str) -> Result<CryptoAuditResult, Problem> {
        let start = Instant::now();

        let key = self.data.parse_ssh_public_key(ssh_data)?;
        let audit = self.security.audit_ssh_key(&key);

        // Record timing
        let elapsed_ms = start.elapsed().as_micros() as f64 / 1000.0;
        record(metric_names::audit_ms(), elapsed_ms);

        if self.emit_events {
            observe::info(
                "crypto_audit",
                format!(
                    "SSH key audit completed with {} threats",
                    audit.threats.len()
                ),
            );
        }

        Ok(audit)
    }

    // ========================================================================
    // PEM Validation
    // ========================================================================

    /// Validate PEM format (any type)
    ///
    /// Validates that data is properly PEM formatted without
    /// checking the specific content type.
    #[cfg(feature = "crypto-validation")]
    pub fn validate_pem_format(&self, pem_data: &str) -> Result<(), Problem> {
        self.data.validate_pem_format(pem_data)?;

        increment_by(metric_names::validated_count(), 1);

        if self.emit_events {
            observe::info("crypto_validation", "PEM format validated");
        }
        Ok(())
    }

    // ========================================================================
    // Quick Checks (No Parsing)
    // ========================================================================

    /// Check if a key type is weak under current policy
    pub fn is_weak_key(&self, key_type: &KeyType) -> bool {
        self.security.is_weak_key(key_type)
    }

    /// Check if a signature algorithm is deprecated
    pub fn is_deprecated_algorithm(&self, algo: &SignatureAlgorithm) -> bool {
        self.security.is_deprecated_algorithm(algo)
    }

    /// Check if a hash algorithm is insecure
    pub fn is_insecure_hash(&self, algorithm: &str) -> bool {
        self.security.is_insecure_hash(algorithm)
    }

    /// Validate a key type against current policy
    pub fn validate_key_strength(&self, key_type: &KeyType) -> Result<(), Problem> {
        self.security.validate_key_strength(key_type)
    }

    /// Validate a signature algorithm
    pub fn validate_signature_algorithm(&self, algo: &SignatureAlgorithm) -> Result<(), Problem> {
        self.security.validate_signature_algorithm(algo)
    }

    /// Validate a hash algorithm
    pub fn validate_hash_algorithm(&self, algorithm: &str) -> Result<(), Problem> {
        self.security.validate_hash_algorithm(algorithm)
    }

    // ========================================================================
    // Format Detection
    // ========================================================================

    /// Detect the format of crypto data from a string
    #[cfg(feature = "crypto-validation")]
    pub fn detect_format(&self, data: &str) -> KeyFormat {
        self.identifiers.detect_key_format(data)
    }

    /// Check if data looks like PEM format
    #[cfg(feature = "crypto-validation")]
    pub fn is_pem_format(&self, data: &str) -> bool {
        self.identifiers.is_pem_format(data)
    }

    /// Check if data looks like SSH key format
    #[cfg(feature = "crypto-validation")]
    pub fn is_ssh_key_format(&self, data: &str) -> bool {
        self.identifiers.is_ssh_key_format(data)
    }

    // ========================================================================
    // Validation Summary
    // ========================================================================

    /// Get a summary of certificate validation
    #[cfg(feature = "crypto-validation")]
    pub fn summarize_certificate(&self, pem_data: &str) -> Result<ValidationSummary, Problem> {
        let audit = self.audit_certificate_pem(pem_data)?;
        Ok(ValidationSummary::from_audit(&audit))
    }

    /// Get a summary of SSH key validation
    #[cfg(feature = "crypto-validation")]
    pub fn summarize_ssh_key(&self, ssh_data: &str) -> Result<ValidationSummary, Problem> {
        let audit = self.audit_ssh_key(ssh_data)?;
        Ok(ValidationSummary::from_audit(&audit))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let _standard = CryptoValidationBuilder::new();
        let _strict = CryptoValidationBuilder::strict();
        let _legacy = CryptoValidationBuilder::legacy();
        let _dev = CryptoValidationBuilder::development();
    }

    #[test]
    fn test_quick_checks() {
        let builder = CryptoValidationBuilder::strict();

        // RSA 2048 is weak under strict policy
        assert!(builder.is_weak_key(&KeyType::Rsa2048));

        // RSA 4096 is fine
        assert!(!builder.is_weak_key(&KeyType::Rsa4096));

        // Check deprecated algorithms
        assert!(builder.is_deprecated_algorithm(&SignatureAlgorithm::RsaPkcs1Md5));
        assert!(!builder.is_deprecated_algorithm(&SignatureAlgorithm::RsaPkcs1Sha256));

        // Check insecure hashes
        assert!(builder.is_insecure_hash("MD5"));
        assert!(!builder.is_insecure_hash("SHA-256"));
    }

    #[test]
    fn test_validation() {
        let builder = CryptoValidationBuilder::new();

        // Should pass for strong key
        assert!(builder.validate_key_strength(&KeyType::Rsa4096).is_ok());

        // Should fail for weak signature
        assert!(
            builder
                .validate_signature_algorithm(&SignatureAlgorithm::RsaPkcs1Md5)
                .is_err()
        );
    }

    // ========================================================================
    // Integration Tests with Real Crypto Data
    // ========================================================================

    // Sample Ed25519 SSH public key for testing
    #[cfg(feature = "crypto-validation")]
    const SAMPLE_ED25519_SSH_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example";

    // Sample RSA SSH public key for testing
    #[cfg(feature = "crypto-validation")]
    const SAMPLE_RSA_SSH_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUd3 user@host";

    // Sample PEM-encoded RSA public key (fake content - tests only check format)
    #[cfg(feature = "crypto-validation")]
    const SAMPLE_RSA_PEM: &str = r#"-----BEGIN RSA PUBLIC KEY-----
FAKE_TEST_DATA_NOT_A_REAL_RSA_KEY
-----END RSA PUBLIC KEY-----"#;

    // Sample PEM-encoded certificate (fake content - tests only check format)
    #[cfg(feature = "crypto-validation")]
    const SAMPLE_CERTIFICATE_PEM: &str = r#"-----BEGIN CERTIFICATE-----
FAKE_TEST_DATA_NOT_A_REAL_CERTIFICATE
-----END CERTIFICATE-----"#;

    // A real, parseable RSA certificate (shared with the x509 primitive
    // tests). The local SAMPLE_CERTIFICATE_PEM is deliberately fake and
    // cannot be parsed, so it cannot exercise the validate/audit paths.
    #[cfg(feature = "crypto-validation")]
    const PARSEABLE_RSA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDoTCCAomgAwIBAgIUIBqYDTwPs0w1FbKM9mMOE7PJUoYwDQYJKoZIhvcNAQEL
BQAwODEWMBQGA1UEAwwNb2N0YXJpbmUudGVzdDERMA8GA1UECgwIT2N0YXJpbmUx
CzAJBgNVBAYTAlVTMB4XDTI2MDcwMzE3MDQ1NFoXDTM2MDYzMDE3MDQ1NFowODEW
MBQGA1UEAwwNb2N0YXJpbmUudGVzdDERMA8GA1UECgwIT2N0YXJpbmUxCzAJBgNV
BAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmrg8ir1LmYXF
TjrgU3U7xXa8U25MWcVM17Af0IG3jPPpriGs/IClbYHOi/gHCfJFnU23q1+FVDUW
whaDnymCBWvrcCu0eYMMleF/P/dwOYbjII+9JuTTermGFCT2k3ccwYRFJvXjsfcP
U/Tfq9Rq3yu5mOW014FGf5CCYhG1W9bosJPSfh0GWBDGi9Ohdaw+tlRdvU+pNWSk
IXLGe1rXCU1u3u7cK4/mHSOksW2k1Iz483B5xGX5ifKX6x2XqRtzooP45et6TLWr
qkaUIwPkX4dXpJ4JKM3G4ZeMDPXPm8lhUKUXL4TfNALMNs7nPM+0Aqfd2roRUWg3
TI2uwB1seQIDAQABo4GiMIGfMB0GA1UdDgQWBBRxWIHTY+24T212hsxG8kRS0A4a
wjAfBgNVHSMEGDAWgBRxWIHTY+24T212hsxG8kRS0A4awjA/BgNVHREEODA2gg1v
Y3RhcmluZS50ZXN0ghF3d3cub2N0YXJpbmUudGVzdIESdGVzdEBvY3RhcmluZS50
ZXN0MAsGA1UdDwQEAwIChDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQAxCxOT/4l3/e9LspAEXohIWzGd03m/7eHCtqKwRBbTxtLQR6uXxJcTw+ou
FhjoJXM0NpuoEX67kYPhK/xlGdSA38erqPIvfRCvWSz0PkvVnGU3wICQYijr61gX
NqkABZp7la/v+Ri4Z0mA6e8Jjn+3y9/kSHAlPVtB2M6LpD+9TRXbY017fzMob95r
TgJHncR9NUia7FyIlgFQD2mAviwTKXo62jwClR/4UbMDyW7WDB7RYsJtlD1ljV5Y
s65IEVG6SQCLEcR2Or1dlnSJEs1Yd2lh/Mm8okWlW+ku4i3Y1VFzlXPchg0qQZ1+
LMkl8mNtd2MbHD07VEPVzgaZQaEg
-----END CERTIFICATE-----";

    #[test]
    #[cfg(feature = "crypto-validation")]
    fn test_certificate_paths_are_exercised() {
        // Locks in the event:: -> observe:: migration on the certificate
        // PEM/DER paths: previously nothing called them, so a reverted or
        // malformed observe:: call there would not have been caught.
        let builder = CryptoValidationBuilder::new();

        // PEM: parseable input reaches the audit + event code.
        let audit = builder
            .audit_certificate_pem(PARSEABLE_RSA_CERT_PEM)
            .expect("a real certificate must parse and audit");
        // Every threat the audit reports must be populated: an empty
        // description would mean the audit produced placeholder entries
        // rather than real findings.
        assert!(
            audit.threats.iter().all(|t| !t.description().is_empty()),
            "audited threats must carry descriptions",
        );
        // The threat list must agree with the pass/warning verdict, so a
        // corrupted threats vec cannot slip through unnoticed.
        assert_eq!(
            audit.threats.is_empty(),
            audit.passed() && audit.warnings().is_empty(),
            "the threat list must agree with passed()/warnings()",
        );

        // validate_certificate_pem walks the same code, and either validates
        // or fails on a blocking threat -- never panics.
        let _ = builder.validate_certificate_pem(PARSEABLE_RSA_CERT_PEM);

        // DER: unparseable bytes must surface an error, not panic, and must
        // not be mistaken for a valid certificate.
        assert!(
            builder
                .validate_certificate_der(b"not-a-der-certificate")
                .is_err(),
            "garbage DER must fail to parse",
        );

        // The fake PEM fixture must NOT parse, confirming the assertions above
        // depend on real certificate data.
        assert!(
            builder
                .audit_certificate_pem(SAMPLE_CERTIFICATE_PEM)
                .is_err(),
            "the fake fixture must not parse",
        );
    }

    #[test]
    #[cfg(feature = "crypto-validation")]
    fn test_format_detection_integration() {
        let builder = CryptoValidationBuilder::new();

        // PEM format detection
        assert!(builder.is_pem_format(SAMPLE_RSA_PEM));
        assert!(builder.is_pem_format(SAMPLE_CERTIFICATE_PEM));
        assert!(!builder.is_pem_format(SAMPLE_ED25519_SSH_KEY));
        assert!(!builder.is_pem_format("random data"));

        // SSH format detection
        assert!(builder.is_ssh_key_format(SAMPLE_ED25519_SSH_KEY));
        assert!(builder.is_ssh_key_format(SAMPLE_RSA_SSH_KEY));
        assert!(!builder.is_ssh_key_format(SAMPLE_RSA_PEM));
        assert!(!builder.is_ssh_key_format("not a key"));
    }

    #[test]
    #[cfg(feature = "crypto-validation")]
    fn test_validate_ssh_key_integration() {
        let builder = CryptoValidationBuilder::new();

        // Ed25519 keys are always strong
        let result = builder.validate_ssh_key(SAMPLE_ED25519_SSH_KEY);
        assert!(result.is_ok(), "Ed25519 key should validate: {:?}", result);
        let validated = result.expect("should succeed");
        assert_eq!(validated.key_type, KeyType::SshEd25519);
        assert!(
            validated.warnings.is_empty(),
            "Ed25519 should have no warnings"
        );
    }

    #[test]
    #[cfg(feature = "crypto-validation")]
    fn test_audit_ssh_key_integration() {
        let builder = CryptoValidationBuilder::new();

        // Audit Ed25519 key
        let result = builder.audit_ssh_key(SAMPLE_ED25519_SSH_KEY);
        assert!(result.is_ok(), "Audit should succeed: {:?}", result);
        let audit = result.expect("should succeed");

        // Ed25519 is strong, should pass
        assert!(audit.passed(), "Ed25519 should pass audit");
        assert!(
            audit.blocking_threats().is_empty(),
            "No blocking threats expected"
        );
    }

    #[test]
    #[cfg(feature = "crypto-validation")]
    fn test_summarize_ssh_key_integration() {
        let builder = CryptoValidationBuilder::new();

        let result = builder.summarize_ssh_key(SAMPLE_ED25519_SSH_KEY);
        assert!(result.is_ok(), "Summary should succeed: {:?}", result);
        let summary = result.expect("should succeed");

        assert!(summary.passed, "Ed25519 should pass");
        assert_eq!(summary.blocking_count, 0);
    }

    #[test]
    #[cfg(feature = "crypto-validation")]
    fn test_strict_policy_flags_weak_keys() {
        let strict = CryptoValidationBuilder::strict();

        // Under strict policy, RSA 2048 is weak
        assert!(strict.is_weak_key(&KeyType::Rsa2048));

        // NOTE: SshRsa cannot be determined weak from type alone (size unknown)
        // Need parsed key to check actual size
        assert!(!strict.is_weak_key(&KeyType::SshRsa));

        // P-256 is weak under strict (requires 384-bit EC)
        assert!(strict.is_weak_key(&KeyType::P256));

        // But Ed25519 is always strong (256-bit security level)
        assert!(!strict.is_weak_key(&KeyType::Ed25519));
        assert!(!strict.is_weak_key(&KeyType::SshEd25519));

        // And RSA 4096 is strong
        assert!(!strict.is_weak_key(&KeyType::Rsa4096));
    }

    #[test]
    #[cfg(feature = "crypto-validation")]
    fn test_legacy_policy_allows_weak_keys() {
        let legacy = CryptoValidationBuilder::legacy();

        // Legacy policy allows RSA 1024+
        assert!(!legacy.is_weak_key(&KeyType::Rsa2048));

        // Legacy allows P-256
        assert!(!legacy.is_weak_key(&KeyType::P256));
    }
}

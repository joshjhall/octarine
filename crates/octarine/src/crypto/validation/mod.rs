//! Cryptographic input validation
//!
//! Unified API for validating cryptographic inputs including certificates,
//! keys, and algorithms. This module combines three orthogonal concerns:
//!
//! - **Classification** (identifiers): What type of crypto artifact is this?
//! - **Format** (data): Can the data be parsed correctly?
//! - **Threats** (security): Does it pose any security risks?
//!
//! # Quick Start
//!
//! ```ignore
//! use octarine::crypto::validation::{validate_certificate_pem, validate_ssh_key};
//!
//! // Validate a certificate
//! let cert = validate_certificate_pem(pem_data)?;
//! println!("Subject: {}", cert.subject);
//! println!("Expires in {} days", cert.days_until_expiry);
//!
//! // Validate an SSH key
//! let key = validate_ssh_key(ssh_data)?;
//! println!("Fingerprint: {}", key.fingerprint);
//! ```
//!
//! # Security Policies
//!
//! Three pre-configured security policies are available:
//!
//! | Policy | RSA Min | EC Min | SHA-1 | Self-Signed | Use Case |
//! |--------|---------|--------|-------|-------------|----------|
//! | `standard` | 2048 | 256 | No | No | Normal operations |
//! | `strict` | 3072 | 384 | No | No | High security |
//! | `legacy` | 1024 | 224 | Yes | Yes | Legacy systems |
//!
//! # Builder API
//!
//! For more control, use the `CryptoValidationBuilder`:
//!
//! ```ignore
//! use octarine::crypto::validation::{CryptoValidationBuilder, CryptoPolicy};
//!
//! // Strict validation
//! let validator = CryptoValidationBuilder::strict();
//!
//! // Custom policy
//! let custom_policy = CryptoPolicy::standard()
//!     .with_min_rsa_bits(3072)
//!     .with_allow_self_signed(true);
//! let validator = CryptoValidationBuilder::with_policy(custom_policy);
//!
//! // Audit without failing
//! let audit = validator.audit_certificate_pem(pem_data)?;
//! if !audit.passed() {
//!     for threat in audit.blocking_threats() {
//!         eprintln!("BLOCKED: {}", threat.description());
//!     }
//! }
//! ```
//!
//! # Quick Checks
//!
//! For simple yes/no checks without parsing:
//!
//! ```ignore
//! use octarine::crypto::validation::{
//!     is_strong_key, is_safe_signature_algorithm, is_secure_hash
//! };
//!
//! if !is_strong_key(&key_type) {
//!     warn!("Key does not meet strength requirements");
//! }
//!
//! if !is_secure_hash("MD5") {
//!     error!("MD5 is not a secure hash algorithm");
//! }
//! ```
//!
//! # Feature Flag
//!
//! Most functionality requires the `crypto-validation` feature:
//!
//! ```toml
//! [dependencies]
//! octarine = { version = "0.2", features = ["crypto-validation"] }
//! ```
//!
//! Basic algorithm checks work without the feature flag.

mod builder;
mod shortcuts;
mod types;

// Re-export builder
pub use builder::CryptoValidationBuilder;

// Re-export types
pub use types::ValidationSummary;

#[cfg(feature = "crypto-validation")]
pub use types::{ValidatedCertificate, ValidatedKey, ValidatedSshKey};

// Re-export policy from security primitives
pub use crate::primitives::security::crypto::{CryptoAuditResult, CryptoPolicy, CryptoThreat};

// Re-export key/algorithm types from identifiers primitives
pub use crate::primitives::identifiers::crypto::{KeyType, SignatureAlgorithm};

// Re-export shortcuts
pub use shortcuts::{
    is_safe_signature_algorithm, is_secure_hash, is_strong_key, is_strong_key_strict,
    legacy_policy, standard_policy, strict_policy, validate_hash_algorithm, validate_key_strength,
    validate_key_strength_strict, validate_signature_algorithm,
};

#[cfg(feature = "crypto-validation")]
pub use shortcuts::{
    audit_certificate_pem, audit_ssh_key, is_pem_format, is_ssh_key_format, summarize_certificate,
    summarize_ssh_key, validate_certificate_der, validate_certificate_pem, validate_pem_format,
    validate_ssh_key,
};

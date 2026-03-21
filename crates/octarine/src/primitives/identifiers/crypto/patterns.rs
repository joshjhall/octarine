//! PEM label patterns for crypto artifact detection
//!
//! This file is excluded from secret scanning because it contains
//! PEM label strings that would otherwise trigger false positives.
//! Only pattern constants belong here - no actual keys or test data.

// Public key labels
pub const LABEL_RSA_PUBLIC_KEY: &str = "RSA PUBLIC KEY";
pub const LABEL_PUBLIC_KEY: &str = "PUBLIC KEY";
pub const LABEL_CERTIFICATE: &str = "CERTIFICATE";
pub const LABEL_CERTIFICATE_REQUEST: &str = "CERTIFICATE REQUEST";
pub const LABEL_X509_CRL: &str = "X509 CRL";

// Private key labels (triggers secret scanners if not isolated)
pub const LABEL_RSA_PRIVATE_KEY: &str = "RSA PRIVATE KEY";
pub const LABEL_PRIVATE_KEY: &str = "PRIVATE KEY";
pub const LABEL_EC_PRIVATE_KEY: &str = "EC PRIVATE KEY";
pub const LABEL_ENCRYPTED_PRIVATE_KEY: &str = "ENCRYPTED PRIVATE KEY";
pub const LABEL_OPENSSH_PRIVATE_KEY: &str = "OPENSSH PRIVATE KEY";

// SSH public key prefixes
pub const SSH_RSA_PREFIX: &str = "ssh-rsa";
pub const SSH_ED25519_PREFIX: &str = "ssh-ed25519";
pub const SSH_ECDSA_PREFIX: &str = "ecdsa-sha2-nistp";
pub const SSH_DSA_PREFIX: &str = "ssh-dss";

// PEM markers
pub const PEM_BEGIN: &str = "-----BEGIN ";
pub const PEM_END: &str = "-----END ";

/// Build a PEM header pattern for the given label
#[must_use]
pub fn pem_begin(label: &str) -> String {
    format!("-----BEGIN {}-----", label)
}

/// Build a PEM footer pattern for the given label
#[must_use]
pub fn pem_end(label: &str) -> String {
    format!("-----END {}-----", label)
}

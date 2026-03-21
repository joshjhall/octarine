//! SSH key and fingerprint detection
//!
//! Pure detection functions for SSH public keys and fingerprints.

use super::super::super::common::patterns;

/// Maximum identifier length for single-value checks
const MAX_IDENTIFIER_LENGTH: usize = 1_000;

// ============================================================================
// Public API
// ============================================================================

/// Check if value is an SSH public key
///
/// Matches SSH public keys in formats: ssh-rsa, ssh-ed25519, ssh-ecdsa, ssh-dss
#[must_use]
pub fn is_ssh_public_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH * 10 {
        // SSH keys can be longer
        return false;
    }
    patterns::network::SSH_PUBLIC_KEY.is_match(trimmed)
}

/// Check if value is an SSH fingerprint (MD5 or SHA256 format)
///
/// Matches both MD5 (colon-separated hex) and SHA256 (base64) fingerprint formats
#[must_use]
pub fn is_ssh_fingerprint(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::SSH_FINGERPRINT_MD5.is_match(trimmed)
        || patterns::network::SSH_FINGERPRINT_SHA256.is_match(trimmed)
}

/// Check if value is an SSH private key
///
/// Matches private key formats: RSA, DSA, EC, OPENSSH, ENCRYPTED
#[must_use]
pub fn is_ssh_private_key(value: &str) -> bool {
    let trimmed = value.trim();
    // Private keys can be quite long
    if trimmed.len() > MAX_IDENTIFIER_LENGTH * 10 {
        return false;
    }
    patterns::network::SSH_PRIVATE_KEY_HEADER.is_match(trimmed)
}

/// Check if value is an SSH key or fingerprint
///
/// Convenience function that checks for public keys, private keys, and fingerprints
#[must_use]
pub fn is_ssh_key(value: &str) -> bool {
    is_ssh_public_key(value) || is_ssh_fingerprint(value) || is_ssh_private_key(value)
}

/// Check if SSH key or fingerprint is a known test/example
///
/// Detects:
/// - Keys with test/example comments
/// - Known example fingerprints from documentation
/// - Keys from test@, demo@, example@ addresses
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::detection::is_test_ssh_key;
///
/// assert!(is_test_ssh_key("ssh-rsa AAAAB3... test@example.com"));
/// assert!(is_test_ssh_key("ssh-ed25519 AAAAC3... demo@localhost"));
/// ```
#[must_use]
pub fn is_test_ssh_key(ssh_key: &str) -> bool {
    let trimmed = ssh_key.trim();
    let lower = trimmed.to_lowercase();

    // Check for test/example comments at end of SSH public key
    let test_comments = [
        "test@",
        "demo@",
        "example@",
        "fake@",
        "sample@",
        "@example.com",
        "@test.com",
        "@localhost",
        "@test",
        " test",
        " demo",
        " example",
        " fake",
        " sample",
    ];
    for comment in &test_comments {
        if lower.ends_with(comment) || lower.contains(comment) {
            return true;
        }
    }

    // Known example fingerprints from GitHub/documentation
    let example_fingerprints = [
        "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", // GitHub's fingerprint (used in docs)
    ];
    for fp in &example_fingerprints {
        if trimmed == *fp {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_ssh_public_key() {
        assert!(is_ssh_public_key(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8... user@host"
        ));
        assert!(is_ssh_public_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMq..."
        ));
        assert!(is_ssh_public_key(
            "ssh-ecdsa AAAAE2VjZHNhLXNoYTItbmlzdHA..."
        ));
        assert!(!is_ssh_public_key("not-an-ssh-key"));
        assert!(!is_ssh_public_key("rsa-ssh AAAAB3...")); // Wrong order
    }

    #[test]
    fn test_is_ssh_fingerprint() {
        // MD5 format
        assert!(is_ssh_fingerprint(
            "16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48"
        ));

        // SHA256 format
        assert!(is_ssh_fingerprint(
            "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"
        ));

        // Invalid
        assert!(!is_ssh_fingerprint("16:27:ac")); // Too short
        assert!(!is_ssh_fingerprint("not-a-fingerprint"));
    }

    #[test]
    fn test_is_ssh_key() {
        // Should match public keys
        assert!(is_ssh_key("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8..."));

        // Should match fingerprints
        assert!(is_ssh_key(
            "16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48"
        ));
        assert!(is_ssh_key(
            "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"
        ));

        // Should reject non-SSH content
        assert!(!is_ssh_key("not-an-ssh-key"));
    }

    #[test]
    fn test_is_test_ssh_key_comments() {
        // SSH keys with test comments
        assert!(is_test_ssh_key(
            "ssh-rsa AAAAB3NzaC1yc2E... test@example.com"
        ));
        assert!(is_test_ssh_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... demo@localhost"
        ));
        assert!(is_test_ssh_key("ssh-rsa AAAAB3... user@test.com"));
        assert!(is_test_ssh_key("ssh-ecdsa AAAAE2... example@host"));
    }

    #[test]
    fn test_is_test_ssh_key_fingerprint() {
        // GitHub's example fingerprint
        assert!(is_test_ssh_key(
            "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"
        ));
    }

    #[test]
    fn test_is_test_ssh_key_production() {
        // Production SSH keys should not be test
        assert!(!is_test_ssh_key(
            "ssh-rsa AAAAB3NzaC1yc2E... user@production.com"
        ));
        assert!(!is_test_ssh_key(
            "16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48"
        ));
    }

    #[test]
    fn test_is_ssh_private_key() {
        // RSA private key
        assert!(is_ssh_private_key("-----BEGIN RSA PRIVATE KEY-----"));
        // OpenSSH format
        assert!(is_ssh_private_key("-----BEGIN OPENSSH PRIVATE KEY-----"));
        // EC private key
        assert!(is_ssh_private_key("-----BEGIN EC PRIVATE KEY-----"));
        // DSA private key
        assert!(is_ssh_private_key("-----BEGIN DSA PRIVATE KEY-----"));
        // Encrypted private key
        assert!(is_ssh_private_key("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        // Generic private key
        assert!(is_ssh_private_key("-----BEGIN PRIVATE KEY-----"));

        // Should not match public keys or other PEM blocks
        assert!(!is_ssh_private_key("-----BEGIN PUBLIC KEY-----"));
        assert!(!is_ssh_private_key("-----BEGIN CERTIFICATE-----"));
        assert!(!is_ssh_private_key("ssh-rsa AAAAB3..."));
    }
}

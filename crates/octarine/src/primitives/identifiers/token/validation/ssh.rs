//! SSH key and fingerprint validation
//!
//! Pure validation functions for SSH public keys, private keys, and fingerprints.

use super::super::detection::{is_ssh_fingerprint, is_ssh_private_key, is_ssh_public_key};
use crate::primitives::Problem;

/// Validate SSH public key format
///
/// Checks that the value matches an SSH public key format (ssh-rsa, ssh-ed25519,
/// ssh-ecdsa, ssh-dss) with a base64-encoded key portion.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_ssh_public_key(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(Problem::Validation("SSH public key cannot be empty".into()));
    }

    if !is_ssh_public_key(trimmed) {
        return Err(Problem::Validation(
            "Invalid SSH public key format: expected ssh-rsa, ssh-ed25519, ssh-ecdsa, or ssh-dss prefix".into(),
        ));
    }

    // Verify key has at least a type and base64 portion
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(Problem::Validation(
            "SSH public key must have a key type and base64-encoded data".into(),
        ));
    }

    Ok(())
}

/// Validate SSH private key format
///
/// Checks that the value contains a valid PEM-encoded private key header.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_ssh_private_key(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "SSH private key cannot be empty".into(),
        ));
    }

    if !is_ssh_private_key(trimmed) {
        return Err(Problem::Validation(
            "Invalid SSH private key format: expected -----BEGIN * PRIVATE KEY----- header".into(),
        ));
    }

    Ok(())
}

/// Validate SSH fingerprint format
///
/// Checks for valid MD5 (colon-separated hex) or SHA256 (base64) fingerprint format.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_ssh_fingerprint(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "SSH fingerprint cannot be empty".into(),
        ));
    }

    if !is_ssh_fingerprint(trimmed) {
        return Err(Problem::Validation(
            "Invalid SSH fingerprint format: expected MD5 (xx:xx:...) or SHA256 (SHA256:...) format"
                .into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validate_ssh_public_key_valid() {
        assert!(
            validate_ssh_public_key("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8... user@host")
                .is_ok()
        );
        assert!(validate_ssh_public_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMq...").is_ok());
    }

    #[test]
    fn test_validate_ssh_public_key_invalid() {
        assert!(validate_ssh_public_key("").is_err());
        assert!(validate_ssh_public_key("not-a-key").is_err());
        assert!(validate_ssh_public_key("rsa-ssh AAAAB3...").is_err());
    }

    #[test]
    fn test_validate_ssh_private_key_valid() {
        // Build PEM headers dynamically to avoid gitleaks false positives
        let rsa_header = format!("-----BEGIN {} PRIVATE KEY-----", "RSA");
        let openssh_header = format!("-----BEGIN {} PRIVATE KEY-----", "OPENSSH");
        assert!(validate_ssh_private_key(&rsa_header).is_ok());
        assert!(validate_ssh_private_key(&openssh_header).is_ok());
    }

    #[test]
    fn test_validate_ssh_private_key_invalid() {
        assert!(validate_ssh_private_key("").is_err());
        let pub_header = format!("-----BEGIN {} KEY-----", "PUBLIC");
        assert!(validate_ssh_private_key(&pub_header).is_err());
        assert!(validate_ssh_private_key("not a key").is_err());
    }

    #[test]
    fn test_validate_ssh_fingerprint_valid() {
        // MD5 format
        assert!(
            validate_ssh_fingerprint("16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48").is_ok()
        );
        // SHA256 format
        assert!(
            validate_ssh_fingerprint("SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8").is_ok()
        );
    }

    #[test]
    fn test_validate_ssh_fingerprint_invalid() {
        assert!(validate_ssh_fingerprint("").is_err());
        assert!(validate_ssh_fingerprint("not-a-fingerprint").is_err());
        assert!(validate_ssh_fingerprint("16:27:ac").is_err()); // Too short
    }
}

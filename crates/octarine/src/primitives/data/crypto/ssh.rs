//! SSH key format parsing
//!
//! Pure functions for parsing SSH public key format.

use crate::primitives::identifiers::crypto::KeyType;
use crate::primitives::types::Problem;

use super::types::ParsedSshPublicKey;

/// Maximum SSH key size (100 KB)
const MAX_SSH_KEY_SIZE: usize = 102_400;

/// Parse an SSH public key from the standard one-line format
///
/// Format: `algorithm base64-data [comment]`
///
/// # Arguments
/// * `data` - SSH public key string
///
/// # Returns
/// Parsed SSH public key or error
///
/// # Errors
/// Returns an error if:
/// - Input is too large
/// - Format is not valid SSH public key
/// - Base64 decoding fails
#[cfg(feature = "crypto-validation")]
pub fn parse_ssh_public_key(data: &str) -> Result<ParsedSshPublicKey, Problem> {
    if data.len() > MAX_SSH_KEY_SIZE {
        return Err(Problem::validation("SSH key exceeds maximum allowed size"));
    }

    let trimmed = data.trim();
    let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();

    if parts.len() < 2 {
        return Err(Problem::validation(
            "Invalid SSH public key format: expected 'algorithm base64-data [comment]'",
        ));
    }

    // SAFETY: We've validated parts.len() >= 2 above
    #[allow(clippy::indexing_slicing)]
    let algorithm = parts[0];
    let key_type = match algorithm {
        "ssh-rsa" => KeyType::SshRsa,
        "ssh-ed25519" => KeyType::SshEd25519,
        "ssh-dss" => KeyType::SshDsa,
        a if a.starts_with("ecdsa-sha2-nistp") => KeyType::SshEcdsa,
        _ => KeyType::Unknown,
    };

    // Use ssh-key crate for proper parsing
    let public_key = ssh_key::PublicKey::from_openssh(trimmed)
        .map_err(|e| Problem::validation(format!("Invalid SSH key: {e}")))?;

    // Get the raw key bytes
    let key_data = public_key
        .to_bytes()
        .map_err(|e| Problem::validation(format!("Failed to extract key bytes: {e}")))?;

    let comment = parts.get(2).map(|s| s.to_string());

    Ok(ParsedSshPublicKey {
        key_type,
        algorithm: algorithm.to_string(),
        key_data: key_data.to_vec(),
        comment,
    })
}

#[cfg(not(feature = "crypto-validation"))]
pub fn parse_ssh_public_key(_data: &str) -> Result<ParsedSshPublicKey, Problem> {
    Err(Problem::validation("crypto-validation feature not enabled"))
}

/// Validate that a string is a valid SSH public key format
///
/// # Arguments
/// * `data` - String to validate
///
/// # Returns
/// `Ok(())` if valid, error otherwise
pub fn validate_ssh_public_key_format(data: &str) -> Result<(), Problem> {
    if data.len() > MAX_SSH_KEY_SIZE {
        return Err(Problem::validation("SSH key exceeds maximum allowed size"));
    }

    #[cfg(feature = "crypto-validation")]
    {
        ssh_key::PublicKey::from_openssh(data.trim())
            .map_err(|e| Problem::validation(format!("Invalid SSH key: {e}")))?;
        Ok(())
    }

    #[cfg(not(feature = "crypto-validation"))]
    {
        let _ = data;
        Err(Problem::validation("crypto-validation feature not enabled"))
    }
}

/// Get the fingerprint of an SSH public key
///
/// Returns the SHA-256 fingerprint in the standard format.
#[cfg(feature = "crypto-validation")]
pub fn ssh_key_fingerprint(data: &str) -> Result<String, Problem> {
    if data.len() > MAX_SSH_KEY_SIZE {
        return Err(Problem::validation("SSH key exceeds maximum allowed size"));
    }

    let public_key = ssh_key::PublicKey::from_openssh(data.trim())
        .map_err(|e| Problem::validation(format!("Invalid SSH key: {e}")))?;

    Ok(public_key.fingerprint(ssh_key::HashAlg::Sha256).to_string())
}

#[cfg(not(feature = "crypto-validation"))]
pub fn ssh_key_fingerprint(_data: &str) -> Result<String, Problem> {
    Err(Problem::validation("crypto-validation feature not enabled"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // A real Ed25519 public key for testing
    const SAMPLE_ED25519_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example";

    #[test]
    #[cfg(feature = "crypto-validation")]
    fn test_parse_ssh_public_key() {
        let result = parse_ssh_public_key(SAMPLE_ED25519_KEY);
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let parsed = result.expect("parse should succeed");
        assert_eq!(parsed.key_type, KeyType::SshEd25519);
        assert_eq!(parsed.algorithm, "ssh-ed25519");
        assert_eq!(parsed.comment, Some("test@example".to_string()));
    }

    #[test]
    #[cfg(feature = "crypto-validation")]
    fn test_parse_ssh_key_invalid() {
        let result = parse_ssh_public_key("not a valid key");
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "crypto-validation")]
    fn test_validate_ssh_format() {
        assert!(validate_ssh_public_key_format(SAMPLE_ED25519_KEY).is_ok());
        assert!(validate_ssh_public_key_format("invalid").is_err());
    }

    #[test]
    #[cfg(feature = "crypto-validation")]
    fn test_ssh_fingerprint() {
        let result = ssh_key_fingerprint(SAMPLE_ED25519_KEY);
        assert!(result.is_ok());
        let fingerprint = result.expect("fingerprint should succeed");
        // Fingerprint should start with SHA256:
        assert!(fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn test_size_limit() {
        let huge = "x".repeat(MAX_SSH_KEY_SIZE + 1);
        assert!(parse_ssh_public_key(&huge).is_err());
    }
}

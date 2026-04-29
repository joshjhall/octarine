//! Token / secret shortcuts (JWT, AWS, SSH, GitLab, Bearer).
//!
//! Convenience functions over [`TokenBuilder`](super::super::TokenBuilder).

use crate::observe::Problem;

use super::super::TokenBuilder;
use super::super::types::ApiKeyProvider;

// ============================================================
// JWT SHORTCUTS
// ============================================================

/// Check if value is a JWT token
#[must_use]
pub fn is_jwt(value: &str) -> bool {
    TokenBuilder::new().is_jwt(value)
}

/// Validate a JWT token structure (format only; does not verify signature)
///
/// # Errors
///
/// Returns `Problem` if the JWT structure is invalid.
pub fn validate_jwt(token: &str) -> Result<(), Problem> {
    TokenBuilder::new().validate_jwt(token)
}

/// Validate an API key using common-provider length bounds (20..=200)
///
/// Covers typical providers (Stripe, AWS, GitHub, Slack, etc.). For custom
/// bounds, call `TokenBuilder::new().validate_api_key(key, min, max)` directly.
///
/// # Errors
///
/// Returns `Problem` if the key is outside the length bounds or the format
/// is not recognized.
pub fn validate_api_key(key: &str) -> Result<ApiKeyProvider, Problem> {
    TokenBuilder::new().validate_api_key(key, 20, 200)
}

/// Validate a session ID using common session length bounds (16..=128)
///
/// Covers UUIDs (36), HMAC sessions (64), and larger opaque IDs. For custom
/// bounds, call `TokenBuilder::new().validate_session_id(session_id, min, max)` directly.
///
/// # Errors
///
/// Returns `Problem` if the session ID is outside the length bounds, has low
/// entropy, or contains invalid characters.
pub fn validate_session_id(session_id: &str) -> Result<(), Problem> {
    TokenBuilder::new().validate_session_id(session_id, 16, 128)
}

/// Redact a JWT token
#[must_use]
pub fn redact_jwt(jwt: &str) -> String {
    TokenBuilder::new().redact_jwt(jwt)
}

// ============================================================
// AWS SHORTCUTS
// ============================================================

/// Check if value is an AWS session token (STS temporary credential)
#[must_use]
pub fn is_aws_session_token(value: &str) -> bool {
    TokenBuilder::new().is_aws_session_token(value)
}

// ============================================================
// SSH KEY SHORTCUTS
// ============================================================

/// Check if value is an SSH public key
#[must_use]
pub fn is_ssh_public_key(value: &str) -> bool {
    TokenBuilder::new().is_ssh_public_key(value)
}

/// Check if value is an SSH private key
#[must_use]
pub fn is_ssh_private_key(value: &str) -> bool {
    TokenBuilder::new().is_ssh_private_key(value)
}

/// Check if value is an SSH fingerprint (MD5 or SHA256 format)
#[must_use]
pub fn is_ssh_fingerprint(value: &str) -> bool {
    TokenBuilder::new().is_ssh_fingerprint(value)
}

// ============================================================
// GITLAB / BEARER TOKEN SHORTCUTS
// ============================================================

/// Check if value is a GitLab token
#[must_use]
pub fn is_gitlab_token(value: &str) -> bool {
    TokenBuilder::new().is_gitlab_token(value)
}

/// Check if value is a Bearer token
#[must_use]
pub fn is_bearer_token(value: &str) -> bool {
    TokenBuilder::new().is_bearer_token(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_ssh_public_key_shortcut() {
        assert!(is_ssh_public_key(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8... user@host"
        ));
        assert!(is_ssh_public_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMq..."
        ));
        assert!(!is_ssh_public_key("not-an-ssh-key"));
    }

    #[test]
    fn test_ssh_private_key_shortcut() {
        // Build PEM headers at runtime to avoid gitleaks false positives
        let rsa_header = ["-----BEGIN", " RSA PRIVATE", " KEY-----"].concat();
        let openssh_header = ["-----BEGIN", " OPENSSH PRIVATE", " KEY-----"].concat();
        assert!(is_ssh_private_key(&rsa_header));
        assert!(is_ssh_private_key(&openssh_header));
        assert!(!is_ssh_private_key("ssh-rsa AAAAB3..."));
    }

    #[test]
    fn test_ssh_fingerprint_shortcut() {
        assert!(is_ssh_fingerprint(
            "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"
        ));
        assert!(is_ssh_fingerprint(
            "16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48"
        ));
        assert!(!is_ssh_fingerprint("not-a-fingerprint"));
    }

    #[test]
    fn test_gitlab_token_shortcut() {
        assert!(is_gitlab_token("glpat-xxxxxxxxxxxxxxxxxxxx"));
        assert!(!is_gitlab_token("not-a-token"));
    }

    #[test]
    fn test_bearer_token_shortcut() {
        assert!(is_bearer_token(
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoiZGF0YSJ9.signature"
        ));
        assert!(!is_bearer_token("not-a-bearer-token"));
    }

    #[test]
    fn test_validate_jwt_shortcut() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                   eyJzdWIiOiIxMjM0NTY3ODkwIn0.\
                   dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(validate_jwt(jwt).is_ok());
        assert!(validate_jwt("not-a-jwt").is_err());
        assert!(validate_jwt("only.two").is_err());
    }

    #[test]
    fn test_validate_api_key_shortcut() {
        // Valid prefixed API key within 20..=200 bounds
        assert!(validate_api_key("sk_test_1234567890abcdef").is_ok());
        // Too short (< 20)
        assert!(validate_api_key("short").is_err());
        // Obvious test/demo keys are rejected by the validator
        assert!(validate_api_key("demokey1234567890abcdef").is_err());
    }

    #[test]
    fn test_validate_session_id_shortcut() {
        // 30-char high-entropy session ID within 16..=128 bounds
        assert!(validate_session_id("Ab3De8Gh2Jk5Mn9Pq4Rs7Tv0Wx3Yz6").is_ok());
        // Too short (< 16)
        assert!(validate_session_id("short").is_err());
        // Obvious test session IDs are rejected
        assert!(validate_session_id("test_session_12345678").is_err());
    }
}

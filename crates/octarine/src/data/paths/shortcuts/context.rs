//! Context-specific sanitization shortcuts
//!
//! Convenience functions for context-aware path sanitization.

use crate::observe::Problem;

use super::super::PathBuilder;

// ============================================================
// CONTEXT-SPECIFIC SANITIZATION SHORTCUTS
// ============================================================

/// Sanitize an environment file path (.env files)
pub fn sanitize_path_env(path: &str) -> Result<String, Problem> {
    PathBuilder::new().sanitize_env_path(path)
}

/// Check if a path appears to be an environment file
pub fn is_env_path(path: &str) -> bool {
    PathBuilder::new().is_env_path(path)
}

/// Sanitize an SSH file path (.ssh directory)
pub fn sanitize_path_ssh(path: &str) -> Result<String, Problem> {
    PathBuilder::new().sanitize_ssh_path(path)
}

/// Check if a path appears to be an SSH-related file
pub fn is_ssh_path(path: &str) -> bool {
    PathBuilder::new().is_ssh_path(path)
}

/// Sanitize a credential file path
pub fn sanitize_path_credential(path: &str) -> Result<String, Problem> {
    PathBuilder::new().sanitize_credential_path(path)
}

/// Check if a path appears to be a credential file
pub fn is_credential_path(path: &str) -> bool {
    PathBuilder::new().is_credential_path(path)
}

/// Sanitize a certificate file path
pub fn sanitize_path_certificate(path: &str) -> Result<String, Problem> {
    PathBuilder::new().sanitize_certificate_path(path)
}

/// Sanitize a keystore file path
pub fn sanitize_path_keystore(path: &str) -> Result<String, Problem> {
    PathBuilder::new().sanitize_keystore_path(path)
}

/// Sanitize a secret file path
pub fn sanitize_path_secret(path: &str) -> Result<String, Problem> {
    PathBuilder::new().sanitize_secret_path(path)
}

/// Sanitize a backup file path
pub fn sanitize_path_backup(path: &str) -> Result<String, Problem> {
    PathBuilder::new().sanitize_backup_path(path)
}

/// Sanitize a 1Password reference (op://)
pub fn sanitize_path_op(path: &str) -> Result<String, Problem> {
    PathBuilder::new().sanitize_op_reference(path)
}

/// Check if a path is a 1Password reference
pub fn is_op_reference(path: &str) -> bool {
    PathBuilder::new().is_op_reference(path)
}

/// Sanitize a user-provided path
///
/// Applies security sanitization for paths from untrusted user input.
pub fn sanitize_path_user(path: &str) -> Result<String, Problem> {
    PathBuilder::new().sanitize(path)
}

/// Sanitize a configuration file path
///
/// Applies security sanitization appropriate for config file paths.
pub fn sanitize_path_config(path: &str) -> Result<String, Problem> {
    PathBuilder::new().sanitize(path)
}

/// Sanitize a database file path
///
/// Applies security sanitization appropriate for database file paths.
pub fn sanitize_path_db(path: &str) -> Result<String, Problem> {
    PathBuilder::new().sanitize(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_context_detection() {
        assert!(is_env_path(".env"));
        assert!(is_env_path(".env.local"));
        assert!(is_ssh_path(".ssh/id_rsa"));
    }
}

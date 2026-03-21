//! Environment file path sanitization
//!
//! Handles paths to .env files with appropriate security checks.

use crate::observe::Problem;
use crate::primitives::security::paths::SecurityBuilder;

/// Check if a path appears to be an environment file path
pub(in crate::data::paths) fn is_env_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.ends_with(".env")
        || lower.contains(".env.")
        || lower.ends_with("/env")
        || lower.contains("/.env")
}

/// Sanitize an environment file path
///
/// Environment files are security-sensitive and require strict validation:
/// - No path traversal allowed
/// - No command injection
/// - No null bytes
/// - Must look like an env file path
pub(in crate::data::paths) fn sanitize_env_path(path: &str) -> Result<String, Problem> {
    // First, run security checks
    let security = SecurityBuilder::new();

    if security.is_traversal_present(path) {
        return Err(Problem::security(
            "Path traversal not allowed in environment file paths",
        ));
    }

    if security.is_command_injection_present(path) {
        return Err(Problem::security(
            "Command injection patterns detected in environment file path",
        ));
    }

    if security.is_null_bytes_present(path) {
        return Err(Problem::security(
            "Null bytes not allowed in environment file paths",
        ));
    }

    // Normalize the path
    let normalized = security.sanitize(path)?;

    // Validate it still looks like an env path
    if !is_env_path(&normalized) && !path.is_empty() {
        // If original looked like env path but normalized doesn't, that's suspicious
        if is_env_path(path) {
            return Err(Problem::validation(
                "Environment file path was modified during sanitization",
            ));
        }
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_env_path() {
        assert!(is_env_path(".env"));
        assert!(is_env_path(".env.local"));
        assert!(is_env_path(".env.production"));
        assert!(is_env_path("config/.env"));
        assert!(is_env_path("/app/.env.development"));
        assert!(!is_env_path("config.yaml"));
        assert!(!is_env_path("/etc/passwd"));
    }

    #[test]
    fn test_sanitize_env_path_valid() {
        assert!(sanitize_env_path(".env").is_ok());
        assert!(sanitize_env_path("config/.env.local").is_ok());
    }

    #[test]
    fn test_sanitize_env_path_rejects_traversal() {
        assert!(sanitize_env_path("../.env").is_err());
        assert!(sanitize_env_path("config/../../.env").is_err());
    }

    #[test]
    fn test_sanitize_env_path_rejects_injection() {
        assert!(sanitize_env_path("$(whoami)/.env").is_err());
        assert!(sanitize_env_path(".env;rm -rf /").is_err());
    }
}

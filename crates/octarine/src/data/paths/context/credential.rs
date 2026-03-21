//! Credential and secret file path sanitization
//!
//! Handles paths to credential files, certificates, keystores, and secrets.

use crate::observe::Problem;
use crate::primitives::security::paths::SecurityBuilder;

/// Check if a path appears to be a credential-related path
pub(in crate::data::paths) fn is_credential_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("credential")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("apikey")
        || lower.contains("api_key")
        || lower.contains("api-key")
        || lower.contains("token")
        || lower.ends_with(".key")
        || lower.ends_with(".pem")
        || lower.ends_with(".crt")
        || lower.ends_with(".cer")
        || lower.ends_with(".p12")
        || lower.ends_with(".pfx")
        || lower.ends_with(".jks")
        || lower.ends_with(".keystore")
        || lower.contains("vault")
}

/// Common validation for credential-related paths
fn validate_credential_path_common(path: &str, context: &str) -> Result<String, Problem> {
    let security = SecurityBuilder::new();

    if security.is_traversal_present(path) {
        return Err(Problem::security(format!(
            "Path traversal not allowed in {} paths",
            context
        )));
    }

    if security.is_command_injection_present(path) {
        return Err(Problem::security(format!(
            "Command injection patterns detected in {} path",
            context
        )));
    }

    if security.is_shell_metacharacters_present(path) {
        return Err(Problem::security(format!(
            "Shell metacharacters not allowed in {} paths",
            context
        )));
    }

    if security.is_null_bytes_present(path) {
        return Err(Problem::security(format!(
            "Null bytes not allowed in {} paths",
            context
        )));
    }

    if security.is_variable_expansion_present(path) {
        return Err(Problem::security(format!(
            "Variable expansion not allowed in {} paths",
            context
        )));
    }

    security.sanitize(path)
}

/// Sanitize a credential file path
pub(in crate::data::paths) fn sanitize_credential_path(path: &str) -> Result<String, Problem> {
    validate_credential_path_common(path, "credential")
}

/// Sanitize a certificate file path
pub(in crate::data::paths) fn sanitize_certificate_path(path: &str) -> Result<String, Problem> {
    let result = validate_credential_path_common(path, "certificate")?;

    // Additional validation: should look like a certificate
    let lower = result.to_lowercase();
    if !lower.ends_with(".pem")
        && !lower.ends_with(".crt")
        && !lower.ends_with(".cer")
        && !lower.ends_with(".der")
        && !lower.ends_with(".p7b")
        && !lower.ends_with(".p7c")
        && !lower.contains("cert")
    {
        // Not strictly required, but warn via observe if it doesn't look like a cert
        // For now, just allow it
    }

    Ok(result)
}

/// Sanitize a keystore file path
pub(in crate::data::paths) fn sanitize_keystore_path(path: &str) -> Result<String, Problem> {
    let result = validate_credential_path_common(path, "keystore")?;

    // Additional validation: should look like a keystore
    let lower = result.to_lowercase();
    if !lower.ends_with(".jks")
        && !lower.ends_with(".keystore")
        && !lower.ends_with(".p12")
        && !lower.ends_with(".pfx")
        && !lower.contains("keystore")
    {
        // Allow but could warn
    }

    Ok(result)
}

/// Sanitize a secret file path
pub(in crate::data::paths) fn sanitize_secret_path(path: &str) -> Result<String, Problem> {
    validate_credential_path_common(path, "secret")
}

/// Sanitize a backup file path
///
/// Backup files may contain sensitive data and need careful handling.
pub(in crate::data::paths) fn sanitize_backup_path(path: &str) -> Result<String, Problem> {
    validate_credential_path_common(path, "backup")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_credential_path() {
        assert!(is_credential_path("credentials.json"));
        assert!(is_credential_path("secrets/api.key"));
        assert!(is_credential_path("server.pem"));
        assert!(is_credential_path("client.crt"));
        assert!(is_credential_path("app.keystore"));
        assert!(is_credential_path("vault/token"));
        assert!(!is_credential_path("config.yaml"));
        assert!(!is_credential_path("/etc/passwd"));
    }

    #[test]
    fn test_sanitize_credential_path_valid() {
        assert!(sanitize_credential_path("credentials/api.key").is_ok());
        assert!(sanitize_credential_path("secrets/db_password").is_ok());
    }

    #[test]
    fn test_sanitize_credential_path_rejects_traversal() {
        assert!(sanitize_credential_path("../credentials/api.key").is_err());
    }

    #[test]
    fn test_sanitize_credential_path_rejects_variable_expansion() {
        assert!(sanitize_credential_path("${HOME}/credentials").is_err());
        assert!(sanitize_credential_path("$USER/secrets").is_err());
    }

    #[test]
    fn test_sanitize_certificate_path() {
        assert!(sanitize_certificate_path("certs/server.pem").is_ok());
        assert!(sanitize_certificate_path("ssl/client.crt").is_ok());
    }

    #[test]
    fn test_sanitize_keystore_path() {
        assert!(sanitize_keystore_path("java/app.jks").is_ok());
        assert!(sanitize_keystore_path("certs/client.p12").is_ok());
    }
}

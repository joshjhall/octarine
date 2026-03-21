//! SecureVar - Environment variables with automatic type detection
//!
//! Provides secure loading of environment variables with:
//! - Automatic secret type detection using PII scanner
//! - Appropriate classification based on detected type
//! - Audit logging via observe
//! - Memory zeroization on drop
//!
//! # Example
//!
//! ```ignore
//! use octarine::crypto::secrets::SecureVar;
//!
//! // Load API key - type is auto-detected
//! let api_key = SecureVar::from_env("OPENAI_API_KEY")?;
//!
//! // Check detected type
//! println!("Detected as: {}", api_key.secret_type());
//!
//! // Use with audit trail
//! let value = api_key.expose_secret_audited("api_call");
//! ```

use std::env;
use std::time::Duration;

use crate::observe;
use crate::observe::pii::{PiiType, scan_for_pii};
use crate::primitives::crypto::secrets::{Classification, SecretType};

use thiserror::Error;

use super::{ExposeSecret, TypedSecret};

/// Error type for SecureVar operations
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SecureVarError {
    /// Environment variable not found
    #[error("environment variable '{0}' not found")]
    NotFound(String),

    /// Environment variable is empty
    #[error("environment variable '{0}' is empty")]
    Empty(String),
}

impl From<SecureVarError> for crate::observe::Problem {
    fn from(err: SecureVarError) -> Self {
        match err {
            SecureVarError::NotFound(name) => Self::not_found(format!("env var '{name}'")),
            SecureVarError::Empty(name) => Self::validation(format!("env var '{name}' is empty")),
        }
    }
}

/// A secure environment variable with automatic type detection.
///
/// `SecureVar` loads environment variables and automatically detects
/// their secret type using the PII scanner. This provides:
/// - Automatic classification based on content patterns
/// - Appropriate handling recommendations
/// - Audit trail for compliance
///
/// # Type Detection
///
/// The following patterns are detected:
/// - API keys (sk-*, api_*, various vendor patterns)
/// - JWT tokens (eyJ* base64 encoded)
/// - OAuth/Bearer tokens
/// - SSH keys
/// - Passwords (when loaded from PASSWORD-named vars)
/// - Database credentials (connection strings)
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::secrets::SecureVar;
///
/// // Auto-detect type from value
/// let key = SecureVar::from_env("API_KEY")?;
///
/// // Or explicitly specify type
/// let db_pass = SecureVar::from_env_typed("DB_PASSWORD", SecretType::Password)?;
/// ```
pub struct SecureVar {
    /// The underlying typed secret
    inner: TypedSecret<String>,
    /// Original environment variable name
    var_name: String,
}

impl SecureVar {
    /// Load an environment variable with automatic type detection.
    ///
    /// Uses the PII scanner to detect the secret type from the value,
    /// and infers additional context from the variable name.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the environment variable
    ///
    /// # Returns
    ///
    /// * `Ok(SecureVar)` - The loaded and classified secret
    /// * `Err(SecureVarError::NotFound)` - Variable doesn't exist
    /// * `Err(SecureVarError::Empty)` - Variable exists but is empty
    ///
    /// # Example
    ///
    /// ```ignore
    /// let api_key = SecureVar::from_env("OPENAI_API_KEY")?;
    /// assert_eq!(api_key.secret_type(), &SecretType::ApiKey);
    /// ```
    pub fn from_env(name: &str) -> Result<Self, SecureVarError> {
        let value = env::var(name).map_err(|_| SecureVarError::NotFound(name.to_string()))?;

        if value.is_empty() {
            return Err(SecureVarError::Empty(name.to_string()));
        }

        // Detect type from value using PII scanner
        let detected_type = detect_secret_type(&value, name);
        let classification = detected_type.minimum_classification();

        observe::debug(
            "secure_var_loaded",
            format!(
                "Loaded env var '{}' as {} (classification: {})",
                name, detected_type, classification
            ),
        );

        let typed = TypedSecret::new(value)
            .with_type(detected_type)
            .with_classification(classification)
            .with_id(format!("env:{}", name));

        Ok(Self {
            inner: typed,
            var_name: name.to_string(),
        })
    }

    /// Load an environment variable with explicit type.
    ///
    /// Use this when you know the secret type and don't want
    /// auto-detection overhead.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the environment variable
    /// * `secret_type` - The known secret type
    ///
    /// # Example
    ///
    /// ```ignore
    /// let db_pass = SecureVar::from_env_typed("DB_PASSWORD", SecretType::Password)?;
    /// ```
    pub fn from_env_typed(name: &str, secret_type: SecretType) -> Result<Self, SecureVarError> {
        let value = env::var(name).map_err(|_| SecureVarError::NotFound(name.to_string()))?;

        if value.is_empty() {
            return Err(SecureVarError::Empty(name.to_string()));
        }

        let classification = secret_type.minimum_classification();

        observe::debug(
            "secure_var_loaded",
            format!(
                "Loaded env var '{}' as {} (explicit type, classification: {})",
                name, secret_type, classification
            ),
        );

        let typed = TypedSecret::new(value)
            .with_type(secret_type)
            .with_classification(classification)
            .with_id(format!("env:{}", name));

        Ok(Self {
            inner: typed,
            var_name: name.to_string(),
        })
    }

    /// Load an environment variable with custom configuration.
    ///
    /// Provides full control over classification, TTL, etc.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the environment variable
    /// * `secret_type` - The secret type
    /// * `classification` - Data classification level
    /// * `ttl` - Optional time-to-live
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::time::Duration;
    ///
    /// let token = SecureVar::from_env_custom(
    ///     "SESSION_TOKEN",
    ///     SecretType::AuthToken,
    ///     Classification::Confidential,
    ///     Some(Duration::from_secs(3600)),
    /// )?;
    /// ```
    pub fn from_env_custom(
        name: &str,
        secret_type: SecretType,
        classification: Classification,
        ttl: Option<Duration>,
    ) -> Result<Self, SecureVarError> {
        let value = env::var(name).map_err(|_| SecureVarError::NotFound(name.to_string()))?;

        if value.is_empty() {
            return Err(SecureVarError::Empty(name.to_string()));
        }

        observe::debug(
            "secure_var_loaded",
            format!(
                "Loaded env var '{}' as {} (custom config, classification: {}, ttl: {:?})",
                name, secret_type, classification, ttl
            ),
        );

        let mut typed = TypedSecret::new(value)
            .with_type(secret_type)
            .with_classification(classification)
            .with_id(format!("env:{}", name));

        if let Some(ttl) = ttl {
            typed = typed.with_ttl(ttl);
        }

        Ok(Self {
            inner: typed,
            var_name: name.to_string(),
        })
    }

    /// Get the environment variable name.
    #[must_use]
    pub fn var_name(&self) -> &str {
        &self.var_name
    }

    /// Get the detected/specified secret type.
    #[must_use]
    pub fn secret_type(&self) -> &SecretType {
        self.inner.secret_type()
    }

    /// Get the classification level.
    #[must_use]
    pub fn classification(&self) -> Classification {
        self.inner.classification()
    }

    /// Check if the secret is usable (not expired).
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.inner.is_usable()
    }

    /// Check if the secret has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.inner.is_expired()
    }

    /// Expose the secret value with audit logging.
    ///
    /// Logs the access operation for compliance audit trails.
    ///
    /// # Arguments
    ///
    /// * `operation` - Description of why the secret is being accessed
    ///
    /// # Example
    ///
    /// ```ignore
    /// let value = api_key.expose_secret_audited("authenticate_api_request");
    /// ```
    pub fn expose_secret_audited(&self, operation: &str) -> &str {
        self.inner.expose_secret_audited(operation)
    }

    /// Get a reference to the underlying TypedSecret.
    #[must_use]
    pub fn as_typed_secret(&self) -> &TypedSecret<String> {
        &self.inner
    }
}

impl ExposeSecret<String> for SecureVar {
    /// Expose the secret value WITHOUT audit logging.
    ///
    /// For audited access, use `expose_secret_audited()` instead.
    fn expose_secret(&self) -> &String {
        self.inner.expose_secret()
    }
}

impl std::fmt::Debug for SecureVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureVar")
            .field("var_name", &self.var_name)
            .field("type", &self.inner.secret_type())
            .field("classification", &self.inner.classification())
            .field("expired", &self.inner.is_expired())
            .field("value", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// Type Detection
// ============================================================================

/// Detect secret type from value and variable name.
///
/// Uses PII scanner for content-based detection, with fallback
/// to variable name heuristics.
fn detect_secret_type(value: &str, var_name: &str) -> SecretType {
    // First, try content-based detection using PII scanner
    let pii_types = scan_for_pii(value);

    // Map PII types to secret types (prefer most specific match)
    for pii in &pii_types {
        match pii {
            PiiType::ApiKey => return SecretType::ApiKey,
            PiiType::Jwt => return SecretType::AuthToken,
            PiiType::OAuthToken => return SecretType::AuthToken,
            PiiType::BearerToken => return SecretType::AuthToken,
            PiiType::SessionId => return SecretType::AuthToken,
            PiiType::SshKey => return SecretType::SshKey,
            PiiType::Password => return SecretType::Password,
            PiiType::OnePasswordToken => return SecretType::ApiKey,
            _ => continue,
        }
    }

    // Fallback to variable name heuristics
    // Order matters: more specific patterns first!
    let name_upper = var_name.to_uppercase();

    // Database credentials (check before PASSWORD since POSTGRES_PASSWORD should be DB cred)
    if name_upper.contains("DATABASE_URL")
        || name_upper.contains("DB_URL")
        || name_upper.starts_with("POSTGRES")
        || name_upper.starts_with("MYSQL")
        || name_upper.starts_with("REDIS")
        || name_upper.starts_with("MONGO")
    {
        return SecretType::DatabaseCredential;
    }

    // SSH keys (check before generic _KEY suffix)
    if name_upper.contains("SSH") {
        return SecretType::SshKey;
    }

    // Specific key types (check before generic _KEY suffix)
    if name_upper.contains("PRIVATE_KEY") || name_upper.contains("PRIVKEY") {
        return SecretType::PrivateKey;
    }

    if name_upper.contains("ENCRYPTION_KEY") || name_upper.contains("ENCRYPT_KEY") {
        return SecretType::EncryptionKey;
    }

    if name_upper.contains("HMAC") || name_upper.contains("SIGNING_KEY") {
        return SecretType::HmacKey;
    }

    // Now generic API key patterns
    if name_upper.contains("API_KEY")
        || name_upper.contains("APIKEY")
        || name_upper.ends_with("_KEY")
    {
        return SecretType::ApiKey;
    }

    // Passwords
    if name_upper.contains("PASSWORD")
        || name_upper.contains("PASSWD")
        || name_upper.contains("_PWD")
    {
        return SecretType::Password;
    }

    // Tokens
    if name_upper.contains("TOKEN") {
        if name_upper.contains("REFRESH") {
            return SecretType::RefreshToken;
        }
        return SecretType::AuthToken;
    }

    // Secrets
    if name_upper.contains("SECRET") {
        if name_upper.contains("WEBHOOK") {
            return SecretType::WebhookSecret;
        }
        return SecretType::Generic;
    }

    // Default to generic
    SecretType::Generic
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // Note: We can't easily test from_env() because setting env vars requires
    // unsafe code (forbidden in octarine). Instead, we test the detection logic.

    #[test]
    fn test_from_env_not_found() {
        let result = SecureVar::from_env("NONEXISTENT_VAR_12345_ABCXYZ");
        assert!(matches!(result, Err(SecureVarError::NotFound(_))));
    }

    #[test]
    fn test_detect_api_key_from_name() {
        let detected = detect_secret_type("some-value", "MY_API_KEY");
        assert_eq!(detected, SecretType::ApiKey);
    }

    #[test]
    fn test_detect_api_key_suffix() {
        let detected = detect_secret_type("value", "OPENAI_KEY");
        assert_eq!(detected, SecretType::ApiKey);
    }

    #[test]
    fn test_detect_password_from_name() {
        let detected = detect_secret_type("hunter2", "DB_PASSWORD");
        assert_eq!(detected, SecretType::Password);
    }

    #[test]
    fn test_detect_password_variants() {
        assert_eq!(detect_secret_type("x", "PASSWD"), SecretType::Password);
        assert_eq!(detect_secret_type("x", "DB_PWD"), SecretType::Password);
    }

    #[test]
    fn test_detect_token_from_name() {
        let detected = detect_secret_type("abc123", "AUTH_TOKEN");
        assert_eq!(detected, SecretType::AuthToken);
    }

    #[test]
    fn test_detect_refresh_token() {
        let detected = detect_secret_type("xyz789", "REFRESH_TOKEN");
        assert_eq!(detected, SecretType::RefreshToken);
    }

    #[test]
    fn test_detect_database_credential() {
        let detected = detect_secret_type("postgres://user:pass@host/db", "DATABASE_URL");
        assert_eq!(detected, SecretType::DatabaseCredential);
    }

    #[test]
    fn test_detect_database_variants() {
        assert_eq!(
            detect_secret_type("x", "POSTGRES_PASSWORD"),
            SecretType::DatabaseCredential
        );
        assert_eq!(
            detect_secret_type("x", "MYSQL_ROOT_PASSWORD"),
            SecretType::DatabaseCredential
        );
        assert_eq!(
            detect_secret_type("x", "REDIS_URL"),
            SecretType::DatabaseCredential
        );
    }

    #[test]
    fn test_detect_ssh_key() {
        let detected = detect_secret_type("key-data", "SSH_PRIVATE_KEY");
        assert_eq!(detected, SecretType::SshKey);
    }

    #[test]
    fn test_detect_private_key() {
        let detected = detect_secret_type("key-data", "TLS_PRIVATE_KEY");
        assert_eq!(detected, SecretType::PrivateKey);
    }

    #[test]
    fn test_detect_encryption_key() {
        let detected = detect_secret_type("key-data", "DATA_ENCRYPTION_KEY");
        assert_eq!(detected, SecretType::EncryptionKey);
    }

    #[test]
    fn test_detect_hmac_key() {
        let detected = detect_secret_type("key-data", "HMAC_SECRET");
        assert_eq!(detected, SecretType::HmacKey);

        let detected2 = detect_secret_type("key-data", "JWT_SIGNING_KEY");
        assert_eq!(detected2, SecretType::HmacKey);
    }

    #[test]
    fn test_detect_webhook_secret() {
        let detected = detect_secret_type("whsec_xxx", "WEBHOOK_SECRET");
        assert_eq!(detected, SecretType::WebhookSecret);
    }

    #[test]
    fn test_detect_generic_fallback() {
        let detected = detect_secret_type("some-value", "RANDOM_CONFIG");
        assert_eq!(detected, SecretType::Generic);
    }

    #[test]
    fn test_detect_jwt_from_value() {
        // JWT tokens start with eyJ (base64 encoded {"alg":...)
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig";
        let detected = detect_secret_type(jwt, "SOME_VAR");
        assert_eq!(detected, SecretType::AuthToken);
    }

    #[test]
    fn test_error_display() {
        let not_found = SecureVarError::NotFound("MY_VAR".to_string());
        assert_eq!(
            not_found.to_string(),
            "environment variable 'MY_VAR' not found"
        );

        let empty = SecureVarError::Empty("MY_VAR".to_string());
        assert_eq!(empty.to_string(), "environment variable 'MY_VAR' is empty");
    }
}

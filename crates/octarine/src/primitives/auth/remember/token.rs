//! Remember-me token generation and validation
//!
//! Implements OWASP ASVS V3.5 controls for secure remember-me functionality:
//! - V3.5.1: Remember-me tokens are random with at least 128 bits of entropy
//! - V3.5.2: Remember-me tokens use split selector:validator approach
//! - V3.5.3: Tokens are rotated on use to prevent fixation attacks

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

use crate::primitives::types::Problem;

// ============================================================================
// Remember Configuration
// ============================================================================

/// Configuration for remember-me tokens
#[derive(Debug, Clone)]
pub struct RememberConfig {
    /// Selector length in bytes (default: 16 = 128 bits)
    pub selector_length: usize,
    /// Validator length in bytes (default: 32 = 256 bits)
    pub validator_length: usize,
    /// Token lifetime (default: 30 days)
    pub token_lifetime: Duration,
    /// Whether to rotate tokens on use (default: true)
    pub rotate_on_use: bool,
    /// Maximum tokens per user (default: 5)
    pub max_tokens_per_user: usize,
    /// Cookie name (default: "remember_me")
    pub cookie_name: String,
}

impl Default for RememberConfig {
    fn default() -> Self {
        Self {
            selector_length: 16,
            validator_length: 32,
            token_lifetime: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            rotate_on_use: true,
            max_tokens_per_user: 5,
            cookie_name: "remember_me".to_string(),
        }
    }
}

impl RememberConfig {
    /// Create a new remember config builder
    #[must_use]
    pub fn builder() -> RememberConfigBuilder {
        RememberConfigBuilder::default()
    }
}

/// Builder for remember configuration
#[derive(Debug, Default)]
pub struct RememberConfigBuilder {
    selector_length: Option<usize>,
    validator_length: Option<usize>,
    token_lifetime: Option<Duration>,
    rotate_on_use: Option<bool>,
    max_tokens_per_user: Option<usize>,
    cookie_name: Option<String>,
}

impl RememberConfigBuilder {
    /// Set the selector length in bytes (minimum 16)
    #[must_use]
    pub fn selector_length(mut self, length: usize) -> Self {
        self.selector_length = Some(length.max(16));
        self
    }

    /// Set the validator length in bytes (minimum 16)
    #[must_use]
    pub fn validator_length(mut self, length: usize) -> Self {
        self.validator_length = Some(length.max(16));
        self
    }

    /// Set the token lifetime
    #[must_use]
    pub fn token_lifetime(mut self, lifetime: Duration) -> Self {
        self.token_lifetime = Some(lifetime);
        self
    }

    /// Set whether to rotate tokens on use
    #[must_use]
    pub fn rotate_on_use(mut self, rotate: bool) -> Self {
        self.rotate_on_use = Some(rotate);
        self
    }

    /// Set the maximum tokens per user
    #[must_use]
    pub fn max_tokens_per_user(mut self, max: usize) -> Self {
        self.max_tokens_per_user = Some(max);
        self
    }

    /// Set the cookie name
    #[must_use]
    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        self.cookie_name = Some(name.into());
        self
    }

    /// Build the configuration
    #[must_use]
    pub fn build(self) -> RememberConfig {
        RememberConfig {
            selector_length: self.selector_length.unwrap_or(16),
            validator_length: self.validator_length.unwrap_or(32),
            token_lifetime: self
                .token_lifetime
                .unwrap_or(Duration::from_secs(30 * 24 * 60 * 60)),
            rotate_on_use: self.rotate_on_use.unwrap_or(true),
            max_tokens_per_user: self.max_tokens_per_user.unwrap_or(5),
            cookie_name: self
                .cookie_name
                .unwrap_or_else(|| "remember_me".to_string()),
        }
    }
}

// ============================================================================
// Remember Token
// ============================================================================

/// A remember-me token for persistent login
///
/// This is the stored representation of a remember-me token.
/// The validator is stored as a hash, never in plaintext.
#[derive(Debug, Clone)]
pub struct RememberToken {
    /// Public identifier for database lookup
    selector: String,
    /// SHA-256 hash of the validator
    validator_hash: String,
    /// The user this token belongs to
    user_id: String,
    /// When the token was created
    created_at: Instant,
    /// Token lifetime
    lifetime: Duration,
    /// Optional device/browser info
    device_info: Option<String>,
    /// Whether the token has been revoked
    revoked: bool,
}

impl RememberToken {
    /// Create a new remember token
    fn new(
        selector: String,
        validator_hash: String,
        user_id: String,
        lifetime: Duration,
        device_info: Option<String>,
    ) -> Self {
        Self {
            selector,
            validator_hash,
            user_id,
            created_at: Instant::now(),
            lifetime,
            device_info,
            revoked: false,
        }
    }

    /// Create a remember token from stored values (for loading from database)
    #[must_use]
    pub fn from_storage(
        selector: String,
        validator_hash: String,
        user_id: String,
        remaining_lifetime: Duration,
        device_info: Option<String>,
        revoked: bool,
    ) -> Self {
        Self {
            selector,
            validator_hash,
            user_id,
            created_at: Instant::now(),
            lifetime: remaining_lifetime,
            device_info,
            revoked,
        }
    }

    /// Get the selector (public identifier)
    #[must_use]
    pub fn selector(&self) -> &str {
        &self.selector
    }

    /// Get the validator hash
    #[must_use]
    pub fn validator_hash(&self) -> &str {
        &self.validator_hash
    }

    /// Get the user ID
    #[must_use]
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Get the device info if set
    #[must_use]
    pub fn device_info(&self) -> Option<&str> {
        self.device_info.as_deref()
    }

    /// Check if the token has expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.lifetime
    }

    /// Check if the token has been revoked
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Mark the token as revoked
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Check if the token is still valid (not expired and not revoked)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_revoked()
    }

    /// Get remaining validity duration
    #[must_use]
    pub fn remaining_validity(&self) -> Option<Duration> {
        if self.is_revoked() {
            return None;
        }
        let elapsed = self.created_at.elapsed();
        if elapsed > self.lifetime {
            None
        } else {
            Some(self.lifetime.saturating_sub(elapsed))
        }
    }
}

impl std::fmt::Display for RememberToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Only show first 8 chars of selector for security
        if self.selector.len() > 8 {
            write!(f, "{}...", &self.selector[..8])
        } else {
            write!(f, "{}", &self.selector)
        }
    }
}

// ============================================================================
// Token Pair (for sending to client)
// ============================================================================

/// A token pair containing both selector and validator
///
/// This is what gets sent to the client in the cookie.
/// The format is `selector:validator` (both base64 encoded).
///
/// `Debug` is implemented manually to redact the plaintext `validator` —
/// derived `Debug` would leak the secret via logs, panics, or test output.
#[derive(Clone)]
pub struct RememberTokenPair {
    /// The stored token (with hashed validator)
    token: RememberToken,
    /// The plaintext validator (only available at generation time)
    validator: String,
}

impl std::fmt::Debug for RememberTokenPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `token` contains only a validator_hash (SHA-256), not plaintext —
        // safe to print via its derived Debug. Only `validator` is secret.
        f.debug_struct("RememberTokenPair")
            .field("token", &self.token)
            .field("validator", &"[REDACTED]")
            .finish()
    }
}

impl RememberTokenPair {
    /// Get the cookie value (selector:validator)
    #[must_use]
    pub fn cookie_value(&self) -> String {
        format!("{}:{}", self.token.selector, self.validator)
    }

    /// Get the stored token
    #[must_use]
    pub fn token(&self) -> &RememberToken {
        &self.token
    }

    /// Get the selector
    #[must_use]
    pub fn selector(&self) -> &str {
        &self.token.selector
    }

    /// Get the validator (only available at generation time)
    #[must_use]
    pub fn validator(&self) -> &str {
        &self.validator
    }
}

// ============================================================================
// Token Generation and Validation
// ============================================================================

/// Generate a new remember-me token
///
/// Creates a cryptographically random token pair with:
/// - A selector for database lookup
/// - A validator that is hashed before storage
///
/// # Arguments
///
/// * `user_id` - The user ID this token is for
/// * `config` - Remember configuration
/// * `device_info` - Optional device/browser information
///
/// # Returns
///
/// A token pair containing the stored token and the plaintext validator.
#[must_use]
pub fn generate_remember_token(
    user_id: &str,
    config: &RememberConfig,
    device_info: Option<&str>,
) -> RememberTokenPair {
    // Generate random selector
    let mut selector_bytes = vec![0u8; config.selector_length];
    rand::rng().fill_bytes(&mut selector_bytes);
    let selector = URL_SAFE_NO_PAD.encode(&selector_bytes);

    // Generate random validator
    let mut validator_bytes = vec![0u8; config.validator_length];
    rand::rng().fill_bytes(&mut validator_bytes);
    let validator = URL_SAFE_NO_PAD.encode(&validator_bytes);

    // Hash the validator for storage
    let validator_hash = hash_validator(&validator);

    let token = RememberToken::new(
        selector,
        validator_hash,
        user_id.to_string(),
        config.token_lifetime,
        device_info.map(String::from),
    );

    RememberTokenPair { token, validator }
}

/// Validate a remember-me token
///
/// Parses the cookie value and validates against the stored token.
///
/// # Arguments
///
/// * `cookie_value` - The value from the remember-me cookie (selector:validator)
/// * `stored_token` - The stored token from the database
///
/// # Returns
///
/// `Ok(())` if valid, `Err(Problem)` with the reason if invalid.
pub fn validate_remember_token(
    cookie_value: &str,
    stored_token: &RememberToken,
) -> Result<(), Problem> {
    // Parse cookie value
    let (selector, validator) = parse_cookie_value(cookie_value)?;

    // Verify selector matches
    if selector != stored_token.selector() {
        return Err(Problem::Auth("Invalid remember-me token".to_string()));
    }

    // Check if revoked
    if stored_token.is_revoked() {
        return Err(Problem::Auth(
            "Remember-me token has been revoked".to_string(),
        ));
    }

    // Check expiration
    if stored_token.is_expired() {
        return Err(Problem::Auth("Remember-me token has expired".to_string()));
    }

    // Hash the submitted validator and compare
    let submitted_hash = hash_validator(validator);
    if !constant_time_compare(&submitted_hash, stored_token.validator_hash()) {
        return Err(Problem::Auth("Invalid remember-me token".to_string()));
    }

    Ok(())
}

/// Parse a cookie value into selector and validator
///
/// # Arguments
///
/// * `cookie_value` - The value from the remember-me cookie (selector:validator)
///
/// # Returns
///
/// A tuple of (selector, validator) on success.
pub fn parse_cookie_value(cookie_value: &str) -> Result<(&str, &str), Problem> {
    let parts: Vec<&str> = cookie_value.splitn(2, ':').collect();

    let selector = parts
        .first()
        .ok_or_else(|| Problem::Auth("Invalid remember-me token format".to_string()))?;
    let validator = parts
        .get(1)
        .ok_or_else(|| Problem::Auth("Invalid remember-me token format".to_string()))?;

    if selector.is_empty() || validator.is_empty() {
        return Err(Problem::Auth(
            "Invalid remember-me token format".to_string(),
        ));
    }

    Ok((selector, validator))
}

// ============================================================================
// Private Helpers
// ============================================================================

/// Hash a validator using SHA-256
fn hash_validator(validator: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(validator.as_bytes());
    let result = hasher.finalize();
    URL_SAFE_NO_PAD.encode(result)
}

/// Constant-time string comparison
///
/// Prevents timing attacks by always comparing the full length.
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    let mut result: u8 = 0;
    for i in 0..a.len() {
        let a_byte = a_bytes.get(i).copied().unwrap_or(0);
        let b_byte = b_bytes.get(i).copied().unwrap_or(0);
        result |= a_byte ^ b_byte;
    }

    result == 0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RememberConfig::default();
        assert_eq!(config.selector_length, 16);
        assert_eq!(config.validator_length, 32);
        assert_eq!(
            config.token_lifetime,
            Duration::from_secs(30 * 24 * 60 * 60)
        );
        assert!(config.rotate_on_use);
        assert_eq!(config.max_tokens_per_user, 5);
        assert_eq!(config.cookie_name, "remember_me");
    }

    #[test]
    fn test_config_builder() {
        let config = RememberConfig::builder()
            .selector_length(32)
            .validator_length(64)
            .token_lifetime(Duration::from_secs(7 * 24 * 60 * 60))
            .rotate_on_use(false)
            .max_tokens_per_user(10)
            .cookie_name("my_remember")
            .build();

        assert_eq!(config.selector_length, 32);
        assert_eq!(config.validator_length, 64);
        assert_eq!(config.token_lifetime, Duration::from_secs(7 * 24 * 60 * 60));
        assert!(!config.rotate_on_use);
        assert_eq!(config.max_tokens_per_user, 10);
        assert_eq!(config.cookie_name, "my_remember");
    }

    #[test]
    fn test_config_builder_minimum_lengths() {
        let config = RememberConfig::builder()
            .selector_length(8)
            .validator_length(8)
            .build();

        // Should be clamped to minimum of 16
        assert_eq!(config.selector_length, 16);
        assert_eq!(config.validator_length, 16);
    }

    #[test]
    fn test_generate_remember_token() {
        let config = RememberConfig::default();
        let pair = generate_remember_token("user123", &config, None);

        assert!(!pair.selector().is_empty());
        assert!(!pair.validator().is_empty());
        assert_eq!(pair.token().user_id(), "user123");
        assert!(!pair.token().is_expired());
        assert!(!pair.token().is_revoked());
        assert!(pair.token().is_valid());
    }

    #[test]
    fn test_generate_with_device_info() {
        let config = RememberConfig::default();
        let pair = generate_remember_token("user123", &config, Some("Chrome on Windows"));

        assert_eq!(pair.token().device_info(), Some("Chrome on Windows"));
    }

    #[test]
    fn test_cookie_value() {
        let config = RememberConfig::default();
        let pair = generate_remember_token("user123", &config, None);

        let cookie = pair.cookie_value();
        assert!(cookie.contains(':'));

        let parts: Vec<&str> = cookie.split(':').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], pair.selector());
        assert_eq!(parts[1], pair.validator());
    }

    #[test]
    fn test_token_uniqueness() {
        let config = RememberConfig::default();
        let pair1 = generate_remember_token("user123", &config, None);
        let pair2 = generate_remember_token("user123", &config, None);

        assert_ne!(pair1.selector(), pair2.selector());
        assert_ne!(pair1.validator(), pair2.validator());
    }

    #[test]
    fn test_validate_remember_token_success() {
        let config = RememberConfig::default();
        let pair = generate_remember_token("user123", &config, None);

        let result = validate_remember_token(&pair.cookie_value(), pair.token());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_remember_token_invalid_validator() {
        let config = RememberConfig::default();
        let pair = generate_remember_token("user123", &config, None);

        // Tamper with the validator
        let cookie = format!("{}:wrong_validator", pair.selector());
        let result = validate_remember_token(&cookie, pair.token());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid"));
    }

    #[test]
    fn test_validate_remember_token_wrong_selector() {
        let config = RememberConfig::default();
        let pair = generate_remember_token("user123", &config, None);

        // Use wrong selector
        let cookie = format!("wrong_selector:{}", pair.validator());
        let result = validate_remember_token(&cookie, pair.token());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid"));
    }

    #[test]
    fn test_validate_remember_token_expired() {
        let config = RememberConfig::builder()
            .token_lifetime(Duration::from_millis(10))
            .build();
        let pair = generate_remember_token("user123", &config, None);

        std::thread::sleep(Duration::from_millis(20));

        let result = validate_remember_token(&pair.cookie_value(), pair.token());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn test_validate_remember_token_revoked() {
        let config = RememberConfig::default();
        let pair = generate_remember_token("user123", &config, None);
        let mut token = pair.token().clone();
        token.revoke();

        let result = validate_remember_token(&pair.cookie_value(), &token);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("revoked"));
    }

    #[test]
    fn test_parse_cookie_value() {
        let (selector, validator) = parse_cookie_value("abc:xyz").unwrap();
        assert_eq!(selector, "abc");
        assert_eq!(validator, "xyz");
    }

    #[test]
    fn test_parse_cookie_value_invalid() {
        // No colon
        assert!(parse_cookie_value("invalid").is_err());

        // Empty selector
        assert!(parse_cookie_value(":validator").is_err());

        // Empty validator
        assert!(parse_cookie_value("selector:").is_err());
    }

    #[test]
    fn test_revoke() {
        let config = RememberConfig::default();
        let pair = generate_remember_token("user123", &config, None);
        let mut token = pair.token().clone();

        assert!(!token.is_revoked());
        assert!(token.is_valid());

        token.revoke();

        assert!(token.is_revoked());
        assert!(!token.is_valid());
    }

    #[test]
    fn test_remaining_validity() {
        let config = RememberConfig::builder()
            .token_lifetime(Duration::from_secs(60))
            .build();
        let pair = generate_remember_token("user123", &config, None);

        let remaining = pair.token().remaining_validity();
        assert!(remaining.is_some());
        assert!(remaining.expect("should have remaining time") <= Duration::from_secs(60));
    }

    #[test]
    fn test_remaining_validity_after_revoke() {
        let config = RememberConfig::default();
        let pair = generate_remember_token("user123", &config, None);
        let mut token = pair.token().clone();
        token.revoke();

        assert!(token.remaining_validity().is_none());
    }

    #[test]
    fn test_token_display_truncates() {
        let config = RememberConfig::default();
        let pair = generate_remember_token("user123", &config, None);
        let display = pair.token().to_string();

        assert!(display.contains("..."));
    }

    #[test]
    fn test_pair_debug_redacts_validator() {
        let config = RememberConfig::default();
        let pair = generate_remember_token("user123", &config, None);
        let debug_str = format!("{pair:?}");

        // Plaintext validator must not appear anywhere in Debug output.
        assert!(
            !debug_str.contains(pair.validator()),
            "Debug output leaked plaintext validator: {debug_str}"
        );
        // Redaction marker is present.
        assert!(debug_str.contains("[REDACTED]"));
        // Selector (not a secret) still visible for diagnostics.
        assert!(debug_str.contains(pair.selector()));
        assert!(debug_str.contains("RememberTokenPair"));
    }

    #[test]
    fn test_from_storage() {
        let token = RememberToken::from_storage(
            "selector123".to_string(),
            "hash456".to_string(),
            "user123".to_string(),
            Duration::from_secs(300),
            Some("Chrome".to_string()),
            false,
        );

        assert_eq!(token.selector(), "selector123");
        assert_eq!(token.validator_hash(), "hash456");
        assert_eq!(token.user_id(), "user123");
        assert_eq!(token.device_info(), Some("Chrome"));
        assert!(!token.is_revoked());
        assert!(token.remaining_validity().is_some());
    }

    #[test]
    fn test_from_storage_revoked() {
        let token = RememberToken::from_storage(
            "selector123".to_string(),
            "hash456".to_string(),
            "user123".to_string(),
            Duration::from_secs(300),
            None,
            true,
        );

        assert!(token.is_revoked());
        assert!(!token.is_valid());
    }

    #[test]
    fn test_hash_validator_deterministic() {
        let hash1 = hash_validator("test_validator");
        let hash2 = hash_validator("test_validator");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_validator_different_inputs() {
        let hash1 = hash_validator("validator1");
        let hash2 = hash_validator("validator2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("abc", "abc"));
        assert!(!constant_time_compare("abc", "abd"));
        assert!(!constant_time_compare("abc", "ab"));
        assert!(!constant_time_compare("ab", "abc"));
    }
}

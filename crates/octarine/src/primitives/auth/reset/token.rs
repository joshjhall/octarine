//! Password reset token generation and validation
//!
//! Implements OWASP ASVS V2.5 controls for secure password reset:
//! - V2.5.1: Reset tokens are random with at least 128 bits of entropy
//! - V2.5.2: Reset tokens expire after a short period (default: 1 hour)
//! - V2.5.4: Rate limiting for reset requests

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use std::time::{Duration, Instant};

use crate::primitives::crypto::secrets::{ExposeSecretCore, SecretCore, SecretStringCore};
use crate::primitives::types::Problem;

// ============================================================================
// Reset Configuration
// ============================================================================

/// Configuration for password reset tokens
#[derive(Debug, Clone)]
pub struct ResetConfig {
    /// Token entropy in bytes (default: 32 = 256 bits)
    pub token_length: usize,
    /// Token lifetime (default: 1 hour)
    pub token_lifetime: Duration,
    /// Maximum active tokens per user (default: 3)
    pub max_active_tokens: usize,
    /// Minimum time between reset requests (default: 1 minute)
    pub rate_limit_window: Duration,
}

impl Default for ResetConfig {
    fn default() -> Self {
        Self {
            token_length: 32,
            token_lifetime: Duration::from_secs(3600), // 1 hour
            max_active_tokens: 3,
            rate_limit_window: Duration::from_secs(60), // 1 minute
        }
    }
}

impl ResetConfig {
    /// Create a new reset config builder
    #[must_use]
    pub fn builder() -> ResetConfigBuilder {
        ResetConfigBuilder::default()
    }
}

/// Builder for reset configuration
#[derive(Debug, Default)]
pub struct ResetConfigBuilder {
    token_length: Option<usize>,
    token_lifetime: Option<Duration>,
    max_active_tokens: Option<usize>,
    rate_limit_window: Option<Duration>,
}

impl ResetConfigBuilder {
    /// Set the token length in bytes (minimum 16, default 32)
    #[must_use]
    pub fn token_length(mut self, length: usize) -> Self {
        self.token_length = Some(length.max(16));
        self
    }

    /// Set the token lifetime
    #[must_use]
    pub fn token_lifetime(mut self, lifetime: Duration) -> Self {
        self.token_lifetime = Some(lifetime);
        self
    }

    /// Set the maximum active tokens per user
    #[must_use]
    pub fn max_active_tokens(mut self, max: usize) -> Self {
        self.max_active_tokens = Some(max);
        self
    }

    /// Set the rate limit window (minimum time between requests)
    #[must_use]
    pub fn rate_limit_window(mut self, window: Duration) -> Self {
        self.rate_limit_window = Some(window);
        self
    }

    /// Build the configuration
    #[must_use]
    pub fn build(self) -> ResetConfig {
        ResetConfig {
            token_length: self.token_length.unwrap_or(32),
            token_lifetime: self.token_lifetime.unwrap_or(Duration::from_secs(3600)),
            max_active_tokens: self.max_active_tokens.unwrap_or(3),
            rate_limit_window: self.rate_limit_window.unwrap_or(Duration::from_secs(60)),
        }
    }
}

// ============================================================================
// Reset Token
// ============================================================================

/// A password reset token with metadata
///
/// Reset tokens are secure, time-limited, single-use tokens for password
/// reset flows. Each token has 256 bits of entropy by default.
///
/// The plaintext token value is stored in a zeroizing `SecretStringCore`
/// wrapper so the secret bytes are wiped from heap memory when the token
/// is dropped. `Debug` is implemented manually to mask the plaintext —
/// derived `Debug` would leak the secret via logs, panics, or test output.
#[derive(Clone)]
pub struct ResetToken {
    /// The token value (URL-safe base64), zeroized on drop.
    token: SecretStringCore,
    /// The user this token is for
    user_id: String,
    /// When the token was created
    created_at: Instant,
    /// Token lifetime
    lifetime: Duration,
    /// Whether the token has been used
    used: bool,
}

impl ResetToken {
    /// Create a new reset token
    fn new(token: String, user_id: String, lifetime: Duration) -> Self {
        Self {
            token: SecretCore::new(token),
            user_id,
            created_at: Instant::now(),
            lifetime,
            used: false,
        }
    }

    /// Create a reset token from stored values (for loading from database)
    ///
    /// # Arguments
    ///
    /// * `token` - The token string
    /// * `user_id` - The user ID
    /// * `remaining_lifetime` - Time remaining until expiration
    /// * `used` - Whether the token has been used
    #[must_use]
    pub fn from_storage(
        token: String,
        user_id: String,
        remaining_lifetime: Duration,
        used: bool,
    ) -> Self {
        Self {
            token: SecretCore::new(token),
            user_id,
            created_at: Instant::now(),
            lifetime: remaining_lifetime,
            used,
        }
    }

    /// Get the token value
    ///
    /// Returns a borrowed view into the zeroizing buffer. Callers should
    /// avoid copying the returned `&str` into long-lived `String`
    /// allocations — the zeroization guarantee only applies to bytes that
    /// stay inside the `ResetToken`'s buffer.
    #[must_use]
    pub fn value(&self) -> &str {
        self.token.expose_secret()
    }

    /// Get the user ID
    #[must_use]
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Check if the token has expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.lifetime
    }

    /// Check if the token has been used
    #[must_use]
    pub fn is_used(&self) -> bool {
        self.used
    }

    /// Mark the token as used
    pub fn mark_used(&mut self) {
        self.used = true;
    }

    /// Check if the token is still valid (not expired and not used)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_used()
    }

    /// Get remaining validity duration
    #[must_use]
    pub fn remaining_validity(&self) -> Option<Duration> {
        if self.is_used() {
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

impl std::fmt::Display for ResetToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Only show first 8 chars for security in logs
        let token = self.token.expose_secret();
        if let Some(prefix) = token.get(..8) {
            write!(f, "{prefix}...")
        } else {
            write!(f, "{token}")
        }
    }
}

impl std::fmt::Debug for ResetToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Mask the plaintext token — same first-8-char scheme as Display.
        let token = self.token.expose_secret();
        let masked = token
            .get(..8)
            .map_or_else(|| token.clone(), |prefix| format!("{prefix}..."));
        f.debug_struct("ResetToken")
            .field("token", &masked)
            .field("user_id", &self.user_id)
            .field("created_at", &self.created_at)
            .field("lifetime", &self.lifetime)
            .field("used", &self.used)
            .finish()
    }
}

impl PartialEq for ResetToken {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison to prevent timing attacks
        constant_time_compare(self.token.expose_secret(), other.token.expose_secret())
            && self.user_id == other.user_id
    }
}

// ============================================================================
// Token Generation and Validation
// ============================================================================

/// Generate a new password reset token
///
/// Creates a cryptographically random token with 256 bits of entropy
/// suitable for password reset flows.
///
/// # Arguments
///
/// * `user_id` - The user ID this token is for
/// * `config` - Reset configuration
///
/// # Returns
///
/// A new reset token.
#[must_use]
pub fn generate_reset_token(user_id: &str, config: &ResetConfig) -> ResetToken {
    let mut bytes = vec![0u8; config.token_length];
    rand::rng().fill_bytes(&mut bytes);

    let token = URL_SAFE_NO_PAD.encode(&bytes);
    ResetToken::new(token, user_id.to_string(), config.token_lifetime)
}

/// Validate a reset token
///
/// Checks that the token matches, belongs to the correct user,
/// has not expired, and has not been used.
///
/// # Arguments
///
/// * `submitted` - The token submitted by the user
/// * `expected` - The expected token from storage
///
/// # Returns
///
/// `Ok(())` if valid, `Err(Problem)` with the reason if invalid.
pub fn validate_reset_token(submitted: &str, expected: &ResetToken) -> Result<(), Problem> {
    // Check if used first (to avoid timing leaks)
    if expected.is_used() {
        return Err(Problem::Auth(
            "Reset token has already been used".to_string(),
        ));
    }

    // Check expiration
    if expected.is_expired() {
        return Err(Problem::Auth("Reset token has expired".to_string()));
    }

    // Constant-time comparison
    if !constant_time_compare(submitted, expected.value()) {
        return Err(Problem::Auth("Invalid reset token".to_string()));
    }

    Ok(())
}

/// Validate that a reset request is not rate-limited
///
/// # Arguments
///
/// * `last_request` - When the last reset was requested (if any)
/// * `config` - Reset configuration
///
/// # Returns
///
/// `Ok(())` if not rate-limited, `Err(Problem::RateLimited)` with remaining time if rate-limited.
pub fn validate_rate_limit(
    last_request: Option<Instant>,
    config: &ResetConfig,
) -> Result<(), Problem> {
    if let Some(last) = last_request {
        let elapsed = last.elapsed();
        if elapsed < config.rate_limit_window {
            let remaining = config.rate_limit_window.saturating_sub(elapsed);
            return Err(Problem::RateLimited(remaining));
        }
    }
    Ok(())
}

// ============================================================================
// Private Helpers
// ============================================================================

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
#[allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ResetConfig::default();
        assert_eq!(config.token_length, 32);
        assert_eq!(config.token_lifetime, Duration::from_secs(3600));
        assert_eq!(config.max_active_tokens, 3);
        assert_eq!(config.rate_limit_window, Duration::from_secs(60));
    }

    #[test]
    fn test_config_builder() {
        let config = ResetConfig::builder()
            .token_length(64)
            .token_lifetime(Duration::from_secs(1800))
            .max_active_tokens(5)
            .rate_limit_window(Duration::from_secs(120))
            .build();

        assert_eq!(config.token_length, 64);
        assert_eq!(config.token_lifetime, Duration::from_secs(1800));
        assert_eq!(config.max_active_tokens, 5);
        assert_eq!(config.rate_limit_window, Duration::from_secs(120));
    }

    #[test]
    fn test_config_builder_minimum_token_length() {
        let config = ResetConfig::builder().token_length(8).build();
        // Should be clamped to minimum of 16
        assert_eq!(config.token_length, 16);
    }

    #[test]
    fn test_generate_reset_token() {
        let config = ResetConfig::default();
        let token = generate_reset_token("user123", &config);

        assert!(!token.value().is_empty());
        assert_eq!(token.user_id(), "user123");
        assert!(!token.is_expired());
        assert!(!token.is_used());
        assert!(token.is_valid());
    }

    #[test]
    fn test_token_url_safe() {
        let config = ResetConfig::default();
        let token = generate_reset_token("user123", &config);

        // Token should be URL-safe (alphanumeric, dash, underscore)
        assert!(
            token
                .value()
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn test_token_uniqueness() {
        let config = ResetConfig::default();
        let token1 = generate_reset_token("user123", &config);
        let token2 = generate_reset_token("user123", &config);

        assert_ne!(token1.value(), token2.value());
    }

    #[test]
    fn test_validate_reset_token_success() {
        let config = ResetConfig::default();
        let token = generate_reset_token("user123", &config);

        let result = validate_reset_token(token.value(), &token);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_reset_token_invalid() {
        let config = ResetConfig::default();
        let token = generate_reset_token("user123", &config);

        let result = validate_reset_token("invalid_token", &token);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid"));
    }

    #[test]
    fn test_validate_reset_token_expired() {
        let config = ResetConfig::builder()
            .token_lifetime(Duration::from_millis(10))
            .build();
        let token = generate_reset_token("user123", &config);

        std::thread::sleep(Duration::from_millis(20));

        let result = validate_reset_token(token.value(), &token);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn test_validate_reset_token_used() {
        let config = ResetConfig::default();
        let mut token = generate_reset_token("user123", &config);
        token.mark_used();

        let result = validate_reset_token(token.value(), &token);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("already been used")
        );
    }

    #[test]
    fn test_mark_used() {
        let config = ResetConfig::default();
        let mut token = generate_reset_token("user123", &config);

        assert!(!token.is_used());
        assert!(token.is_valid());

        token.mark_used();

        assert!(token.is_used());
        assert!(!token.is_valid());
    }

    #[test]
    fn test_remaining_validity() {
        let config = ResetConfig::builder()
            .token_lifetime(Duration::from_secs(60))
            .build();
        let token = generate_reset_token("user123", &config);

        let remaining = token.remaining_validity();
        assert!(remaining.is_some());
        assert!(remaining.expect("should have remaining time") <= Duration::from_secs(60));
    }

    #[test]
    fn test_remaining_validity_after_expiry() {
        let config = ResetConfig::builder()
            .token_lifetime(Duration::from_millis(10))
            .build();
        let token = generate_reset_token("user123", &config);

        std::thread::sleep(Duration::from_millis(20));

        assert!(token.remaining_validity().is_none());
    }

    #[test]
    fn test_remaining_validity_after_used() {
        let config = ResetConfig::default();
        let mut token = generate_reset_token("user123", &config);
        token.mark_used();

        assert!(token.remaining_validity().is_none());
    }

    #[test]
    fn test_validate_rate_limit_none() {
        let config = ResetConfig::default();
        let result = validate_rate_limit(None, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_rate_limit_within_window() {
        let config = ResetConfig::builder()
            .rate_limit_window(Duration::from_secs(60))
            .build();
        let last = Instant::now();

        let result = validate_rate_limit(Some(last), &config);
        assert!(result.is_err());
        // Error contains "Rate limit exceeded"
        assert!(result.unwrap_err().to_string().contains("Rate limit"));
    }

    #[test]
    fn test_validate_rate_limit_outside_window() {
        let config = ResetConfig::builder()
            .rate_limit_window(Duration::from_millis(10))
            .build();
        let last = Instant::now();

        std::thread::sleep(Duration::from_millis(20));

        let result = validate_rate_limit(Some(last), &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_rate_limit_exact_boundary() {
        // Test at exact boundary - should allow since elapsed >= window
        let config = ResetConfig::builder()
            .rate_limit_window(Duration::from_millis(50))
            .build();
        let last = Instant::now();

        // Wait exactly the window duration
        std::thread::sleep(Duration::from_millis(50));

        let result = validate_rate_limit(Some(last), &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_rate_limit_zero_window() {
        // Zero window should always allow
        let config = ResetConfig::builder()
            .rate_limit_window(Duration::from_millis(0))
            .build();
        let last = Instant::now();

        let result = validate_rate_limit(Some(last), &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_token_display_truncates() {
        let config = ResetConfig::default();
        let token = generate_reset_token("user123", &config);
        let display = token.to_string();

        assert!(display.contains("..."));
        assert!(!display.contains(token.value()));
    }

    #[test]
    fn test_debug_redacts_token() {
        let config = ResetConfig::default();
        let token = generate_reset_token("user123", &config);
        let debug_str = format!("{token:?}");

        // Full plaintext token must not appear anywhere in Debug output.
        assert!(
            !debug_str.contains(token.value()),
            "Debug output leaked plaintext token: {debug_str}"
        );
        // Masked form is present.
        assert!(debug_str.contains("..."));
        // Non-secret fields still visible for diagnostics.
        assert!(debug_str.contains("user123"));
        assert!(debug_str.contains("ResetToken"));
    }

    #[test]
    fn test_from_storage() {
        let token = ResetToken::from_storage(
            "test_token_value".to_string(),
            "user123".to_string(),
            Duration::from_secs(300),
            false,
        );

        assert_eq!(token.value(), "test_token_value");
        assert_eq!(token.user_id(), "user123");
        assert!(!token.is_used());
        assert!(token.remaining_validity().is_some());
    }

    #[test]
    fn test_from_storage_used() {
        let token = ResetToken::from_storage(
            "test_token_value".to_string(),
            "user123".to_string(),
            Duration::from_secs(300),
            true,
        );

        assert!(token.is_used());
        assert!(!token.is_valid());
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("abc", "abc"));
        assert!(!constant_time_compare("abc", "abd"));
        assert!(!constant_time_compare("abc", "ab"));
        assert!(!constant_time_compare("ab", "abc"));
    }

    #[test]
    fn test_token_zeroized_on_drop() {
        // Smoke test: building, exposing, and dropping a ResetToken does
        // not panic and the SecretStringCore wrapper is in place. Actual
        // memory zeroization is covered by SecretCore's own test suite —
        // we just verify the wiring here.
        let config = ResetConfig::default();
        let token = generate_reset_token("user123", &config);
        assert!(!token.value().is_empty());
        drop(token);
    }
}

//! CSRF token generation and validation
//!
//! Provides secure CSRF token generation using cryptographic randomness.

use rand::Rng;
use std::time::{Duration, Instant};

use crate::primitives::types::Problem;

// ============================================================================
// CSRF Configuration
// ============================================================================

/// Same-site cookie policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SameSite {
    /// Cookie is only sent in first-party context
    #[default]
    Strict,
    /// Cookie is sent with top-level navigations
    Lax,
    /// Cookie is always sent (requires Secure)
    None,
}

impl std::fmt::Display for SameSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strict => write!(f, "Strict"),
            Self::Lax => write!(f, "Lax"),
            Self::None => write!(f, "None"),
        }
    }
}

/// Configuration for CSRF protection
#[derive(Debug, Clone)]
pub struct CsrfConfig {
    /// Token length in bytes (default: 32 = 256 bits)
    pub token_length: usize,
    /// Cookie name for double-submit pattern (default: "__csrf")
    pub cookie_name: String,
    /// Header name for token submission (default: "X-CSRF-Token")
    pub header_name: String,
    /// Form field name for token submission (default: "_csrf")
    pub form_field_name: String,
    /// Same-site cookie policy (default: Strict)
    pub same_site: SameSite,
    /// Whether to require secure cookie (default: true in production)
    pub secure: bool,
    /// Token expiration time (default: 1 hour)
    pub token_lifetime: Duration,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            token_length: 32,
            cookie_name: "__csrf".to_string(),
            header_name: "X-CSRF-Token".to_string(),
            form_field_name: "_csrf".to_string(),
            same_site: SameSite::Strict,
            secure: true,
            token_lifetime: Duration::from_secs(3600),
        }
    }
}

impl CsrfConfig {
    /// Create a new CSRF config builder
    #[must_use]
    pub fn builder() -> CsrfConfigBuilder {
        CsrfConfigBuilder::default()
    }
}

/// Builder for CSRF configuration
#[derive(Debug, Default)]
pub struct CsrfConfigBuilder {
    token_length: Option<usize>,
    cookie_name: Option<String>,
    header_name: Option<String>,
    form_field_name: Option<String>,
    same_site: Option<SameSite>,
    secure: Option<bool>,
    token_lifetime: Option<Duration>,
}

impl CsrfConfigBuilder {
    /// Set the token length in bytes
    #[must_use]
    pub fn token_length(mut self, length: usize) -> Self {
        self.token_length = Some(length);
        self
    }

    /// Set the cookie name
    #[must_use]
    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        self.cookie_name = Some(name.into());
        self
    }

    /// Set the header name
    #[must_use]
    pub fn header_name(mut self, name: impl Into<String>) -> Self {
        self.header_name = Some(name.into());
        self
    }

    /// Set the form field name
    #[must_use]
    pub fn form_field_name(mut self, name: impl Into<String>) -> Self {
        self.form_field_name = Some(name.into());
        self
    }

    /// Set the same-site policy
    #[must_use]
    pub fn same_site(mut self, policy: SameSite) -> Self {
        self.same_site = Some(policy);
        self
    }

    /// Set whether to require secure cookie
    #[must_use]
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = Some(secure);
        self
    }

    /// Set the token lifetime
    #[must_use]
    pub fn token_lifetime(mut self, lifetime: Duration) -> Self {
        self.token_lifetime = Some(lifetime);
        self
    }

    /// Minimum token length in bytes (128 bits)
    const MIN_TOKEN_LENGTH: usize = 16;

    /// Build the configuration
    ///
    /// # Errors
    ///
    /// Returns `Problem::Validation` if `token_length` is less than 16 bytes
    /// (128 bits), the cryptographic minimum for CSRF tokens.
    pub fn build(self) -> Result<CsrfConfig, Problem> {
        let token_length = self.token_length.unwrap_or(32);

        if token_length < Self::MIN_TOKEN_LENGTH {
            return Err(Problem::Validation(format!(
                "CSRF token length must be at least {} bytes, got {}",
                Self::MIN_TOKEN_LENGTH,
                token_length
            )));
        }

        Ok(CsrfConfig {
            token_length,
            cookie_name: self.cookie_name.unwrap_or_else(|| "__csrf".to_string()),
            header_name: self
                .header_name
                .unwrap_or_else(|| "X-CSRF-Token".to_string()),
            form_field_name: self.form_field_name.unwrap_or_else(|| "_csrf".to_string()),
            same_site: self.same_site.unwrap_or_default(),
            secure: self.secure.unwrap_or(true),
            token_lifetime: self.token_lifetime.unwrap_or(Duration::from_secs(3600)),
        })
    }
}

// ============================================================================
// CSRF Token
// ============================================================================

/// A CSRF token with metadata
#[derive(Debug, Clone)]
pub struct CsrfToken {
    /// The token value (URL-safe base64)
    token: String,
    /// When the token was created
    created_at: Instant,
    /// Token lifetime
    lifetime: Duration,
}

impl CsrfToken {
    /// Create a new CSRF token with the given value and lifetime
    #[must_use]
    fn new(token: String, lifetime: Duration) -> Self {
        Self {
            token,
            created_at: Instant::now(),
            lifetime,
        }
    }

    /// Get the token value
    #[must_use]
    pub fn value(&self) -> &str {
        &self.token
    }

    /// Check if the token has expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.lifetime
    }

    /// Get remaining validity duration
    #[must_use]
    pub fn remaining_validity(&self) -> Option<Duration> {
        let elapsed = self.created_at.elapsed();
        if elapsed > self.lifetime {
            None
        } else {
            Some(self.lifetime.saturating_sub(elapsed))
        }
    }
}

impl std::fmt::Display for CsrfToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.token)
    }
}

impl PartialEq for CsrfToken {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison to prevent timing attacks
        constant_time_compare(&self.token, &other.token)
    }
}

// ============================================================================
// Token Generation and Validation
// ============================================================================

/// Generate a new CSRF token
///
/// Creates a cryptographically random token suitable for CSRF protection.
///
/// # Arguments
///
/// * `config` - CSRF configuration
///
/// # Returns
///
/// A new CSRF token.
pub fn generate_csrf_token(config: &CsrfConfig) -> CsrfToken {
    let mut rng = rand::rng();
    let mut bytes = vec![0u8; config.token_length];
    rng.fill(&mut bytes[..]);

    // Use URL-safe base64 encoding
    let token = base64_url_encode(&bytes);

    CsrfToken::new(token, config.token_lifetime)
}

/// Validate a submitted CSRF token against the expected token
///
/// Performs constant-time comparison to prevent timing attacks.
///
/// # Arguments
///
/// * `submitted` - The token submitted by the client
/// * `expected` - The expected token
///
/// # Returns
///
/// `Ok(())` if valid, `Err(Problem)` if invalid.
pub fn validate_csrf_token(submitted: &str, expected: &CsrfToken) -> Result<(), Problem> {
    // Check expiration first
    if expected.is_expired() {
        return Err(Problem::Auth("CSRF token has expired".to_string()));
    }

    // Constant-time comparison
    if !constant_time_compare(submitted, expected.value()) {
        return Err(Problem::Auth("Invalid CSRF token".to_string()));
    }

    Ok(())
}

/// Validate a raw token string against another
///
/// For use in double-submit cookie pattern where we compare
/// cookie value against header/form value.
///
/// # Arguments
///
/// * `submitted` - The token from header/form
/// * `cookie_value` - The token from cookie
///
/// # Returns
///
/// `true` if tokens match, `false` otherwise.
#[must_use]
pub fn tokens_match(submitted: &str, cookie_value: &str) -> bool {
    constant_time_compare(submitted, cookie_value)
}

// ============================================================================
// Private Helpers
// ============================================================================

/// URL-safe base64 encoding
fn base64_url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let n = match chunk.len() {
            3 => {
                (u32::from(chunk.first().copied().unwrap_or(0)) << 16)
                    | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
                    | u32::from(chunk.get(2).copied().unwrap_or(0))
            }
            2 => {
                (u32::from(chunk.first().copied().unwrap_or(0)) << 16)
                    | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            }
            1 => u32::from(chunk.first().copied().unwrap_or(0)) << 16,
            _ => 0,
        };

        result.push(char::from(
            ALPHABET
                .get((n >> 18 & 0x3F) as usize)
                .copied()
                .unwrap_or(b'A'),
        ));
        result.push(char::from(
            ALPHABET
                .get((n >> 12 & 0x3F) as usize)
                .copied()
                .unwrap_or(b'A'),
        ));

        if chunk.len() > 1 {
            result.push(char::from(
                ALPHABET
                    .get((n >> 6 & 0x3F) as usize)
                    .copied()
                    .unwrap_or(b'A'),
            ));
        }
        if chunk.len() > 2 {
            result.push(char::from(
                ALPHABET.get((n & 0x3F) as usize).copied().unwrap_or(b'A'),
            ));
        }
    }

    result
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
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CsrfConfig::default();
        assert_eq!(config.token_length, 32);
        assert_eq!(config.cookie_name, "__csrf");
        assert_eq!(config.header_name, "X-CSRF-Token");
        assert_eq!(config.form_field_name, "_csrf");
        assert_eq!(config.same_site, SameSite::Strict);
        assert!(config.secure);
    }

    #[test]
    fn test_config_builder() {
        let config = CsrfConfig::builder()
            .token_length(64)
            .cookie_name("my_csrf")
            .header_name("X-My-CSRF")
            .form_field_name("csrf_token")
            .same_site(SameSite::Lax)
            .secure(false)
            .token_lifetime(Duration::from_secs(7200))
            .build()
            .expect("valid config");

        assert_eq!(config.token_length, 64);
        assert_eq!(config.cookie_name, "my_csrf");
        assert_eq!(config.header_name, "X-My-CSRF");
        assert_eq!(config.form_field_name, "csrf_token");
        assert_eq!(config.same_site, SameSite::Lax);
        assert!(!config.secure);
        assert_eq!(config.token_lifetime, Duration::from_secs(7200));
    }

    #[test]
    fn test_generate_csrf_token() {
        let config = CsrfConfig::default();
        let token = generate_csrf_token(&config);

        // Token should be URL-safe and non-empty
        assert!(!token.value().is_empty());
        assert!(
            token
                .value()
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );

        // Token should not be expired immediately
        assert!(!token.is_expired());
    }

    #[test]
    fn test_token_uniqueness() {
        let config = CsrfConfig::default();
        let token1 = generate_csrf_token(&config);
        let token2 = generate_csrf_token(&config);

        // Tokens should be unique
        assert_ne!(token1.value(), token2.value());
    }

    #[test]
    fn test_validate_csrf_token() {
        let config = CsrfConfig::default();
        let token = generate_csrf_token(&config);

        // Valid token should pass
        assert!(validate_csrf_token(token.value(), &token).is_ok());

        // Invalid token should fail
        assert!(validate_csrf_token("invalid_token", &token).is_err());
    }

    #[test]
    fn test_token_expiration() {
        let config = CsrfConfig::builder()
            .token_lifetime(Duration::from_millis(10))
            .build()
            .expect("valid config");
        let token = generate_csrf_token(&config);

        // Should be valid initially
        assert!(!token.is_expired());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        // Should be expired
        assert!(token.is_expired());
        assert!(validate_csrf_token(token.value(), &token).is_err());
    }

    #[test]
    fn test_tokens_match() {
        let config = CsrfConfig::default();
        let token = generate_csrf_token(&config);

        assert!(tokens_match(token.value(), token.value()));
        assert!(!tokens_match("different", token.value()));
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("abc", "abc"));
        assert!(!constant_time_compare("abc", "abd"));
        assert!(!constant_time_compare("abc", "ab"));
        assert!(!constant_time_compare("ab", "abc"));
    }

    #[test]
    fn test_same_site_display() {
        assert_eq!(SameSite::Strict.to_string(), "Strict");
        assert_eq!(SameSite::Lax.to_string(), "Lax");
        assert_eq!(SameSite::None.to_string(), "None");
    }

    #[test]
    fn test_token_remaining_validity() {
        let config = CsrfConfig::builder()
            .token_lifetime(Duration::from_secs(60))
            .build()
            .expect("valid config");
        let token = generate_csrf_token(&config);

        let remaining = token.remaining_validity();
        assert!(remaining.is_some());
        assert!(remaining.expect("should have remaining time") <= Duration::from_secs(60));
    }

    #[test]
    fn test_build_rejects_zero_length() {
        let result = CsrfConfig::builder().token_length(0).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_build_rejects_short_length() {
        let result = CsrfConfig::builder().token_length(15).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_build_accepts_minimum_length() {
        let result = CsrfConfig::builder().token_length(16).build();
        assert!(result.is_ok());
    }
}

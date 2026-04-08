//! CSRF protection with observe integration
//!
//! Provides CSRF protection operations with audit logging.

use crate::observe;
use crate::primitives::auth::csrf::{
    CsrfConfig, CsrfToken, generate_csrf_token, tokens_match, validate_csrf_token,
};
use crate::primitives::types::Problem;

// ============================================================================
// CSRF Protection
// ============================================================================

/// CSRF protection manager with audit logging
///
/// Provides CSRF token generation and validation with compliance-grade
/// audit trails.
pub struct CsrfProtection {
    /// CSRF configuration
    config: CsrfConfig,
}

impl CsrfProtection {
    /// Create a new CSRF protection instance with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: CsrfConfig::default(),
        }
    }

    /// Create a new CSRF protection instance with custom configuration
    #[must_use]
    pub fn with_config(config: CsrfConfig) -> Self {
        Self { config }
    }

    /// Generate a new CSRF token
    ///
    /// # Audit Events
    ///
    /// - `auth.csrf.token_generated` (DEBUG)
    #[must_use]
    pub fn generate_token(&self) -> CsrfToken {
        let token = generate_csrf_token(&self.config);

        observe::debug("auth.csrf.token_generated", "New CSRF token generated");

        token
    }

    /// Validate a CSRF token using synchronizer token pattern
    ///
    /// Compares the submitted token against a server-stored expected token.
    ///
    /// # Arguments
    ///
    /// * `submitted` - The token submitted by the client
    /// * `expected` - The expected token (stored server-side)
    ///
    /// # Audit Events
    ///
    /// - `auth.csrf.validation_success` (DEBUG) on success
    /// - `auth.csrf.validation_failed` (WARN) on failure
    pub fn validate(&self, submitted: &str, expected: &CsrfToken) -> Result<(), Problem> {
        let result = validate_csrf_token(submitted, expected);

        match &result {
            Ok(()) => {
                observe::debug(
                    "auth.csrf.validation_success",
                    "CSRF token validation successful",
                );
            }
            Err(e) => {
                observe::warn(
                    "auth.csrf.validation_failed",
                    format!("CSRF token validation failed: {}", e),
                );
            }
        }

        result
    }

    /// Validate using double-submit cookie pattern
    ///
    /// Compares the token from a header/form against the token from a cookie.
    /// Both tokens should have been set from the same origin.
    ///
    /// # Arguments
    ///
    /// * `submitted` - The token from header or form
    /// * `cookie_value` - The token from the cookie
    ///
    /// # Audit Events
    ///
    /// - `auth.csrf.validation_success` (DEBUG) on success
    /// - `auth.csrf.validation_failed` (WARN) on failure
    pub fn validate_double_submit(
        &self,
        submitted: &str,
        cookie_value: &str,
    ) -> Result<(), Problem> {
        if tokens_match(submitted, cookie_value) {
            observe::debug(
                "auth.csrf.validation_success",
                "Double-submit CSRF validation successful",
            );
            Ok(())
        } else {
            observe::warn(
                "auth.csrf.validation_failed",
                "Double-submit CSRF validation failed: tokens do not match",
            );
            Err(Problem::Auth("CSRF token mismatch".to_string()))
        }
    }

    /// Check if a request method requires CSRF validation
    ///
    /// GET, HEAD, OPTIONS are considered safe methods that don't need CSRF.
    #[must_use]
    pub fn requires_validation(&self, method: &str) -> bool {
        let method_upper = method.to_uppercase();
        !matches!(method_upper.as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE")
    }

    /// Get the configuration
    #[must_use]
    pub fn config(&self) -> &CsrfConfig {
        &self.config
    }

    /// Get the cookie name for double-submit pattern
    #[must_use]
    pub fn cookie_name(&self) -> &str {
        &self.config.cookie_name
    }

    /// Get the header name for token submission
    #[must_use]
    pub fn header_name(&self) -> &str {
        &self.config.header_name
    }

    /// Get the form field name for token submission
    #[must_use]
    pub fn form_field_name(&self) -> &str {
        &self.config.form_field_name
    }

    /// Generate a cookie header value for the token
    ///
    /// Returns a string suitable for the Set-Cookie header.
    #[must_use]
    pub fn cookie_header_value(&self, token: &CsrfToken) -> String {
        let mut cookie = format!("{}={}", self.config.cookie_name, token.value());

        cookie.push_str("; Path=/");
        cookie.push_str("; HttpOnly");

        if self.config.secure {
            cookie.push_str("; Secure");
        }

        cookie.push_str(&format!("; SameSite={}", self.config.same_site));

        cookie
    }
}

impl Default for CsrfProtection {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token() {
        let csrf = CsrfProtection::new();
        let token = csrf.generate_token();

        assert!(!token.value().is_empty());
    }

    #[test]
    fn test_validate_success() {
        let csrf = CsrfProtection::new();
        let token = csrf.generate_token();

        let result = csrf.validate(token.value(), &token);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_failure() {
        let csrf = CsrfProtection::new();
        let token = csrf.generate_token();

        let result = csrf.validate("wrong_token", &token);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_double_submit_success() {
        let csrf = CsrfProtection::new();
        let token = csrf.generate_token();
        let token_value = token.value().to_string();

        let result = csrf.validate_double_submit(&token_value, &token_value);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_double_submit_failure() {
        let csrf = CsrfProtection::new();

        let result = csrf.validate_double_submit("token1", "token2");
        assert!(result.is_err());
    }

    #[test]
    fn test_requires_validation() {
        let csrf = CsrfProtection::new();

        // Safe methods don't require validation
        assert!(!csrf.requires_validation("GET"));
        assert!(!csrf.requires_validation("get"));
        assert!(!csrf.requires_validation("HEAD"));
        assert!(!csrf.requires_validation("OPTIONS"));
        assert!(!csrf.requires_validation("TRACE"));

        // Unsafe methods require validation
        assert!(csrf.requires_validation("POST"));
        assert!(csrf.requires_validation("PUT"));
        assert!(csrf.requires_validation("DELETE"));
        assert!(csrf.requires_validation("PATCH"));
    }

    #[test]
    fn test_cookie_header_value() {
        let csrf = CsrfProtection::new();
        let token = csrf.generate_token();

        let cookie = csrf.cookie_header_value(&token);

        assert!(cookie.contains("__csrf="));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
    }

    #[test]
    fn test_cookie_header_no_secure() {
        let config = CsrfConfig::builder()
            .secure(false)
            .build()
            .expect("valid config");
        let csrf = CsrfProtection::with_config(config);
        let token = csrf.generate_token();

        let cookie = csrf.cookie_header_value(&token);

        assert!(!cookie.contains("Secure"));
    }

    #[test]
    fn test_accessors() {
        let config = CsrfConfig::builder()
            .cookie_name("my_csrf")
            .header_name("X-My-CSRF")
            .form_field_name("csrf_field")
            .build()
            .expect("valid config");
        let csrf = CsrfProtection::with_config(config);

        assert_eq!(csrf.cookie_name(), "my_csrf");
        assert_eq!(csrf.header_name(), "X-My-CSRF");
        assert_eq!(csrf.form_field_name(), "csrf_field");
    }

    #[test]
    fn test_validate_double_submit_empty_strings() {
        let csrf = CsrfProtection::new();

        // Two empty strings should match (constant-time compare of equal values)
        let result = csrf.validate_double_submit("", "");
        assert!(result.is_ok());

        // Empty vs non-empty should fail
        let result = csrf.validate_double_submit("", "some_token");
        assert!(result.is_err());

        // Non-empty vs empty should fail
        let result = csrf.validate_double_submit("some_token", "");
        assert!(result.is_err());
    }
}

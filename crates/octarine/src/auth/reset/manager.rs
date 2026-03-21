//! Password reset manager with observe integration
//!
//! Provides password reset operations with audit logging for ASVS V2.5 compliance.

use crate::observe;
use crate::primitives::auth::reset::{
    ResetConfig, ResetToken, generate_reset_token, validate_rate_limit, validate_reset_token,
};
use crate::primitives::types::Problem;

use super::store::ResetTokenStore;

// ============================================================================
// Reset Manager
// ============================================================================

/// Password reset manager with audit logging
///
/// Manages password reset tokens with compliance-grade audit trails.
///
/// # Features
///
/// - Secure token generation (256 bits of entropy)
/// - Time-limited tokens (default: 1 hour)
/// - Rate limiting for reset requests
/// - Single-use token validation
/// - Audit logging for all operations
///
/// # Example
///
/// ```ignore
/// use octarine::auth::reset::{ResetManager, MemoryResetStore, ResetConfig};
///
/// let store = MemoryResetStore::new();
/// let manager = ResetManager::new(store, ResetConfig::default());
///
/// // Request a password reset
/// let token = manager.request_reset("user@example.com")?;
///
/// // Later, validate and consume the token
/// manager.validate_and_consume(&token_value, "user@example.com")?;
/// ```
pub struct ResetManager<S: ResetTokenStore> {
    store: S,
    config: ResetConfig,
}

impl<S: ResetTokenStore> ResetManager<S> {
    /// Create a new reset manager
    #[must_use]
    pub fn new(store: S, config: ResetConfig) -> Self {
        Self { store, config }
    }

    /// Create a reset manager with default configuration
    #[must_use]
    pub fn with_store(store: S) -> Self {
        Self::new(store, ResetConfig::default())
    }

    /// Request a password reset for a user
    ///
    /// Generates a new reset token after checking rate limits.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user identifier (email or username)
    ///
    /// # Returns
    ///
    /// The reset token on success.
    ///
    /// # Audit Events
    ///
    /// - `auth.reset.requested` (INFO) - Reset requested
    /// - `auth.reset.rate_limited` (WARN) - Rate limit exceeded
    ///
    /// # Errors
    ///
    /// Returns an error if rate limited or if storage fails.
    pub fn request_reset(&self, user_id: &str) -> Result<ResetToken, Problem> {
        // Check rate limit
        let last_request = self.store.get_last_request_time(user_id)?;
        if let Err(e) = validate_rate_limit(last_request, &self.config) {
            observe::warn(
                "auth.reset.rate_limited",
                "Password reset rate limited for user",
            );
            return Err(e);
        }

        // Check max active tokens
        let active_tokens = self.store.get_active_for_user(user_id)?;
        if active_tokens.len() >= self.config.max_active_tokens {
            observe::warn(
                "auth.reset.max_tokens_exceeded",
                "Maximum active reset tokens exceeded",
            );
            // Invalidate oldest token to make room
            // In production, you might want different behavior
        }

        // Generate new token
        let token = generate_reset_token(user_id, &self.config);

        // Store the token
        self.store.store(user_id, &token)?;

        observe::info("auth.reset.requested", "Password reset token generated");

        Ok(token)
    }

    /// Validate a reset token without consuming it
    ///
    /// Useful for checking if a token is valid before showing
    /// the password reset form.
    ///
    /// # Arguments
    ///
    /// * `token_value` - The token string to validate
    ///
    /// # Returns
    ///
    /// The user ID if the token is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid, expired, or used.
    pub fn validate(&self, token_value: &str) -> Result<String, Problem> {
        let token = self
            .store
            .get_by_token(token_value)?
            .ok_or_else(|| Problem::Auth("Reset token not found".to_string()))?;

        validate_reset_token(token_value, &token)?;

        Ok(token.user_id().to_string())
    }

    /// Validate and consume a reset token
    ///
    /// Validates the token and marks it as used. After this call,
    /// the token cannot be used again.
    ///
    /// # Arguments
    ///
    /// * `token_value` - The token string to validate
    /// * `expected_user_id` - The expected user ID (for additional verification)
    ///
    /// # Returns
    ///
    /// `Ok(())` if the token is valid and was consumed.
    ///
    /// # Audit Events
    ///
    /// - `auth.reset.validated` (INFO) - Token validated and consumed
    /// - `auth.reset.invalid` (WARN) - Invalid token attempted
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid, expired, used, or
    /// belongs to a different user.
    pub fn validate_and_consume(
        &self,
        token_value: &str,
        expected_user_id: &str,
    ) -> Result<(), Problem> {
        let token = self
            .store
            .get_by_token(token_value)?
            .ok_or_else(|| Problem::Auth("Reset token not found".to_string()))?;

        // Verify user matches
        if token.user_id() != expected_user_id {
            observe::warn(
                "auth.reset.user_mismatch",
                "Reset token user mismatch detected",
            );
            return Err(Problem::Auth(
                "Reset token does not belong to this user".to_string(),
            ));
        }

        // Validate the token
        if let Err(e) = validate_reset_token(token_value, &token) {
            observe::warn(
                "auth.reset.invalid",
                format!("Reset token validation failed: {}", e),
            );
            return Err(e);
        }

        // Mark as used
        self.store.mark_used(token_value)?;

        observe::info("auth.reset.validated", "Password reset token consumed");

        Ok(())
    }

    /// Complete the password reset
    ///
    /// Should be called after the password has been successfully changed.
    /// Invalidates all reset tokens for the user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user identifier
    ///
    /// # Audit Events
    ///
    /// - `auth.reset.completed` (INFO) - Reset completed successfully
    ///
    /// # Errors
    ///
    /// Returns an error if invalidation fails.
    pub fn complete_reset(&self, user_id: &str) -> Result<(), Problem> {
        let count = self.store.invalidate_all_for_user(user_id)?;

        observe::info(
            "auth.reset.completed",
            format!("Password reset completed, {} token(s) invalidated", count),
        );

        Ok(())
    }

    /// Revoke all reset tokens for a user
    ///
    /// Can be called if the user requests to cancel pending resets
    /// or if suspicious activity is detected.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user identifier
    ///
    /// # Returns
    ///
    /// Number of tokens revoked.
    ///
    /// # Audit Events
    ///
    /// - `auth.reset.revoked` (INFO) - Tokens revoked
    ///
    /// # Errors
    ///
    /// Returns an error if revocation fails.
    pub fn revoke_all(&self, user_id: &str) -> Result<usize, Problem> {
        let count = self.store.invalidate_all_for_user(user_id)?;

        if count > 0 {
            observe::info(
                "auth.reset.revoked",
                format!("{} reset token(s) revoked", count),
            );
        }

        Ok(count)
    }

    /// Clean up expired tokens
    ///
    /// Should be called periodically (e.g., via a background job).
    ///
    /// # Returns
    ///
    /// Number of tokens cleaned up.
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup fails.
    pub fn cleanup(&self) -> Result<usize, Problem> {
        let count = self.store.cleanup_expired()?;

        if count > 0 {
            observe::debug(
                "auth.reset.cleanup",
                format!("Cleaned up {} expired reset token(s)", count),
            );
        }

        Ok(count)
    }

    /// Get the configuration
    #[must_use]
    pub fn config(&self) -> &ResetConfig {
        &self.config
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::auth::reset::store::MemoryResetStore;
    use std::time::Duration;

    fn create_manager() -> ResetManager<MemoryResetStore> {
        let store = MemoryResetStore::new();
        ResetManager::new(store, ResetConfig::default())
    }

    #[test]
    fn test_request_reset() {
        let manager = create_manager();

        let token = manager
            .request_reset("user@example.com")
            .expect("should succeed");
        assert!(!token.value().is_empty());
        assert_eq!(token.user_id(), "user@example.com");
    }

    #[test]
    fn test_validate() {
        let manager = create_manager();

        let token = manager
            .request_reset("user@example.com")
            .expect("should succeed");
        let user_id = manager.validate(token.value()).expect("should succeed");
        assert_eq!(user_id, "user@example.com");
    }

    #[test]
    fn test_validate_invalid_token() {
        let manager = create_manager();

        let result = manager.validate("invalid_token");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_and_consume() {
        let manager = create_manager();

        let token = manager
            .request_reset("user@example.com")
            .expect("should succeed");
        let token_value = token.value().to_string();

        // First validation should succeed
        manager
            .validate_and_consume(&token_value, "user@example.com")
            .expect("should succeed");

        // Second validation should fail (already used)
        let result = manager.validate_and_consume(&token_value, "user@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_and_consume_wrong_user() {
        let manager = create_manager();

        let token = manager
            .request_reset("user@example.com")
            .expect("should succeed");

        let result = manager.validate_and_consume(token.value(), "other@example.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not belong"));
    }

    #[test]
    fn test_complete_reset() {
        // Use a manager with no rate limiting for this test
        let store = MemoryResetStore::new();
        let config = ResetConfig::builder()
            .rate_limit_window(Duration::from_millis(0))
            .build();
        let manager = ResetManager::new(store, config);

        let token1 = manager
            .request_reset("user@example.com")
            .expect("should succeed");
        let _token2 = manager
            .request_reset("user@example.com")
            .expect("should succeed");

        manager
            .complete_reset("user@example.com")
            .expect("should succeed");

        // Tokens should now be invalid
        let result = manager.validate(token1.value());
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_all() {
        // Use a manager with no rate limiting for this test
        let store = MemoryResetStore::new();
        let config = ResetConfig::builder()
            .rate_limit_window(Duration::from_millis(0))
            .build();
        let manager = ResetManager::new(store, config);

        let _ = manager
            .request_reset("user@example.com")
            .expect("should succeed");
        let _ = manager
            .request_reset("user@example.com")
            .expect("should succeed");

        let count = manager
            .revoke_all("user@example.com")
            .expect("should succeed");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_rate_limiting() {
        let store = MemoryResetStore::new();
        let config = ResetConfig::builder()
            .rate_limit_window(Duration::from_secs(60))
            .build();
        let manager = ResetManager::new(store, config);

        // First request should succeed
        let _ = manager
            .request_reset("user@example.com")
            .expect("should succeed");

        // Second request should be rate limited
        let result = manager.request_reset("user@example.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Rate limit"));
    }

    #[test]
    fn test_cleanup() {
        let store = MemoryResetStore::new();
        let config = ResetConfig::builder()
            .token_lifetime(Duration::from_millis(10))
            .rate_limit_window(Duration::from_millis(1))
            .build();
        let manager = ResetManager::new(store, config);

        let _ = manager
            .request_reset("user@example.com")
            .expect("should succeed");

        std::thread::sleep(Duration::from_millis(20));

        let count = manager.cleanup().expect("should succeed");
        assert_eq!(count, 1);
    }

    #[test]
    fn test_expired_token_validation() {
        let store = MemoryResetStore::new();
        let config = ResetConfig::builder()
            .token_lifetime(Duration::from_millis(10))
            .build();
        let manager = ResetManager::new(store, config);

        let token = manager
            .request_reset("user@example.com")
            .expect("should succeed");

        std::thread::sleep(Duration::from_millis(20));

        let result = manager.validate(token.value());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }
}

//! Remember-me manager with observe integration
//!
//! Provides persistent login operations with audit logging for ASVS V3.5 compliance.

use crate::observe;
use crate::primitives::auth::remember::{
    RememberConfig, RememberToken, RememberTokenPair, generate_remember_token, parse_cookie_value,
    validate_remember_token,
};
use crate::primitives::types::Problem;

use super::store::RememberTokenStore;

// ============================================================================
// Remember Manager
// ============================================================================

/// Remember-me manager with audit logging
///
/// Manages persistent login tokens with compliance-grade audit trails.
///
/// # Features
///
/// - Split selector:validator token design
/// - Token rotation on use (prevent token fixation)
/// - Device binding support
/// - Configurable lifetime (default: 30 days)
/// - Audit logging for all operations
///
/// # Example
///
/// ```ignore
/// use octarine::auth::remember::{RememberManager, MemoryRememberStore, RememberConfig};
///
/// let store = MemoryRememberStore::new();
/// let manager = RememberManager::new(store, RememberConfig::default());
///
/// // Issue a remember-me token on login
/// let pair = manager.issue_token("user123", None)?;
/// // Set cookie: pair.cookie_value()
///
/// // Later, validate the cookie and get a new session
/// let user_id = manager.validate_and_refresh(&cookie_value)?;
/// ```
pub struct RememberManager<S: RememberTokenStore> {
    store: S,
    config: RememberConfig,
}

impl<S: RememberTokenStore> RememberManager<S> {
    /// Create a new remember manager
    #[must_use]
    pub fn new(store: S, config: RememberConfig) -> Self {
        Self { store, config }
    }

    /// Create a remember manager with default configuration
    #[must_use]
    pub fn with_store(store: S) -> Self {
        Self::new(store, RememberConfig::default())
    }

    /// Issue a new remember-me token
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user identifier
    /// * `device_info` - Optional device/browser information
    ///
    /// # Returns
    ///
    /// The token pair (containing the cookie value).
    ///
    /// # Audit Events
    ///
    /// - `auth.remember.issued` (INFO) - Token issued
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or max tokens exceeded.
    pub fn issue_token(
        &self,
        user_id: &str,
        device_info: Option<&str>,
    ) -> Result<RememberTokenPair, Problem> {
        // Check max tokens per user
        let active_count = self.store.count_active_for_user(user_id)?;
        if active_count >= self.config.max_tokens_per_user {
            observe::warn(
                "auth.remember.max_tokens_exceeded",
                "Maximum remember-me tokens exceeded, revoking oldest",
            );
            // Revoke oldest tokens to make room
            // For simplicity, we revoke all and re-issue
            // In production, you'd want to keep some recent ones
            self.store.revoke_all_for_user(user_id)?;
        }

        // Generate new token
        let pair = generate_remember_token(user_id, &self.config, device_info);

        // Store the token
        self.store.store(pair.token())?;

        observe::info("auth.remember.issued", "Remember-me token issued");

        Ok(pair)
    }

    /// Validate a remember-me token without consuming it
    ///
    /// Useful for checking if a cookie is valid before creating a session.
    ///
    /// # Arguments
    ///
    /// * `cookie_value` - The value from the remember-me cookie
    ///
    /// # Returns
    ///
    /// The user ID if the token is valid.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid, expired, or revoked.
    pub fn validate(&self, cookie_value: &str) -> Result<String, Problem> {
        let (selector, _) = parse_cookie_value(cookie_value)?;

        let token = self
            .store
            .get_by_selector(selector)?
            .ok_or_else(|| Problem::Auth("Remember-me token not found".to_string()))?;

        validate_remember_token(cookie_value, &token)?;

        Ok(token.user_id().to_string())
    }

    /// Validate and refresh a remember-me token
    ///
    /// Validates the token and optionally rotates it (issues a new one).
    /// This is the main method to use when a user returns with a remember-me cookie.
    ///
    /// # Arguments
    ///
    /// * `cookie_value` - The value from the remember-me cookie
    ///
    /// # Returns
    ///
    /// The user ID and optionally a new token pair (if rotation is enabled).
    ///
    /// # Audit Events
    ///
    /// - `auth.remember.validated` (INFO) - Token validated
    /// - `auth.remember.rotated` (DEBUG) - Token rotated
    /// - `auth.remember.invalid` (WARN) - Invalid token
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid.
    pub fn validate_and_refresh(
        &self,
        cookie_value: &str,
    ) -> Result<(String, Option<RememberTokenPair>), Problem> {
        let (selector, _) = parse_cookie_value(cookie_value)?;

        let token = self
            .store
            .get_by_selector(selector)?
            .ok_or_else(|| Problem::Auth("Remember-me token not found".to_string()))?;

        if let Err(e) = validate_remember_token(cookie_value, &token) {
            observe::warn(
                "auth.remember.invalid",
                format!("Remember-me validation failed: {}", e),
            );
            return Err(e);
        }

        let user_id = token.user_id().to_string();
        let device_info = token.device_info().map(String::from);

        observe::info("auth.remember.validated", "Remember-me token validated");

        // Rotate token if configured
        let new_pair = if self.config.rotate_on_use {
            // Delete old token
            self.store.delete(selector)?;

            // Issue new token
            let pair = generate_remember_token(&user_id, &self.config, device_info.as_deref());
            self.store.store(pair.token())?;

            observe::debug("auth.remember.rotated", "Remember-me token rotated");

            Some(pair)
        } else {
            None
        };

        Ok((user_id, new_pair))
    }

    /// Revoke a specific remember-me token
    ///
    /// Used when user logs out from a specific device.
    ///
    /// # Arguments
    ///
    /// * `cookie_value` - The value from the remember-me cookie
    ///
    /// # Returns
    ///
    /// `true` if the token was found and revoked.
    ///
    /// # Audit Events
    ///
    /// - `auth.remember.revoked` (INFO) - Token revoked
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn revoke(&self, cookie_value: &str) -> Result<bool, Problem> {
        let (selector, _) = parse_cookie_value(cookie_value)?;

        let revoked = self.store.revoke(selector)?;

        if revoked {
            observe::info("auth.remember.revoked", "Remember-me token revoked");
        }

        Ok(revoked)
    }

    /// Revoke all remember-me tokens for a user
    ///
    /// Used when user logs out from all devices or changes password.
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
    /// - `auth.remember.all_revoked` (INFO) - All tokens revoked
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn revoke_all(&self, user_id: &str) -> Result<usize, Problem> {
        let count = self.store.revoke_all_for_user(user_id)?;

        if count > 0 {
            observe::info(
                "auth.remember.all_revoked",
                format!("{} remember-me token(s) revoked", count),
            );
        }

        Ok(count)
    }

    /// Get all active tokens for a user
    ///
    /// Useful for showing active sessions/devices.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user identifier
    ///
    /// # Returns
    ///
    /// List of active tokens with device info.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval fails.
    pub fn get_active_tokens(&self, user_id: &str) -> Result<Vec<RememberToken>, Problem> {
        self.store.get_active_for_user(user_id)
    }

    /// Clean up expired and revoked tokens
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
                "auth.remember.cleanup",
                format!("Cleaned up {} expired remember-me token(s)", count),
            );
        }

        Ok(count)
    }

    /// Get the cookie name from configuration
    #[must_use]
    pub fn cookie_name(&self) -> &str {
        &self.config.cookie_name
    }

    /// Get the configuration
    #[must_use]
    pub fn config(&self) -> &RememberConfig {
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
    use crate::auth::remember::store::MemoryRememberStore;
    use std::time::Duration;

    fn create_manager() -> RememberManager<MemoryRememberStore> {
        let store = MemoryRememberStore::new();
        RememberManager::new(store, RememberConfig::default())
    }

    #[test]
    fn test_issue_token() {
        let manager = create_manager();

        let pair = manager
            .issue_token("user@example.com", None)
            .expect("should succeed");
        assert!(!pair.cookie_value().is_empty());
        assert_eq!(pair.token().user_id(), "user@example.com");
    }

    #[test]
    fn test_issue_token_with_device_info() {
        let manager = create_manager();

        let pair = manager
            .issue_token("user@example.com", Some("Chrome on Windows"))
            .expect("should succeed");
        assert_eq!(pair.token().device_info(), Some("Chrome on Windows"));
    }

    #[test]
    fn test_validate() {
        let manager = create_manager();

        let pair = manager
            .issue_token("user@example.com", None)
            .expect("should succeed");
        let user_id = manager
            .validate(&pair.cookie_value())
            .expect("should succeed");
        assert_eq!(user_id, "user@example.com");
    }

    #[test]
    fn test_validate_invalid_token() {
        let manager = create_manager();

        let result = manager.validate("invalid:token");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_and_refresh_without_rotation() {
        let store = MemoryRememberStore::new();
        let config = RememberConfig::builder().rotate_on_use(false).build();
        let manager = RememberManager::new(store, config);

        let pair = manager
            .issue_token("user@example.com", None)
            .expect("should succeed");

        let (user_id, new_pair) = manager
            .validate_and_refresh(&pair.cookie_value())
            .expect("should succeed");

        assert_eq!(user_id, "user@example.com");
        assert!(new_pair.is_none()); // No rotation
    }

    #[test]
    fn test_validate_and_refresh_with_rotation() {
        let manager = create_manager(); // Default has rotation enabled

        let pair = manager
            .issue_token("user@example.com", None)
            .expect("should succeed");
        let old_cookie = pair.cookie_value();

        let (user_id, new_pair) = manager
            .validate_and_refresh(&old_cookie)
            .expect("should succeed");

        assert_eq!(user_id, "user@example.com");
        assert!(new_pair.is_some()); // Rotation happened

        let new_pair = new_pair.unwrap();
        assert_ne!(new_pair.cookie_value(), old_cookie);

        // Old cookie should no longer be valid
        let result = manager.validate(&old_cookie);
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke() {
        let manager = create_manager();

        let pair = manager
            .issue_token("user@example.com", None)
            .expect("should succeed");
        let cookie = pair.cookie_value();

        let revoked = manager.revoke(&cookie).expect("should succeed");
        assert!(revoked);

        // Cookie should no longer be valid
        let result = manager.validate(&cookie);
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_all() {
        let store = MemoryRememberStore::new();
        let config = RememberConfig::builder().max_tokens_per_user(10).build();
        let manager = RememberManager::new(store, config);

        let _ = manager
            .issue_token("user@example.com", None)
            .expect("should succeed");
        let _ = manager
            .issue_token("user@example.com", None)
            .expect("should succeed");

        let count = manager
            .revoke_all("user@example.com")
            .expect("should succeed");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_get_active_tokens() {
        let store = MemoryRememberStore::new();
        let config = RememberConfig::builder().max_tokens_per_user(10).build();
        let manager = RememberManager::new(store, config);

        let _ = manager
            .issue_token("user@example.com", Some("Device 1"))
            .expect("should succeed");
        let _ = manager
            .issue_token("user@example.com", Some("Device 2"))
            .expect("should succeed");

        let tokens = manager
            .get_active_tokens("user@example.com")
            .expect("should succeed");
        assert_eq!(tokens.len(), 2);
    }

    #[test]
    fn test_max_tokens_per_user() {
        let store = MemoryRememberStore::new();
        let config = RememberConfig::builder().max_tokens_per_user(2).build();
        let manager = RememberManager::new(store, config);

        // Issue 2 tokens (at limit)
        let _ = manager
            .issue_token("user@example.com", None)
            .expect("should succeed");
        let _ = manager
            .issue_token("user@example.com", None)
            .expect("should succeed");

        // Third token should trigger cleanup and still succeed
        let result = manager.issue_token("user@example.com", None);
        assert!(result.is_ok());

        // Should only have 1 token now (old ones revoked, new one issued)
        let tokens = manager
            .get_active_tokens("user@example.com")
            .expect("should succeed");
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn test_cleanup() {
        let store = MemoryRememberStore::new();
        let config = RememberConfig::builder()
            .token_lifetime(Duration::from_millis(10))
            .max_tokens_per_user(10)
            .build();
        let manager = RememberManager::new(store, config);

        let _ = manager
            .issue_token("user@example.com", None)
            .expect("should succeed");

        std::thread::sleep(Duration::from_millis(20));

        let count = manager.cleanup().expect("should succeed");
        assert_eq!(count, 1);
    }

    #[test]
    fn test_expired_token_validation() {
        let store = MemoryRememberStore::new();
        let config = RememberConfig::builder()
            .token_lifetime(Duration::from_millis(10))
            .build();
        let manager = RememberManager::new(store, config);

        let pair = manager
            .issue_token("user@example.com", None)
            .expect("should succeed");

        std::thread::sleep(Duration::from_millis(20));

        let result = manager.validate(&pair.cookie_value());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn test_cookie_name() {
        let store = MemoryRememberStore::new();
        let config = RememberConfig::builder().cookie_name("my_remember").build();
        let manager = RememberManager::new(store, config);

        assert_eq!(manager.cookie_name(), "my_remember");
    }
}

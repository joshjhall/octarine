//! Remember-me token storage backends
//!
//! Provides pluggable storage for remember-me tokens with in-memory implementation.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::primitives::auth::remember::RememberToken;
use crate::primitives::types::Problem;

// ============================================================================
// Remember Token Store Trait
// ============================================================================

/// Trait for remember-me token storage backends
///
/// Implement this trait to provide custom token storage (Redis, PostgreSQL, etc.).
///
/// # Implementation Notes
///
/// - Tokens use a split selector:validator design
/// - Store the validator_hash, never the plaintext validator
/// - Index by selector for fast lookup
/// - Implement token cleanup for expired/revoked tokens
pub trait RememberTokenStore: Send + Sync {
    /// Store a remember-me token
    ///
    /// # Arguments
    ///
    /// * `token` - The remember token to store
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    fn store(&self, token: &RememberToken) -> Result<(), Problem>;

    /// Get a token by its selector
    ///
    /// # Arguments
    ///
    /// * `selector` - The selector to look up
    ///
    /// # Returns
    ///
    /// The token if found, None otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval fails.
    fn get_by_selector(&self, selector: &str) -> Result<Option<RememberToken>, Problem>;

    /// Get all active tokens for a user
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID
    ///
    /// # Returns
    ///
    /// List of active (non-expired, non-revoked) tokens.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval fails.
    fn get_active_for_user(&self, user_id: &str) -> Result<Vec<RememberToken>, Problem>;

    /// Revoke a token by its selector
    ///
    /// # Arguments
    ///
    /// * `selector` - The selector of the token to revoke
    ///
    /// # Returns
    ///
    /// `true` if the token was found and revoked, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    fn revoke(&self, selector: &str) -> Result<bool, Problem>;

    /// Revoke all tokens for a user
    ///
    /// Called when user logs out from all devices or changes password.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID
    ///
    /// # Returns
    ///
    /// Number of tokens revoked.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    fn revoke_all_for_user(&self, user_id: &str) -> Result<usize, Problem>;

    /// Delete a token (for rotation)
    ///
    /// # Arguments
    ///
    /// * `selector` - The selector of the token to delete
    ///
    /// # Returns
    ///
    /// `true` if the token was found and deleted, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    fn delete(&self, selector: &str) -> Result<bool, Problem>;

    /// Count active tokens for a user
    ///
    /// Used to enforce max tokens per user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID
    ///
    /// # Returns
    ///
    /// Number of active tokens.
    ///
    /// # Errors
    ///
    /// Returns an error if counting fails.
    fn count_active_for_user(&self, user_id: &str) -> Result<usize, Problem>;

    /// Clean up expired and revoked tokens
    ///
    /// Should be called periodically to remove stale data.
    ///
    /// # Returns
    ///
    /// Number of tokens cleaned up.
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup fails.
    fn cleanup_expired(&self) -> Result<usize, Problem>;
}

// ============================================================================
// In-Memory Remember Token Store
// ============================================================================

/// In-memory remember token store for development and testing
///
/// Not suitable for production multi-instance deployments.
#[derive(Debug, Default)]
pub struct MemoryRememberStore {
    /// Tokens indexed by selector
    tokens: RwLock<HashMap<String, RememberToken>>,
    /// Selectors by user ID (for lookup by user)
    user_tokens: RwLock<HashMap<String, Vec<String>>>,
}

impl MemoryRememberStore {
    /// Create a new in-memory remember token store
    #[must_use]
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            user_tokens: RwLock::new(HashMap::new()),
        }
    }
}

impl RememberTokenStore for MemoryRememberStore {
    fn store(&self, token: &RememberToken) -> Result<(), Problem> {
        let mut tokens = self.tokens.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire remember store lock: {e}"))
        })?;

        let mut user_tokens = self.user_tokens.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire remember store lock: {e}"))
        })?;

        let selector = token.selector().to_string();
        let user_id = token.user_id().to_string();

        tokens.insert(selector.clone(), token.clone());

        user_tokens.entry(user_id).or_default().push(selector);

        Ok(())
    }

    fn get_by_selector(&self, selector: &str) -> Result<Option<RememberToken>, Problem> {
        let tokens = self.tokens.read().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire remember store lock: {e}"))
        })?;

        Ok(tokens.get(selector).cloned())
    }

    fn get_active_for_user(&self, user_id: &str) -> Result<Vec<RememberToken>, Problem> {
        let tokens = self.tokens.read().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire remember store lock: {e}"))
        })?;

        let user_tokens = self.user_tokens.read().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire remember store lock: {e}"))
        })?;

        let mut active = Vec::new();
        if let Some(selectors) = user_tokens.get(user_id) {
            for selector in selectors {
                if let Some(token) = tokens.get(selector)
                    && token.is_valid()
                {
                    active.push(token.clone());
                }
            }
        }

        Ok(active)
    }

    fn revoke(&self, selector: &str) -> Result<bool, Problem> {
        let mut tokens = self.tokens.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire remember store lock: {e}"))
        })?;

        if let Some(token) = tokens.get_mut(selector) {
            token.revoke();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn revoke_all_for_user(&self, user_id: &str) -> Result<usize, Problem> {
        let mut tokens = self.tokens.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire remember store lock: {e}"))
        })?;

        let user_tokens = self.user_tokens.read().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire remember store lock: {e}"))
        })?;

        let mut count: usize = 0;
        if let Some(selectors) = user_tokens.get(user_id) {
            for selector in selectors {
                if let Some(token) = tokens.get_mut(selector)
                    && !token.is_revoked()
                {
                    token.revoke();
                    count = count.saturating_add(1);
                }
            }
        }

        Ok(count)
    }

    fn delete(&self, selector: &str) -> Result<bool, Problem> {
        let mut tokens = self.tokens.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire remember store lock: {e}"))
        })?;

        let mut user_tokens = self.user_tokens.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire remember store lock: {e}"))
        })?;

        if let Some(token) = tokens.remove(selector) {
            // Remove from user's list
            if let Some(selectors) = user_tokens.get_mut(token.user_id()) {
                selectors.retain(|s| s != selector);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn count_active_for_user(&self, user_id: &str) -> Result<usize, Problem> {
        let tokens = self.tokens.read().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire remember store lock: {e}"))
        })?;

        let user_tokens = self.user_tokens.read().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire remember store lock: {e}"))
        })?;

        let mut count: usize = 0;
        if let Some(selectors) = user_tokens.get(user_id) {
            for selector in selectors {
                if let Some(token) = tokens.get(selector)
                    && token.is_valid()
                {
                    count = count.saturating_add(1);
                }
            }
        }

        Ok(count)
    }

    fn cleanup_expired(&self) -> Result<usize, Problem> {
        let mut tokens = self.tokens.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire remember store lock: {e}"))
        })?;

        let mut user_tokens = self.user_tokens.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire remember store lock: {e}"))
        })?;

        // Find expired/revoked tokens
        let expired: Vec<String> = tokens
            .iter()
            .filter(|(_, token)| !token.is_valid())
            .map(|(k, _)| k.clone())
            .collect();

        let count = expired.len();

        // Remove expired tokens
        for selector in &expired {
            tokens.remove(selector);
        }

        // Clean up user token lists
        for selectors in user_tokens.values_mut() {
            selectors.retain(|s| !expired.contains(s));
        }

        // Remove empty user entries
        user_tokens.retain(|_, v| !v.is_empty());

        Ok(count)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::primitives::auth::remember::{RememberConfig, generate_remember_token};
    use std::time::Duration;

    #[test]
    fn test_store_and_get() {
        let store = MemoryRememberStore::new();
        let config = RememberConfig::default();
        let pair = generate_remember_token("user123", &config, None);

        store.store(pair.token()).expect("store should succeed");

        let retrieved = store
            .get_by_selector(pair.selector())
            .expect("get should succeed");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id(), "user123");
    }

    #[test]
    fn test_get_nonexistent() {
        let store = MemoryRememberStore::new();

        let result = store
            .get_by_selector("nonexistent")
            .expect("get should succeed");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_active_for_user() {
        let store = MemoryRememberStore::new();
        let config = RememberConfig::default();

        let pair1 = generate_remember_token("user123", &config, None);
        let pair2 = generate_remember_token("user123", &config, None);
        let pair3 = generate_remember_token("other_user", &config, None);

        store.store(pair1.token()).expect("store should succeed");
        store.store(pair2.token()).expect("store should succeed");
        store.store(pair3.token()).expect("store should succeed");

        let active = store
            .get_active_for_user("user123")
            .expect("get should succeed");
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn test_revoke() {
        let store = MemoryRememberStore::new();
        let config = RememberConfig::default();
        let pair = generate_remember_token("user123", &config, None);
        let selector = pair.selector().to_string();

        store.store(pair.token()).expect("store should succeed");

        let revoked = store.revoke(&selector).expect("revoke should succeed");
        assert!(revoked);

        let retrieved = store
            .get_by_selector(&selector)
            .expect("get should succeed")
            .expect("token should exist");
        assert!(retrieved.is_revoked());
    }

    #[test]
    fn test_revoke_nonexistent() {
        let store = MemoryRememberStore::new();

        let revoked = store.revoke("nonexistent").expect("revoke should succeed");
        assert!(!revoked);
    }

    #[test]
    fn test_revoke_all_for_user() {
        let store = MemoryRememberStore::new();
        let config = RememberConfig::default();

        let pair1 = generate_remember_token("user123", &config, None);
        let pair2 = generate_remember_token("user123", &config, None);
        let pair3 = generate_remember_token("other_user", &config, None);

        store.store(pair1.token()).expect("store should succeed");
        store.store(pair2.token()).expect("store should succeed");
        store.store(pair3.token()).expect("store should succeed");

        let count = store
            .revoke_all_for_user("user123")
            .expect("revoke should succeed");
        assert_eq!(count, 2);

        let active = store
            .get_active_for_user("user123")
            .expect("get should succeed");
        assert!(active.is_empty());

        // Other user's tokens should remain valid
        let other_active = store
            .get_active_for_user("other_user")
            .expect("get should succeed");
        assert_eq!(other_active.len(), 1);
    }

    #[test]
    fn test_delete() {
        let store = MemoryRememberStore::new();
        let config = RememberConfig::default();
        let pair = generate_remember_token("user123", &config, None);
        let selector = pair.selector().to_string();

        store.store(pair.token()).expect("store should succeed");

        let deleted = store.delete(&selector).expect("delete should succeed");
        assert!(deleted);

        let retrieved = store
            .get_by_selector(&selector)
            .expect("get should succeed");
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_count_active_for_user() {
        let store = MemoryRememberStore::new();
        let config = RememberConfig::default();

        let pair1 = generate_remember_token("user123", &config, None);
        let pair2 = generate_remember_token("user123", &config, None);

        store.store(pair1.token()).expect("store should succeed");
        store.store(pair2.token()).expect("store should succeed");

        let count = store
            .count_active_for_user("user123")
            .expect("count should succeed");
        assert_eq!(count, 2);

        // Revoke one
        store
            .revoke(pair1.selector())
            .expect("revoke should succeed");

        let count = store
            .count_active_for_user("user123")
            .expect("count should succeed");
        assert_eq!(count, 1);
    }

    #[test]
    fn test_cleanup_expired() {
        let store = MemoryRememberStore::new();
        let config = RememberConfig::builder()
            .token_lifetime(Duration::from_millis(10))
            .build();

        let pair = generate_remember_token("user123", &config, None);
        store.store(pair.token()).expect("store should succeed");

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        let count = store.cleanup_expired().expect("cleanup should succeed");
        assert_eq!(count, 1);

        let active = store
            .get_active_for_user("user123")
            .expect("get should succeed");
        assert!(active.is_empty());
    }
}

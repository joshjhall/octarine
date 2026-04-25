//! Password reset token storage backends
//!
//! Provides pluggable storage for reset tokens with in-memory implementation.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use crate::primitives::auth::reset::ResetToken;
use crate::primitives::types::Problem;

// ============================================================================
// Reset Token Store Trait
// ============================================================================

/// Trait for password reset token storage backends
///
/// Implement this trait to provide custom token storage (Redis, PostgreSQL, etc.).
///
/// # Implementation Notes
///
/// - Tokens should be stored securely (ideally hashed)
/// - Implementations should support token expiration
/// - Rate limiting data should be stored alongside tokens
pub trait ResetTokenStore: Send + Sync {
    /// Store a reset token
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID
    /// * `token` - The reset token to store
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    fn store(&self, user_id: &str, token: &ResetToken) -> Result<(), Problem>;

    /// Get a reset token by its value
    ///
    /// # Arguments
    ///
    /// * `token_value` - The token string to look up
    ///
    /// # Returns
    ///
    /// The token if found, None otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval fails.
    fn get_by_token(&self, token_value: &str) -> Result<Option<ResetToken>, Problem>;

    /// Get all active tokens for a user
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID
    ///
    /// # Returns
    ///
    /// List of active (non-expired, non-used) tokens.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval fails.
    fn get_active_for_user(&self, user_id: &str) -> Result<Vec<ResetToken>, Problem>;

    /// Mark a token as used
    ///
    /// # Arguments
    ///
    /// * `token_value` - The token to mark as used
    ///
    /// # Returns
    ///
    /// `true` if the token was found and marked, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    fn mark_used(&self, token_value: &str) -> Result<bool, Problem>;

    /// Invalidate all tokens for a user
    ///
    /// Called when password is successfully reset or user requests revocation.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID
    ///
    /// # Returns
    ///
    /// Number of tokens invalidated.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    fn invalidate_all_for_user(&self, user_id: &str) -> Result<usize, Problem>;

    /// Get the time of the last reset request for a user
    ///
    /// Used for rate limiting.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID
    ///
    /// # Returns
    ///
    /// The time of the last request, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval fails.
    fn get_last_request_time(&self, user_id: &str) -> Result<Option<Instant>, Problem>;

    /// Clean up expired tokens
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
// In-Memory Reset Token Store
// ============================================================================

/// Entry for tracking reset tokens
#[derive(Debug)]
struct ResetEntry {
    token: ResetToken,
    /// When the token was stored (for auditing purposes)
    #[allow(dead_code)]
    stored_at: Instant,
}

/// In-memory reset token store for development and testing
///
/// Not suitable for production multi-instance deployments.
///
/// # Security note
///
/// This in-memory store uses the plaintext token as the `HashMap` lookup
/// key for simplicity. Production stores should hash the lookup key
/// (e.g., HMAC with a per-deployment secret) so the database never holds
/// reusable plaintext credentials. The token bytes embedded inside each
/// stored `ResetToken` are zeroized on drop because `ResetToken` wraps
/// them in a zeroizing buffer; the lookup-key copies maintained by this
/// store are zeroized when the store itself is dropped (see the `Drop`
/// impl below).
#[derive(Debug, Default)]
pub struct MemoryResetStore {
    /// Tokens indexed by token value
    tokens: RwLock<HashMap<String, ResetEntry>>,
    /// Token values by user ID (for lookup by user)
    user_tokens: RwLock<HashMap<String, Vec<String>>>,
    /// Last request time by user ID (for rate limiting)
    last_requests: RwLock<HashMap<String, Instant>>,
}

impl MemoryResetStore {
    /// Create a new in-memory reset token store
    #[must_use]
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            user_tokens: RwLock::new(HashMap::new()),
            last_requests: RwLock::new(HashMap::new()),
        }
    }
}

impl Drop for MemoryResetStore {
    fn drop(&mut self) {
        // Zeroize the plaintext lookup keys held by this store. The
        // `ResetToken` values inside each entry zeroize themselves via
        // their internal `SecretStringCore` wrapper, but the `HashMap`
        // keys are owned `String`s — we wipe them on store drop so the
        // plaintext is not left in heap memory after the store dies.
        if let Ok(tokens) = self.tokens.get_mut() {
            for (key, _) in tokens.drain() {
                let mut key = key;
                key.zeroize();
            }
        }
        if let Ok(user_tokens) = self.user_tokens.get_mut() {
            for (_, mut values) in user_tokens.drain() {
                for value in &mut values {
                    value.zeroize();
                }
            }
        }
    }
}

impl ResetTokenStore for MemoryResetStore {
    fn store(&self, user_id: &str, token: &ResetToken) -> Result<(), Problem> {
        let mut tokens = self.tokens.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire reset store lock: {e}"))
        })?;

        let mut user_tokens = self.user_tokens.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire reset store lock: {e}"))
        })?;

        let mut last_requests = self.last_requests.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire reset store lock: {e}"))
        })?;

        // Store the token
        let token_value = token.value().to_string();
        tokens.insert(
            token_value.clone(),
            ResetEntry {
                token: token.clone(),
                stored_at: Instant::now(),
            },
        );

        // Track by user
        user_tokens
            .entry(user_id.to_string())
            .or_default()
            .push(token_value);

        // Update last request time
        last_requests.insert(user_id.to_string(), Instant::now());

        Ok(())
    }

    fn get_by_token(&self, token_value: &str) -> Result<Option<ResetToken>, Problem> {
        let tokens = self.tokens.read().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire reset store lock: {e}"))
        })?;

        Ok(tokens.get(token_value).map(|entry| entry.token.clone()))
    }

    fn get_active_for_user(&self, user_id: &str) -> Result<Vec<ResetToken>, Problem> {
        let tokens = self.tokens.read().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire reset store lock: {e}"))
        })?;

        let user_tokens = self.user_tokens.read().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire reset store lock: {e}"))
        })?;

        let mut active = Vec::new();
        if let Some(token_values) = user_tokens.get(user_id) {
            for value in token_values {
                if let Some(entry) = tokens.get(value)
                    && entry.token.is_valid()
                {
                    active.push(entry.token.clone());
                }
            }
        }

        Ok(active)
    }

    fn mark_used(&self, token_value: &str) -> Result<bool, Problem> {
        let mut tokens = self.tokens.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire reset store lock: {e}"))
        })?;

        if let Some(entry) = tokens.get_mut(token_value) {
            entry.token.mark_used();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn invalidate_all_for_user(&self, user_id: &str) -> Result<usize, Problem> {
        let mut tokens = self.tokens.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire reset store lock: {e}"))
        })?;

        let mut user_tokens = self.user_tokens.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire reset store lock: {e}"))
        })?;

        let mut count: usize = 0;
        if let Some(token_values) = user_tokens.remove(user_id) {
            for value in token_values {
                if tokens.remove(&value).is_some() {
                    count = count.saturating_add(1);
                }
            }
        }

        Ok(count)
    }

    fn get_last_request_time(&self, user_id: &str) -> Result<Option<Instant>, Problem> {
        let last_requests = self.last_requests.read().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire reset store lock: {e}"))
        })?;

        Ok(last_requests.get(user_id).copied())
    }

    fn cleanup_expired(&self) -> Result<usize, Problem> {
        let mut tokens = self.tokens.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire reset store lock: {e}"))
        })?;

        let mut user_tokens = self.user_tokens.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire reset store lock: {e}"))
        })?;

        let mut last_requests = self.last_requests.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire reset store lock: {e}"))
        })?;

        // Find expired tokens
        let expired: Vec<String> = tokens
            .iter()
            .filter(|(_, entry)| !entry.token.is_valid())
            .map(|(k, _)| k.clone())
            .collect();

        let count = expired.len();

        // Remove expired tokens
        for token_value in &expired {
            tokens.remove(token_value);
        }

        // Clean up user token lists
        for token_values in user_tokens.values_mut() {
            token_values.retain(|v| !expired.contains(v));
        }

        // Remove empty user entries
        user_tokens.retain(|_, v| !v.is_empty());

        // Clean up old last request times (older than 24 hours)
        let stale_threshold = Duration::from_secs(86400);
        last_requests.retain(|_, instant| instant.elapsed() < stale_threshold);

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
    use crate::primitives::auth::reset::{ResetConfig, generate_reset_token};

    #[test]
    fn test_store_and_get() {
        let store = MemoryResetStore::new();
        let config = ResetConfig::default();
        let token = generate_reset_token("user123", &config);

        store
            .store("user123", &token)
            .expect("store should succeed");

        let retrieved = store
            .get_by_token(token.value())
            .expect("get should succeed");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id(), "user123");
    }

    #[test]
    fn test_get_nonexistent() {
        let store = MemoryResetStore::new();

        let result = store
            .get_by_token("nonexistent")
            .expect("get should succeed");
        assert!(result.is_none());
    }

    #[test]
    fn test_get_active_for_user() {
        let store = MemoryResetStore::new();
        let config = ResetConfig::default();

        let token1 = generate_reset_token("user123", &config);
        let token2 = generate_reset_token("user123", &config);
        let token3 = generate_reset_token("other_user", &config);

        store
            .store("user123", &token1)
            .expect("store should succeed");
        store
            .store("user123", &token2)
            .expect("store should succeed");
        store
            .store("other_user", &token3)
            .expect("store should succeed");

        let active = store
            .get_active_for_user("user123")
            .expect("get should succeed");
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn test_mark_used() {
        let store = MemoryResetStore::new();
        let config = ResetConfig::default();
        let token = generate_reset_token("user123", &config);
        let token_value = token.value().to_string();

        store
            .store("user123", &token)
            .expect("store should succeed");

        let marked = store.mark_used(&token_value).expect("mark should succeed");
        assert!(marked);

        let retrieved = store
            .get_by_token(&token_value)
            .expect("get should succeed")
            .expect("token should exist");
        assert!(retrieved.is_used());
    }

    #[test]
    fn test_mark_used_nonexistent() {
        let store = MemoryResetStore::new();

        let marked = store.mark_used("nonexistent").expect("mark should succeed");
        assert!(!marked);
    }

    #[test]
    fn test_invalidate_all_for_user() {
        let store = MemoryResetStore::new();
        let config = ResetConfig::default();

        let token1 = generate_reset_token("user123", &config);
        let token2 = generate_reset_token("user123", &config);
        let token3 = generate_reset_token("other_user", &config);

        store
            .store("user123", &token1)
            .expect("store should succeed");
        store
            .store("user123", &token2)
            .expect("store should succeed");
        store
            .store("other_user", &token3)
            .expect("store should succeed");

        let count = store
            .invalidate_all_for_user("user123")
            .expect("invalidate should succeed");
        assert_eq!(count, 2);

        let active = store
            .get_active_for_user("user123")
            .expect("get should succeed");
        assert!(active.is_empty());

        // Other user's tokens should remain
        let other_active = store
            .get_active_for_user("other_user")
            .expect("get should succeed");
        assert_eq!(other_active.len(), 1);
    }

    #[test]
    fn test_get_last_request_time() {
        let store = MemoryResetStore::new();
        let config = ResetConfig::default();
        let token = generate_reset_token("user123", &config);

        // No request yet
        let last = store
            .get_last_request_time("user123")
            .expect("get should succeed");
        assert!(last.is_none());

        // Store a token
        store
            .store("user123", &token)
            .expect("store should succeed");

        // Now should have a request time
        let last = store
            .get_last_request_time("user123")
            .expect("get should succeed");
        assert!(last.is_some());
    }

    #[test]
    fn test_cleanup_expired() {
        let store = MemoryResetStore::new();
        let config = ResetConfig::builder()
            .token_lifetime(Duration::from_millis(10))
            .build();

        let token = generate_reset_token("user123", &config);
        store
            .store("user123", &token)
            .expect("store should succeed");

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

//! Lockout storage backends
//!
//! Provides pluggable storage for lockout status with in-memory implementation.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Duration;

use crate::primitives::auth::lockout::LockoutStatus;
use crate::primitives::types::Problem;

// ============================================================================
// Lockout Store Trait
// ============================================================================

/// Trait for lockout storage backends
///
/// Implement this trait to provide custom lockout storage (Redis, PostgreSQL, etc.).
pub trait LockoutStore: Send + Sync {
    /// Get the lockout status for an identifier
    ///
    /// Returns a default status if the identifier doesn't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval fails.
    fn get(&self, identifier: &str) -> Result<LockoutStatus, Problem>;

    /// Update the lockout status for an identifier
    ///
    /// # Errors
    ///
    /// Returns an error if update fails.
    fn update(&self, identifier: &str, status: &LockoutStatus) -> Result<(), Problem>;

    /// Clear the lockout status for an identifier
    ///
    /// Returns `true` if the identifier existed, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if clearing fails.
    fn clear(&self, identifier: &str) -> Result<bool, Problem>;

    /// Clean up old failure records across all identifiers
    ///
    /// Returns the number of records cleaned up.
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup fails.
    fn cleanup_old_records(&self, window: Duration) -> Result<usize, Problem>;
}

// ============================================================================
// In-Memory Lockout Store
// ============================================================================

/// In-memory lockout store for development and testing
///
/// Not suitable for production multi-instance deployments.
#[derive(Debug, Default)]
pub struct MemoryLockoutStore {
    statuses: RwLock<HashMap<String, LockoutStatus>>,
}

impl MemoryLockoutStore {
    /// Create a new in-memory lockout store
    #[must_use]
    pub fn new() -> Self {
        Self {
            statuses: RwLock::new(HashMap::new()),
        }
    }
}

impl LockoutStore for MemoryLockoutStore {
    fn get(&self, identifier: &str) -> Result<LockoutStatus, Problem> {
        let statuses = self.statuses.read().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire lockout store lock: {e}"))
        })?;

        Ok(statuses
            .get(identifier)
            .cloned()
            .unwrap_or_else(LockoutStatus::new))
    }

    fn update(&self, identifier: &str, status: &LockoutStatus) -> Result<(), Problem> {
        let mut statuses = self.statuses.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire lockout store lock: {e}"))
        })?;

        statuses.insert(identifier.to_string(), status.clone());
        Ok(())
    }

    fn clear(&self, identifier: &str) -> Result<bool, Problem> {
        let mut statuses = self.statuses.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire lockout store lock: {e}"))
        })?;

        Ok(statuses.remove(identifier).is_some())
    }

    fn cleanup_old_records(&self, window: Duration) -> Result<usize, Problem> {
        let mut statuses = self.statuses.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire lockout store lock: {e}"))
        })?;

        let mut cleaned: usize = 0;
        for status in statuses.values_mut() {
            let before = status.failures.len();
            status.cleanup_old_failures(window);
            cleaned = cleaned.saturating_add(before.saturating_sub(status.failures.len()));
        }

        // Remove entries with no failures and no lockout
        statuses.retain(|_, status| !status.failures.is_empty() || status.is_locked());

        Ok(cleaned)
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
    fn test_memory_store_get_default() {
        let store = MemoryLockoutStore::new();

        let status = store.get("user1").expect("get should succeed");
        assert_eq!(status.consecutive_failures, 0);
        assert!(status.failures.is_empty());
    }

    #[test]
    fn test_memory_store_update_and_get() {
        let store = MemoryLockoutStore::new();

        let mut status = LockoutStatus::new();
        status.record_failure();
        status.record_failure();

        store
            .update("user1", &status)
            .expect("update should succeed");

        let retrieved = store.get("user1").expect("get should succeed");
        assert_eq!(retrieved.consecutive_failures, 2);
        assert_eq!(retrieved.failures.len(), 2);
    }

    #[test]
    fn test_memory_store_clear() {
        let store = MemoryLockoutStore::new();

        let mut status = LockoutStatus::new();
        status.record_failure();
        store
            .update("user1", &status)
            .expect("update should succeed");

        let cleared = store.clear("user1").expect("clear should succeed");
        assert!(cleared);

        let retrieved = store.get("user1").expect("get should succeed");
        assert_eq!(retrieved.consecutive_failures, 0);
    }

    #[test]
    fn test_memory_store_clear_nonexistent() {
        let store = MemoryLockoutStore::new();

        let cleared = store.clear("nonexistent").expect("clear should succeed");
        assert!(!cleared);
    }
}

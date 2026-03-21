//! Session storage backends
//!
//! Provides pluggable storage for sessions with in-memory implementation.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::primitives::auth::session::{Session, SessionId};
use crate::primitives::types::Problem;

// ============================================================================
// Session Store Trait
// ============================================================================

/// Trait for session storage backends
///
/// Implement this trait to provide custom session storage (Redis, PostgreSQL, etc.).
pub trait SessionStore: Send + Sync {
    /// Store a new session
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    fn create(&self, session: Session) -> Result<(), Problem>;

    /// Retrieve a session by ID
    ///
    /// Returns `None` if the session doesn't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval fails.
    fn get(&self, session_id: &SessionId) -> Result<Option<Session>, Problem>;

    /// Update an existing session
    ///
    /// # Errors
    ///
    /// Returns an error if the session doesn't exist or update fails.
    fn update(&self, session: &Session) -> Result<(), Problem>;

    /// Delete a session
    ///
    /// Returns `true` if the session was deleted, `false` if it didn't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if deletion fails.
    fn delete(&self, session_id: &SessionId) -> Result<bool, Problem>;

    /// Delete all sessions for a user
    ///
    /// Returns the number of sessions deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if deletion fails.
    fn delete_all_for_user(&self, user_id: &str) -> Result<usize, Problem>;

    /// Count active sessions for a user
    ///
    /// # Errors
    ///
    /// Returns an error if counting fails.
    fn count_for_user(&self, user_id: &str) -> Result<usize, Problem>;

    /// Clean up expired sessions
    ///
    /// Returns the number of sessions cleaned up.
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup fails.
    fn cleanup_expired(&self) -> Result<usize, Problem>;
}

// ============================================================================
// In-Memory Session Store
// ============================================================================

/// In-memory session store for development and testing
///
/// Not suitable for production multi-instance deployments.
#[derive(Debug, Default)]
pub struct MemorySessionStore {
    sessions: RwLock<HashMap<String, Session>>,
}

impl MemorySessionStore {
    /// Create a new in-memory session store
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }
}

impl SessionStore for MemorySessionStore {
    fn create(&self, session: Session) -> Result<(), Problem> {
        let mut sessions = self.sessions.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire session store lock: {e}"))
        })?;

        sessions.insert(session.id.as_str().to_string(), session);
        Ok(())
    }

    fn get(&self, session_id: &SessionId) -> Result<Option<Session>, Problem> {
        let sessions = self.sessions.read().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire session store lock: {e}"))
        })?;

        Ok(sessions.get(session_id.as_str()).cloned())
    }

    fn update(&self, session: &Session) -> Result<(), Problem> {
        let mut sessions = self.sessions.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire session store lock: {e}"))
        })?;

        if sessions.contains_key(session.id.as_str()) {
            sessions.insert(session.id.as_str().to_string(), session.clone());
            Ok(())
        } else {
            Err(Problem::NotFound(format!(
                "Session {} not found",
                session.id
            )))
        }
    }

    fn delete(&self, session_id: &SessionId) -> Result<bool, Problem> {
        let mut sessions = self.sessions.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire session store lock: {e}"))
        })?;

        Ok(sessions.remove(session_id.as_str()).is_some())
    }

    fn delete_all_for_user(&self, user_id: &str) -> Result<usize, Problem> {
        let mut sessions = self.sessions.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire session store lock: {e}"))
        })?;

        let initial_count = sessions.len();
        sessions.retain(|_, session| session.user_id != user_id);
        Ok(initial_count.saturating_sub(sessions.len()))
    }

    fn count_for_user(&self, user_id: &str) -> Result<usize, Problem> {
        let sessions = self.sessions.read().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire session store lock: {e}"))
        })?;

        Ok(sessions.values().filter(|s| s.user_id == user_id).count())
    }

    fn cleanup_expired(&self) -> Result<usize, Problem> {
        let mut sessions = self.sessions.write().map_err(|e| {
            Problem::OperationFailed(format!("Failed to acquire session store lock: {e}"))
        })?;

        let initial_count = sessions.len();
        sessions.retain(|_, session| !session.is_expired());
        Ok(initial_count.saturating_sub(sessions.len()))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::primitives::auth::session::SessionConfig;

    fn create_test_session(user_id: &str) -> Session {
        Session::new(user_id, &SessionConfig::default())
    }

    #[test]
    fn test_memory_store_create_and_get() {
        let store = MemorySessionStore::new();
        let session = create_test_session("user1");
        let session_id = session.id.clone();

        store.create(session).expect("create should succeed");

        let retrieved = store.get(&session_id).expect("get should succeed");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.expect("should have session").user_id, "user1");
    }

    #[test]
    fn test_memory_store_update() {
        let store = MemorySessionStore::new();
        let mut session = create_test_session("user1");
        let session_id = session.id.clone();

        store
            .create(session.clone())
            .expect("create should succeed");

        session.touch();
        store.update(&session).expect("update should succeed");

        let retrieved = store
            .get(&session_id)
            .expect("get should succeed")
            .expect("should have session");
        assert!(retrieved.last_accessed_at >= session.last_accessed_at);
    }

    #[test]
    fn test_memory_store_update_nonexistent() {
        let store = MemorySessionStore::new();
        let session = create_test_session("user1");

        let result = store.update(&session);
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_store_delete() {
        let store = MemorySessionStore::new();
        let session = create_test_session("user1");
        let session_id = session.id.clone();

        store.create(session).expect("create should succeed");

        let deleted = store.delete(&session_id).expect("delete should succeed");
        assert!(deleted);

        let retrieved = store.get(&session_id).expect("get should succeed");
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_memory_store_delete_nonexistent() {
        let store = MemorySessionStore::new();
        let session_id = SessionId::generate();

        let deleted = store.delete(&session_id).expect("delete should succeed");
        assert!(!deleted);
    }

    #[test]
    fn test_memory_store_delete_all_for_user() {
        let store = MemorySessionStore::new();

        store.create(create_test_session("user1")).expect("create");
        store.create(create_test_session("user1")).expect("create");
        store.create(create_test_session("user2")).expect("create");

        let deleted = store.delete_all_for_user("user1").expect("delete_all");
        assert_eq!(deleted, 2);

        let count = store.count_for_user("user1").expect("count");
        assert_eq!(count, 0);

        let count = store.count_for_user("user2").expect("count");
        assert_eq!(count, 1);
    }

    #[test]
    fn test_memory_store_count_for_user() {
        let store = MemorySessionStore::new();

        store.create(create_test_session("user1")).expect("create");
        store.create(create_test_session("user1")).expect("create");
        store.create(create_test_session("user2")).expect("create");

        assert_eq!(store.count_for_user("user1").expect("count"), 2);
        assert_eq!(store.count_for_user("user2").expect("count"), 1);
        assert_eq!(store.count_for_user("user3").expect("count"), 0);
    }
}

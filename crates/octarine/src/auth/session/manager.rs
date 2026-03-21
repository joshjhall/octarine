//! Session manager with observe integration
//!
//! Provides session lifecycle management with audit logging.

use std::sync::Arc;

use crate::observe;
use crate::primitives::auth::session::{Session, SessionBinding, SessionConfig, SessionId};
use crate::primitives::types::Problem;

use super::store::SessionStore;

// ============================================================================
// Session Manager
// ============================================================================

/// Session manager with audit logging
///
/// Manages session lifecycle with automatic observe events for compliance.
pub struct SessionManager<S: SessionStore> {
    /// Session storage backend
    store: Arc<S>,
    /// Session configuration
    config: SessionConfig,
}

impl<S: SessionStore> SessionManager<S> {
    /// Create a new session manager with the given store and config
    pub fn new(store: Arc<S>, config: SessionConfig) -> Self {
        Self { store, config }
    }

    /// Create a new session for a user
    ///
    /// # Audit Events
    ///
    /// - `auth.session.created` (INFO)
    pub fn create_session(&self, user_id: &str) -> Result<Session, Problem> {
        let session = Session::new(user_id, &self.config);

        self.store.create(session.clone())?;

        observe::info(
            "auth.session.created",
            format!("Session created for user: {}", user_id),
        );

        Ok(session)
    }

    /// Create a new session with binding
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID
    /// * `user_agent` - Optional user agent string
    /// * `ip` - Optional client IP address
    ///
    /// # Audit Events
    ///
    /// - `auth.session.created` (INFO)
    pub fn create_session_with_binding(
        &self,
        user_id: &str,
        user_agent: Option<&str>,
        ip: Option<&str>,
    ) -> Result<Session, Problem> {
        let binding = self.create_binding(user_agent, ip);
        let session = Session::new_with_binding(user_id, &self.config, binding);

        self.store.create(session.clone())?;

        observe::info(
            "auth.session.created",
            format!(
                "Session created for user: {} (binding: ua={}, ip={})",
                user_id, self.config.bind_user_agent, self.config.bind_ip
            ),
        );

        Ok(session)
    }

    /// Validate and optionally refresh a session
    ///
    /// Returns the session if valid, or an error if expired/invalid.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session ID to validate
    /// * `user_agent` - Current user agent (for binding validation)
    /// * `ip` - Current client IP (for binding validation)
    ///
    /// # Audit Events
    ///
    /// - `auth.session.validated` (DEBUG) - Session is valid
    /// - `auth.session.expired` (INFO) - Session has expired
    /// - `auth.session.binding_mismatch` (WARN) - Session binding doesn't match
    pub fn validate_session(
        &self,
        session_id: &SessionId,
        user_agent: Option<&str>,
        ip: Option<&str>,
    ) -> Result<Session, Problem> {
        let mut session = self
            .store
            .get(session_id)?
            .ok_or_else(|| Problem::NotFound(format!("Session {} not found", session_id)))?;

        // Check expiration
        if session.is_expired() {
            observe::info(
                "auth.session.expired",
                format!("Session {} expired (absolute timeout)", session_id),
            );
            self.store.delete(session_id)?;
            return Err(Problem::Auth("Session expired".to_string()));
        }

        // Check idle timeout
        if session.is_idle_expired(&self.config) {
            observe::info(
                "auth.session.expired",
                format!("Session {} expired (idle timeout)", session_id),
            );
            self.store.delete(session_id)?;
            return Err(Problem::Auth(
                "Session expired due to inactivity".to_string(),
            ));
        }

        // Check binding
        if !session.validate_binding(user_agent, ip) {
            observe::warn(
                "auth.session.binding_mismatch",
                format!(
                    "Session {} binding mismatch (possible session hijacking)",
                    session_id
                ),
            );
            return Err(Problem::Auth("Session binding mismatch".to_string()));
        }

        // Update last accessed time
        session.touch();
        self.store.update(&session)?;

        observe::debug(
            "auth.session.validated",
            format!(
                "Session {} validated for user {}",
                session_id, session.user_id
            ),
        );

        Ok(session)
    }

    /// Terminate a session (logout)
    ///
    /// # Audit Events
    ///
    /// - `auth.session.terminated` (INFO)
    pub fn terminate_session(&self, session_id: &SessionId) -> Result<bool, Problem> {
        // Get session info for logging before deletion
        let session = self.store.get(session_id)?;

        let deleted = self.store.delete(session_id)?;

        if deleted {
            let user_id = session
                .map(|s| s.user_id)
                .unwrap_or_else(|| "unknown".to_string());
            observe::info(
                "auth.session.terminated",
                format!("Session {} terminated for user {}", session_id, user_id),
            );
        }

        Ok(deleted)
    }

    /// Terminate all sessions for a user (logout everywhere)
    ///
    /// # Audit Events
    ///
    /// - `auth.session.terminated_all` (INFO)
    pub fn terminate_all_for_user(&self, user_id: &str) -> Result<usize, Problem> {
        let count = self.store.delete_all_for_user(user_id)?;

        if count > 0 {
            observe::info(
                "auth.session.terminated_all",
                format!("Terminated {} sessions for user {}", count, user_id),
            );
        }

        Ok(count)
    }

    /// Regenerate session ID (for privilege escalation)
    ///
    /// Creates a new session with a new ID, copying data from the old session.
    ///
    /// # Audit Events
    ///
    /// - `auth.session.regenerated` (INFO)
    pub fn regenerate_session(
        &self,
        old_session_id: &SessionId,
        user_agent: Option<&str>,
        ip: Option<&str>,
    ) -> Result<Session, Problem> {
        // Get the old session
        let old_session = self
            .store
            .get(old_session_id)?
            .ok_or_else(|| Problem::NotFound(format!("Session {} not found", old_session_id)))?;

        // Create new session
        let new_session = if self.config.bind_user_agent || self.config.bind_ip {
            self.create_session_with_binding(&old_session.user_id, user_agent, ip)?
        } else {
            self.create_session(&old_session.user_id)?
        };

        // Delete old session
        self.store.delete(old_session_id)?;

        observe::info(
            "auth.session.regenerated",
            format!(
                "Session regenerated for user {} ({} -> {})",
                old_session.user_id, old_session_id, new_session.id
            ),
        );

        Ok(new_session)
    }

    /// Get the number of active sessions for a user
    pub fn count_user_sessions(&self, user_id: &str) -> Result<usize, Problem> {
        self.store.count_for_user(user_id)
    }

    /// Clean up expired sessions
    ///
    /// Should be called periodically (e.g., every 5 minutes).
    ///
    /// # Audit Events
    ///
    /// - `auth.session.cleanup` (DEBUG) if any sessions were cleaned
    pub fn cleanup_expired(&self) -> Result<usize, Problem> {
        let count = self.store.cleanup_expired()?;

        if count > 0 {
            observe::debug(
                "auth.session.cleanup",
                format!("Cleaned up {} expired sessions", count),
            );
        }

        Ok(count)
    }

    /// Create a session binding based on configuration
    fn create_binding(&self, user_agent: Option<&str>, ip: Option<&str>) -> SessionBinding {
        let ua = if self.config.bind_user_agent {
            user_agent
        } else {
            None
        };

        let bound_ip = if self.config.bind_ip {
            if self.config.bind_network_only {
                // Network-only binding handled in SessionBinding
                ip
            } else {
                ip
            }
        } else {
            None
        };

        if self.config.bind_network_only && self.config.bind_ip {
            SessionBinding::from_context(ua, None)
        } else {
            SessionBinding::from_context(ua, bound_ip)
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::auth::session::MemorySessionStore;

    fn create_manager() -> SessionManager<MemorySessionStore> {
        let store = Arc::new(MemorySessionStore::new());
        let config = SessionConfig::default();
        SessionManager::new(store, config)
    }

    #[test]
    fn test_create_session() {
        let manager = create_manager();
        let session = manager
            .create_session("user1")
            .expect("create should succeed");

        assert_eq!(session.user_id, "user1");
        assert!(session.is_valid(&SessionConfig::default()));
    }

    #[test]
    fn test_create_session_with_binding() {
        let store = Arc::new(MemorySessionStore::new());
        let config = SessionConfig::builder()
            .bind_user_agent(true)
            .bind_ip(true)
            .build();
        let manager = SessionManager::new(store, config);

        let session = manager
            .create_session_with_binding("user1", Some("Mozilla/5.0"), Some("192.168.1.1"))
            .expect("create should succeed");

        assert!(session.binding.is_some());
    }

    #[test]
    fn test_validate_session() {
        let manager = create_manager();
        let session = manager
            .create_session("user1")
            .expect("create should succeed");

        let validated = manager
            .validate_session(&session.id, None, None)
            .expect("validate should succeed");

        assert_eq!(validated.user_id, "user1");
    }

    #[test]
    fn test_validate_session_not_found() {
        let manager = create_manager();
        let fake_id = SessionId::generate();

        let result = manager.validate_session(&fake_id, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_terminate_session() {
        let manager = create_manager();
        let session = manager
            .create_session("user1")
            .expect("create should succeed");

        let terminated = manager
            .terminate_session(&session.id)
            .expect("terminate should succeed");
        assert!(terminated);

        let result = manager.validate_session(&session.id, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_terminate_all_for_user() {
        let manager = create_manager();

        manager.create_session("user1").expect("create");
        manager.create_session("user1").expect("create");
        manager.create_session("user2").expect("create");

        let count = manager
            .terminate_all_for_user("user1")
            .expect("terminate_all");
        assert_eq!(count, 2);

        let count = manager.count_user_sessions("user1").expect("count");
        assert_eq!(count, 0);

        let count = manager.count_user_sessions("user2").expect("count");
        assert_eq!(count, 1);
    }

    #[test]
    fn test_regenerate_session() {
        let manager = create_manager();
        let old_session = manager.create_session("user1").expect("create");
        let old_id = old_session.id.clone();

        let new_session = manager
            .regenerate_session(&old_id, None, None)
            .expect("regenerate should succeed");

        assert_eq!(new_session.user_id, "user1");
        assert_ne!(new_session.id.as_str(), old_id.as_str());

        // Old session should be gone
        let result = manager.validate_session(&old_id, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_binding_validation_failure() {
        let store = Arc::new(MemorySessionStore::new());
        let config = SessionConfig::builder().bind_user_agent(true).build();
        let manager = SessionManager::new(store, config);

        let session = manager
            .create_session_with_binding("user1", Some("Mozilla/5.0"), None)
            .expect("create should succeed");

        // Validate with different user agent
        let result = manager.validate_session(&session.id, Some("Chrome/100"), None);
        assert!(result.is_err());
    }
}

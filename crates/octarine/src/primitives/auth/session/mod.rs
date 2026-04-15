//! Session management primitives (Layer 1)
//!
//! Provides pure session operations without observe instrumentation.

mod binding;
pub(crate) mod config;
mod id;

pub use binding::SessionBinding;
pub use config::{SessionConfig, SessionConfigBuilder};
pub use id::SessionId;

use chrono::{DateTime, Utc};

// ============================================================================
// Session
// ============================================================================

/// A user session with binding and timeout information
#[derive(Debug, Clone)]
pub struct Session {
    /// Unique session identifier (128+ bits entropy)
    pub id: SessionId,
    /// User ID this session belongs to
    pub user_id: String,
    /// When the session was created
    pub created_at: DateTime<Utc>,
    /// When the session was last accessed
    pub last_accessed_at: DateTime<Utc>,
    /// When the session expires (absolute timeout)
    pub expires_at: DateTime<Utc>,
    /// Optional session binding for additional security
    pub binding: Option<SessionBinding>,
}

impl Session {
    /// Create a new session with the given configuration
    #[must_use]
    #[allow(clippy::arithmetic_side_effects)] // Safe: adding duration to timestamp
    pub fn new(user_id: impl Into<String>, config: &SessionConfig) -> Self {
        let now = Utc::now();
        Self {
            id: SessionId::generate(),
            user_id: user_id.into(),
            created_at: now,
            last_accessed_at: now,
            expires_at: now + config.absolute_timeout,
            binding: None,
        }
    }

    /// Create a new session with binding
    #[must_use]
    pub fn new_with_binding(
        user_id: impl Into<String>,
        config: &SessionConfig,
        binding: SessionBinding,
    ) -> Self {
        let mut session = Self::new(user_id, config);
        session.binding = Some(binding);
        session
    }

    /// Check if the session has expired (absolute timeout)
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the session has been idle too long
    #[must_use]
    #[allow(clippy::arithmetic_side_effects)] // Safe: adding duration to timestamp
    pub fn is_idle_expired(&self, config: &SessionConfig) -> bool {
        Utc::now() > self.last_accessed_at + config.idle_timeout
    }

    /// Check if the session is valid (not expired, not idle)
    #[must_use]
    pub fn is_valid(&self, config: &SessionConfig) -> bool {
        !self.is_expired() && !self.is_idle_expired(config)
    }

    /// Touch the session (update last accessed time)
    pub fn touch(&mut self) {
        self.last_accessed_at = Utc::now();
    }

    /// Validate session binding matches
    ///
    /// Returns `true` if binding matches or no binding is configured.
    #[must_use]
    pub fn validate_binding(&self, user_agent: Option<&str>, ip: Option<&str>) -> bool {
        match &self.binding {
            Some(binding) => binding.matches(user_agent, ip),
            None => true,
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
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_session_new() {
        let config = SessionConfig::default();
        let session = Session::new("user123", &config);

        assert_eq!(session.user_id, "user123");
        assert!(!session.is_expired());
        assert!(!session.is_idle_expired(&config));
        assert!(session.is_valid(&config));
        assert!(session.binding.is_none());
    }

    #[test]
    fn test_session_touch() {
        let config = SessionConfig::default();
        let mut session = Session::new("user123", &config);

        let original_accessed = session.last_accessed_at;
        sleep(Duration::from_millis(10));
        session.touch();

        assert!(session.last_accessed_at > original_accessed);
    }

    #[test]
    fn test_session_with_binding() {
        let config = SessionConfig::default();
        let binding = SessionBinding::from_context(Some("Mozilla/5.0"), Some("192.168.1.1"));
        let session = Session::new_with_binding("user123", &config, binding);

        assert!(session.binding.is_some());
        assert!(session.validate_binding(Some("Mozilla/5.0"), Some("192.168.1.1")));
    }
}

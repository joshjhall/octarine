//! Security-related audit events
//!
//! Critical for compliance and security monitoring.
//! These events track authentication, authorization, and security violations.

/// Security events for audit trail
#[derive(Debug, Clone)]
pub(super) enum SecurityEvent {
    /// User login attempt
    LoginAttempt {
        username: String,
        method: String, // password, oauth, sso, etc.
    },

    /// Successful login
    LoginSuccess { user_id: String, session_id: String },

    /// Failed login
    LoginFailure { username: String, reason: String },

    /// Permission check denied
    PermissionDenied {
        user_id: String,
        resource: String,
        action: String,
    },

    /// Token expired
    TokenExpired {
        token_type: String,
        user_id: Option<String>,
    },

    /// Rate limit exceeded
    RateLimitExceeded {
        identifier: String,
        limit_type: String,
    },

    /// Security policy violation
    SecurityViolation { policy: String, details: String },
}

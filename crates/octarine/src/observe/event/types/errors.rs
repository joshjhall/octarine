//! Error-related audit events
//!
//! These events are generated when errors occur in the system.
//! They automatically create audit trails for debugging and compliance.

/// Error events that affect control flow
#[derive(Debug, Clone)]
pub(super) enum ErrorEvent {
    /// Validation failed
    Validation {
        field: Option<String>,
        reason: String,
    },

    /// Type conversion failed
    Conversion {
        from_type: String,
        to_type: String,
        reason: String,
    },

    /// Sanitization failed
    Sanitization { input_type: String, reason: String },

    /// Authentication failed
    Authentication { method: String, reason: String },

    /// Authorization failed
    Authorization {
        resource: String,
        action: String,
        reason: String,
    },

    /// Resource not found
    NotFound {
        resource_type: String,
        identifier: String,
    },

    /// System error
    System { component: String, reason: String },
}

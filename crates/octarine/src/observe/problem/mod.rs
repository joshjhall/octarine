//! Problem subsystem - problems that create observability events
//!
//! This module provides problem types that automatically generate
//! observability events when problems occur, ensuring every issue is tracked.

// Core implementation (internal only)
mod create;

// Type definitions
mod types;

// Builder pattern for configurable problem operations
pub(crate) mod builder;

// Builder exports - these are the main way to work with problems
// Internal to observe module only
#[allow(unused_imports)]
pub(in crate::observe) use builder::ProblemBuilder;

// Shortcuts for common patterns (internal to observe)
// These provide pre-configured problems for common use cases
pub(in crate::observe) use builder::shortcuts;

// Public exports - carefully selected for external use
pub use types::{Problem, Result};

// For backward compatibility, expose shortcuts as Problem methods
impl Problem {
    /// Create a validation error (input doesn't meet requirements)
    pub fn validation(msg: impl Into<String>) -> Self {
        shortcuts::validation(msg)
    }

    /// Create a conversion error (failed to convert between types)
    pub fn conversion(msg: impl Into<String>) -> Self {
        shortcuts::conversion(msg)
    }

    /// Create a sanitization error (failed to sanitize input)
    pub fn sanitization(msg: impl Into<String>) -> Self {
        shortcuts::sanitization(msg)
    }

    /// Create a configuration error (invalid configuration)
    pub fn config(msg: impl Into<String>) -> Self {
        shortcuts::config(msg)
    }

    /// Create a not found error (resource doesn't exist)
    pub fn not_found(what: impl Into<String>) -> Self {
        shortcuts::not_found(what)
    }

    /// Create an authentication error (failed to authenticate)
    pub fn auth(msg: impl Into<String>) -> Self {
        shortcuts::auth(msg)
    }

    /// Create a permission denied error (insufficient privileges)
    pub fn permission_denied(msg: impl Into<String>) -> Self {
        shortcuts::permission_denied(msg)
    }

    /// Create a security error (security violation detected)
    pub fn security(msg: impl Into<String>) -> Self {
        shortcuts::security(msg)
    }

    /// Create a network error (network operation failed)
    pub fn network(msg: impl Into<String>) -> Self {
        shortcuts::network(msg)
    }

    /// Create a database error (database operation failed)
    pub fn database(msg: impl Into<String>) -> Self {
        shortcuts::database(msg)
    }

    /// Create a parse error (failed to parse input)
    pub fn parse(msg: impl Into<String>) -> Self {
        shortcuts::parse(msg)
    }

    /// Create a timeout error (operation exceeded time limit)
    pub fn timeout(msg: impl Into<String>) -> Self {
        shortcuts::timeout(msg)
    }

    /// Create an operation failed error (generic operation failure)
    pub fn operation_failed(msg: impl Into<String>) -> Self {
        shortcuts::operation_failed(msg)
    }

    /// Create an other/unknown error (catch-all for uncategorized errors)
    pub fn other(msg: impl Into<String>) -> Self {
        shortcuts::other(msg)
    }
}

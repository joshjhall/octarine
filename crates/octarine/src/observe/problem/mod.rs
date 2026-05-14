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

/// Observability-enabled constructors for [`Problem`].
///
/// `Problem` is defined in the `octarine-problem` micro-crate to keep its
/// recompilation blast radius small. Rust's orphan rules prevent us from
/// attaching inherent methods to it from `octarine::observe`, so these
/// constructors live on a trait instead. The call syntax is unchanged
/// (`Problem::validation(msg)`) once `ProblemExt` is in scope.
///
/// Several constructors dispatch audit events as a side effect of building
/// the problem (validation, conversion, sanitization, permission_denied,
/// security). Use these instead of constructing variants directly when you
/// want the failure to land in the audit trail.
pub trait ProblemExt: Sized {
    /// Create a validation error (input doesn't meet requirements)
    fn validation(msg: impl Into<String>) -> Self;

    /// Create a conversion error (failed to convert between types)
    fn conversion(msg: impl Into<String>) -> Self;

    /// Create a sanitization error (failed to sanitize input)
    fn sanitization(msg: impl Into<String>) -> Self;

    /// Create a configuration error (invalid configuration)
    fn config(msg: impl Into<String>) -> Self;

    /// Create a not found error (resource doesn't exist)
    fn not_found(what: impl Into<String>) -> Self;

    /// Create an authentication error (failed to authenticate)
    fn auth(msg: impl Into<String>) -> Self;

    /// Create a permission denied error (insufficient privileges)
    fn permission_denied(msg: impl Into<String>) -> Self;

    /// Create a security error (security violation detected)
    fn security(msg: impl Into<String>) -> Self;

    /// Create a network error (network operation failed)
    fn network(msg: impl Into<String>) -> Self;

    /// Create a database error (database operation failed)
    fn database(msg: impl Into<String>) -> Self;

    /// Create a parse error (failed to parse input)
    fn parse(msg: impl Into<String>) -> Self;

    /// Create a timeout error (operation exceeded time limit)
    fn timeout(msg: impl Into<String>) -> Self;

    /// Create an operation failed error (generic operation failure)
    fn operation_failed(msg: impl Into<String>) -> Self;

    /// Create an other/unknown error (catch-all for uncategorized errors)
    fn other(msg: impl Into<String>) -> Self;
}

impl ProblemExt for Problem {
    fn validation(msg: impl Into<String>) -> Self {
        shortcuts::validation(msg)
    }

    fn conversion(msg: impl Into<String>) -> Self {
        shortcuts::conversion(msg)
    }

    fn sanitization(msg: impl Into<String>) -> Self {
        shortcuts::sanitization(msg)
    }

    fn config(msg: impl Into<String>) -> Self {
        shortcuts::config(msg)
    }

    fn not_found(what: impl Into<String>) -> Self {
        shortcuts::not_found(what)
    }

    fn auth(msg: impl Into<String>) -> Self {
        shortcuts::auth(msg)
    }

    fn permission_denied(msg: impl Into<String>) -> Self {
        shortcuts::permission_denied(msg)
    }

    fn security(msg: impl Into<String>) -> Self {
        shortcuts::security(msg)
    }

    fn network(msg: impl Into<String>) -> Self {
        shortcuts::network(msg)
    }

    fn database(msg: impl Into<String>) -> Self {
        shortcuts::database(msg)
    }

    fn parse(msg: impl Into<String>) -> Self {
        shortcuts::parse(msg)
    }

    fn timeout(msg: impl Into<String>) -> Self {
        shortcuts::timeout(msg)
    }

    fn operation_failed(msg: impl Into<String>) -> Self {
        shortcuts::operation_failed(msg)
    }

    fn other(msg: impl Into<String>) -> Self {
        shortcuts::other(msg)
    }
}

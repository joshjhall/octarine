//! Foundation error type for octarine
//!
//! Provides the `Problem` enum and `Result` type alias used throughout
//! octarine. Extracted into its own crate so changes to error variants
//! recompile only this micro-crate, not every consumer file.
//!
//! ## Architecture Note
//!
//! This is the **central definition** for octarine's error type. It has no
//! dependencies on observe or other octarine modules — the `observe` crate
//! re-exports these types and adds observability features (event dispatch,
//! builders) on top.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use octarine_problem::{Problem, Result};
//!
//! fn validate_input(input: &str) -> Result<()> {
//!     if input.is_empty() {
//!         return Err(Problem::Validation("Input cannot be empty".into()));
//!     }
//!     Ok(())
//! }
//! ```

use thiserror::Error;

/// Problem type for all operations
///
/// This enum provides a clean problem hierarchy. When used through the `observe`
/// module's shortcuts (e.g., `Problem::validation()`), problems automatically
/// generate observability events.
#[derive(Debug, Error)]
pub enum Problem {
    /// Configuration-related errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Input validation errors
    #[error("Validation error: {0}")]
    Validation(String),

    /// Type conversion errors
    #[error("Conversion error: {0}")]
    Conversion(String),

    /// Input sanitization errors
    #[error("Sanitization error: {0}")]
    Sanitization(String),

    /// File I/O errors
    #[error("IO error")]
    Io(#[from] std::io::Error),

    /// Parsing errors
    #[error("Parse error: {0}")]
    Parse(String),

    /// Network errors
    #[error("Network error: {0}")]
    Network(String),

    /// Authentication/authorization errors
    #[error("Authentication failed: {0}")]
    Auth(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Not found errors
    #[error("{0} not found")]
    NotFound(String),

    /// Already exists errors
    #[error("{0} already exists")]
    AlreadyExists(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimited(std::time::Duration),

    /// Operation timeout
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Async runtime errors (channels, workers, executors, circuit breakers)
    #[error("Runtime error: {0}")]
    Runtime(String),

    /// Database errors
    #[error("Database error: {0}")]
    Database(String),

    /// Generic operation failed
    #[error("Operation failed: {0}")]
    OperationFailed(String),

    /// Other error
    #[error("{0}")]
    Other(String),
}

/// Result type alias using Problem
pub type Result<T> = std::result::Result<T, Problem>;

// =============================================================================
// Event-free constructors (Layer 0 — no observe dependency)
// =============================================================================

/// Event-free constructors for [`Problem`].
///
/// This is the **Layer 1 (primitives)** constructor surface. It mirrors the
/// method names of `observe::ProblemExt` so call sites read identically
/// (`Problem::validation(msg)`), but building a problem through this trait has
/// **no side effects** — it never dispatches an observability event.
///
/// `octarine::primitives` re-exports this trait (aliased as `ProblemExt`) so
/// pure primitives can construct typed problems without reaching into the
/// observe layer, keeping the dependency graph unidirectional. Layer 2
/// (`observe`) has its own same-named trait whose constructors additionally
/// emit audit events for security- and user-attributable failures; Layer 3
/// wrappers are where that audit coverage belongs.
///
/// Each method returns the same [`Problem`] variant the observe-layer
/// constructor produces, so the two paths differ only in the event side
/// effect — the error value is identical.
pub trait ProblemConstructors: Sized {
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
    ///
    /// Returns the [`Problem::PermissionDenied`] variant, matching the
    /// observe-layer `security` constructor.
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

impl ProblemConstructors for Problem {
    fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }

    fn conversion(msg: impl Into<String>) -> Self {
        Self::Conversion(msg.into())
    }

    fn sanitization(msg: impl Into<String>) -> Self {
        Self::Sanitization(msg.into())
    }

    fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    fn not_found(what: impl Into<String>) -> Self {
        Self::NotFound(what.into())
    }

    fn auth(msg: impl Into<String>) -> Self {
        Self::Auth(msg.into())
    }

    fn permission_denied(msg: impl Into<String>) -> Self {
        Self::PermissionDenied(msg.into())
    }

    fn security(msg: impl Into<String>) -> Self {
        // Matches observe's `create_security`, which returns PermissionDenied.
        Self::PermissionDenied(msg.into())
    }

    fn network(msg: impl Into<String>) -> Self {
        Self::Network(msg.into())
    }

    fn database(msg: impl Into<String>) -> Self {
        Self::Database(msg.into())
    }

    fn parse(msg: impl Into<String>) -> Self {
        Self::Parse(msg.into())
    }

    fn timeout(msg: impl Into<String>) -> Self {
        Self::Timeout(msg.into())
    }

    fn operation_failed(msg: impl Into<String>) -> Self {
        Self::OperationFailed(msg.into())
    }

    fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}

// =============================================================================
// Primitive helper functions (no observe dependency)
// =============================================================================

impl Problem {
    /// Create an I/O error from a message
    ///
    /// This is a primitive helper that doesn't trigger observe events.
    /// For observe-enabled I/O errors, use the observe module shortcuts.
    pub fn io(msg: impl Into<String>) -> Self {
        Self::OperationFailed(format!("IO error: {}", msg.into()))
    }
}

// Convenience From implementations
impl From<String> for Problem {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}

impl From<&str> for Problem {
    fn from(s: &str) -> Self {
        Self::Other(s.to_string())
    }
}

impl From<serde_json::Error> for Problem {
    fn from(err: serde_json::Error) -> Self {
        Self::Parse(err.to_string())
    }
}

// xshell error conversion (xshell is always included as dependency)
impl From<xshell::Error> for Problem {
    fn from(e: xshell::Error) -> Self {
        Problem::OperationFailed(format!("Shell command failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_problem_display() {
        let p = Problem::Validation("test error".into());
        assert_eq!(p.to_string(), "Validation error: test error");
    }

    #[test]
    fn test_problem_from_string() {
        let p: Problem = "test".into();
        assert!(matches!(p, Problem::Other(_)));
    }

    #[test]
    fn test_result_type_alias() {
        fn returns_ok() -> Result<i32> {
            Ok(42)
        }
        fn returns_err() -> Result<i32> {
            Err(Problem::Validation("test".into()))
        }

        assert!(returns_ok().is_ok());
        assert!(returns_err().is_err());
    }

    #[test]
    fn test_result_err() {
        let r: Result<i32> = Err(Problem::NotFound("item".into()));
        assert!(r.is_err());
    }

    #[test]
    fn test_constructors_input_variants() {
        assert!(matches!(Problem::validation("m"), Problem::Validation(_)));
        assert!(matches!(Problem::conversion("m"), Problem::Conversion(_)));
        assert!(matches!(
            Problem::sanitization("m"),
            Problem::Sanitization(_)
        ));
        assert!(matches!(Problem::parse("m"), Problem::Parse(_)));
    }

    #[test]
    fn test_constructors_security_variants() {
        assert!(matches!(Problem::auth("m"), Problem::Auth(_)));
        assert!(matches!(
            Problem::permission_denied("m"),
            Problem::PermissionDenied(_)
        ));
        // security maps to PermissionDenied, matching observe's create_security.
        assert!(matches!(
            Problem::security("m"),
            Problem::PermissionDenied(_)
        ));
    }

    #[test]
    fn test_constructors_operational_variants() {
        assert!(matches!(Problem::config("m"), Problem::Config(_)));
        assert!(matches!(Problem::not_found("m"), Problem::NotFound(_)));
        assert!(matches!(Problem::network("m"), Problem::Network(_)));
        assert!(matches!(Problem::database("m"), Problem::Database(_)));
        assert!(matches!(Problem::timeout("m"), Problem::Timeout(_)));
        assert!(matches!(
            Problem::operation_failed("m"),
            Problem::OperationFailed(_)
        ));
        assert!(matches!(Problem::other("m"), Problem::Other(_)));
    }

    #[test]
    fn test_constructors_preserve_message() {
        let p = Problem::validation("bad input");
        assert_eq!(p.to_string(), "Validation error: bad input");
    }
}

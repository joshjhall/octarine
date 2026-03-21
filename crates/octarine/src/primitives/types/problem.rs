//! Problem type definitions
//!
//! Foundation error types for rust-core. These are pure types with no dependencies
//! on observe or other internal modules, making them safe to use in primitives.
//!
//! ## Architecture Note
//!
//! This is a **primitive** module in `types/` - core foundational types. It has
//! NO dependencies on observe or other internal modules. The `observe` module
//! re-exports these types and adds observability features (event dispatching,
//! builders) on top.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use octarine::primitives::types::{Problem, Result};
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
/// module's shortcuts (e.g., `Problem::Validation()`), problems automatically
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
}

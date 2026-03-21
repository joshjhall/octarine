//! Cross-module shortcuts for observe
//!
//! These shortcuts combine context + event + problem for common
//! observability patterns. They provide the most convenient API
//! for typical logging and error handling scenarios.
//!
//! This is the public API - it delegates to builder shortcuts.

use super::builder::aggregate_shortcuts;
use super::builder::event_shortcuts;
use super::event; // Use event module directly for its re-exported functions
use super::problem::Problem;

/// Log an info message with operation context
pub fn info(operation: &str, message: impl Into<String>) {
    event_shortcuts::info(operation, message);
}

/// Log a debug message with operation context
pub fn debug(operation: &str, message: impl Into<String>) {
    event_shortcuts::debug(operation, message);
}

/// Log a warning with operation context
pub fn warn(operation: &str, message: impl Into<String>) {
    event_shortcuts::warn(operation, message);
}

/// Log an error with operation context (non-fatal)
pub fn error(operation: &str, message: impl Into<String>) {
    event_shortcuts::error(operation, message);
}

/// Log a successful operation
pub fn success(operation: &str, message: impl Into<String>) {
    event_shortcuts::success(operation, message);
}

/// Log a trace message with operation context (very detailed)
pub fn trace(operation: &str, message: impl Into<String>) {
    event_shortcuts::trace(operation, message);
}

/// Log a validation success
pub fn validation_success(message: impl Into<String>) {
    success("validation", message);
}

/// Log an authentication success
pub fn auth_success(user: &str) {
    event::auth_success(user);
}

// ==========================================
// ERROR HANDLING PATTERNS (Context + Event + Problem)
// ==========================================

/// Log an error with context and return a Problem
///
/// This combines logging an error event with returning a problem,
/// ensuring the error is both logged and propagated.
pub fn fail(operation: &str, message: impl Into<String>) -> Problem {
    aggregate_shortcuts::fail(operation, message)
}

/// Log a security error and return a security Problem
///
/// Use this for security-relevant errors that need full audit logging.
pub fn fail_security(operation: &str, message: impl Into<String>) -> Problem {
    aggregate_shortcuts::fail_security(operation, message)
}

/// Log a permission denied error and return Problem
pub fn fail_permission(operation: &str, user: &str, resource: &str) -> Problem {
    aggregate_shortcuts::fail_permission(operation, user, resource)
}

/// Log a validation error and return Problem
pub fn fail_validation(field: &str, message: impl Into<String>) -> Problem {
    aggregate_shortcuts::fail_validation(field, message)
}

// ==========================================
// DEVELOPMENT HELPERS
// ==========================================

/// Quick debug with minimal context
pub fn debug_here(message: impl Into<String>) {
    event::debug(message);
}

/// Mark unimplemented feature and return Problem
pub fn todo(feature: &str) -> Problem {
    aggregate_shortcuts::todo(feature)
}

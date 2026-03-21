//! Shortcut functions for observe operations
//!
//! Provides convenient functions that create a unified builder and call methods.
//! These wrap the ObserveBuilder to provide a simpler API.

use super::ObserveBuilder;
use crate::observe::problem::Problem;

// ==========================================
// LOGGING SHORTCUTS
// ==========================================

/// Log info message with operation context
pub fn info(operation: &str, message: impl Into<String>) {
    ObserveBuilder::for_operation(operation)
        .message(message)
        .info();
}

/// Log debug message with operation context
pub fn debug(operation: &str, message: impl Into<String>) {
    ObserveBuilder::for_operation(operation)
        .message(message)
        .debug();
}

/// Log warning with operation context
pub fn warn(operation: &str, message: impl Into<String>) {
    ObserveBuilder::for_operation(operation)
        .message(message)
        .warn();
}

/// Log error with operation context
pub fn error(operation: &str, message: impl Into<String>) {
    ObserveBuilder::for_operation(operation)
        .message(message)
        .error();
}

/// Log success with operation context
pub fn success(operation: &str, message: impl Into<String>) {
    ObserveBuilder::for_operation(operation)
        .message(message)
        .success();
}

/// Log trace with operation context
pub fn trace(operation: &str, message: impl Into<String>) {
    ObserveBuilder::for_operation(operation)
        .message(message)
        .trace();
}

// ==========================================
// ERROR HANDLING SHORTCUTS
// ==========================================

/// Log error and return Problem
pub fn fail(operation: &str, message: impl Into<String>) -> Problem {
    ObserveBuilder::for_operation(operation)
        .message(message)
        .fail()
}

/// Log security error and return Problem
pub fn fail_security(operation: &str, message: impl Into<String>) -> Problem {
    ObserveBuilder::for_operation(operation)
        .message(message)
        .fail_security_agg()
}

/// Log permission denied and return Problem
pub fn fail_permission(operation: &str, user: &str, resource: &str) -> Problem {
    ObserveBuilder::for_operation(operation).fail_permission_agg(user, resource)
}

/// Log validation error and return Problem
pub fn fail_validation(field: &str, message: impl Into<String>) -> Problem {
    ObserveBuilder::for_operation("validation")
        .message(message)
        .fail_validation_agg(field)
}

/// Mark TODO and return Problem
pub fn todo(feature: &str) -> Problem {
    ObserveBuilder::for_operation(feature).todo_agg()
}

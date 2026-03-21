//! Shortcut functions for event operations
//!
//! Provides convenient functions for logging events.
//! These are scoped to event operations only.

use super::ObserveBuilder;

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

//! Aggregate observability operations
//!
//! Domain functions that combine context + event + problem for common patterns.
//! These are the business logic implementations that builders delegate to.

use super::context::shortcuts as context_shortcuts;
use super::event::EventBuilder;
use super::problem::Problem;
use super::problem::builder::shortcuts as problem_shortcuts;

// ==========================================
// LOGGING PATTERNS (Context + Event)
// ==========================================

/// Log a message with operation context
pub(super) fn log_with_operation(level: LogLevel, operation: &str, message: impl Into<String>) {
    let context = context_shortcuts::full_builder()
        .with_operation(operation)
        .build();

    dispatch_with_level(level, message, context);
}

/// Log levels for dispatch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Success,
    Trace,
}

/// Dispatch event at specific log level
fn dispatch_with_level(level: LogLevel, message: impl Into<String>, context: super::EventContext) {
    let builder = EventBuilder::new(message).with_context(context);

    match level {
        LogLevel::Debug => builder.debug(),
        LogLevel::Info => builder.info(),
        LogLevel::Warn => builder.warn(),
        LogLevel::Error => builder.error(),
        LogLevel::Success => builder.success(),
        LogLevel::Trace => builder.trace(),
    }
}

// ==========================================
// ERROR HANDLING PATTERNS (Context + Event + Problem)
// ==========================================

/// Log error with context and return Problem
pub(super) fn fail_with_operation(operation: &str, message: impl Into<String>) -> Problem {
    let msg = message.into();

    // Log the error with context
    log_with_operation(LogLevel::Error, operation, msg.clone());

    // Return a problem
    problem_shortcuts::validation(msg)
}

/// Log security error with context and return Problem
pub(super) fn fail_security_with_operation(operation: &str, message: impl Into<String>) -> Problem {
    let msg = message.into();

    // Log as critical security event
    let context = context_shortcuts::security_builder()
        .with_operation(operation)
        .build();

    EventBuilder::new(msg.clone())
        .with_context(context)
        .critical();

    // Return security problem
    problem_shortcuts::security(msg)
}

/// Log permission denied with context and return Problem
pub(super) fn fail_permission_with_context(operation: &str, user: &str, resource: &str) -> Problem {
    let msg = format_permission_denied(user, resource, operation);

    // Log with security context
    let context = context_shortcuts::authentication_builder(user)
        .with_operation(operation)
        .security_relevant(true)
        .build();

    EventBuilder::new(&msg).with_context(context).critical();

    // Return permission problem
    problem_shortcuts::permission_denied(msg)
}

/// Format permission denied message
fn format_permission_denied(user: &str, resource: &str, operation: &str) -> String {
    format!(
        "User {} denied access to {} during {}",
        user, resource, operation
    )
}

/// Log validation error with field context and return Problem
pub(super) fn fail_validation_for_field(field: &str, message: impl Into<String>) -> Problem {
    let msg = message.into();
    let full_msg = format_validation_error(field, msg);

    // Log validation error
    log_with_operation(LogLevel::Error, "validation", &full_msg);

    // Return validation problem
    problem_shortcuts::validation(full_msg)
}

/// Format validation error message
fn format_validation_error(field: &str, message: String) -> String {
    format!("Validation failed for {}: {}", field, message)
}

// ==========================================
// DEVELOPMENT HELPERS
// ==========================================

/// Mark unimplemented feature, log warning, and return Problem
pub(super) fn mark_todo(feature: &str) -> Problem {
    let msg = format_todo_message(feature);
    log_with_operation(LogLevel::Warn, "todo", &msg);
    problem_shortcuts::system(msg)
}

/// Format TODO message
fn format_todo_message(feature: &str) -> String {
    format!("TODO: {} not implemented", feature)
}

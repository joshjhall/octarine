//! Event shortcuts for common logging patterns
//!
//! These shortcuts provide quick ways to dispatch events without
//! needing to build them manually. They all use full context capture.
//!
//! For more control, use EventBuilder directly.

use crate::observe::context::shortcuts as context_shortcuts;
use crate::observe::event::builder::EventBuilder;

// ==========================================
// LOGGING SHORTCUTS
// ==========================================

/// Dispatches a debug event immediately
pub fn debug(message: impl Into<String>) {
    EventBuilder::new(message)
        .with_context(context_shortcuts::full())
        .debug();
}

/// Dispatches an info event immediately
pub fn info(message: impl Into<String>) {
    EventBuilder::new(message)
        .with_context(context_shortcuts::full())
        .info();
}

/// Dispatches a warning event immediately
pub fn warn(message: impl Into<String>) {
    EventBuilder::new(message)
        .with_context(context_shortcuts::full())
        .warn();
}

/// Dispatches an error event immediately (just logs, no Problem)
pub fn error(message: impl Into<String>) {
    EventBuilder::new(message)
        .with_context(context_shortcuts::full())
        .error();
}

/// Dispatches a critical event immediately
pub fn critical(message: impl Into<String>) {
    EventBuilder::new(message)
        .with_context(context_shortcuts::security())
        .critical();
}

// ==========================================
// BUSINESS EVENT SHORTCUTS
// ==========================================

/// Dispatches a success event immediately
pub fn success(message: impl Into<String>) {
    EventBuilder::new(message)
        .with_context(context_shortcuts::full())
        .success();
}

/// Dispatches a trace event immediately (for detailed debugging)
pub fn trace(message: impl Into<String>) {
    EventBuilder::new(message)
        .with_context(context_shortcuts::minimal())
        .debug(); // Trace is just debug with minimal context
}

// ==========================================
// SECURITY EVENT SHORTCUTS
// ==========================================

/// Dispatches an authentication success event
pub fn auth_success(user: &str) {
    EventBuilder::new(format!("Authentication successful for user: {}", user))
        .with_context(context_shortcuts::authentication(user))
        .auth_success();
}

/// Dispatches an authentication failure event
pub fn auth_failure(user: &str, _reason: &str) {
    EventBuilder::new(format!("Authentication failed for user: {}", user))
        .with_context(context_shortcuts::authentication(user))
        .auth_failure();
}

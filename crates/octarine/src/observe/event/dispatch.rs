//! Event dispatch implementation functions (INTERNAL)
//!
//! These functions create and dispatch observability events.
//! Access these through the builder pattern or shortcuts, not directly.

use crate::observe::types::{Event, EventType};
use crate::observe::writers;
use std::collections::HashMap;

/// Apply metadata to an event
fn apply_metadata(mut event: Event, metadata: HashMap<String, serde_json::Value>) -> Event {
    for (key, value) in metadata {
        event = event.with_metadata(key, value);
    }
    event
}

// Implementation functions for event dispatch
// These are pub(super) so the builder can delegate to them
/// Dispatch a debug event with context and metadata
pub(super) fn dispatch_debug(
    message: impl Into<String>,
    context: crate::observe::EventContext,
    metadata: HashMap<String, serde_json::Value>,
) {
    let mut event = Event::new(EventType::Debug, message);
    event = event.with_context(context);
    event = apply_metadata(event, metadata);
    writers::dispatch(event);
}

/// Dispatch an info event with context and metadata
pub(super) fn dispatch_info(
    message: impl Into<String>,
    context: crate::observe::EventContext,
    metadata: HashMap<String, serde_json::Value>,
) {
    let mut event = Event::new(EventType::Info, message);
    event = event.with_context(context);
    event = apply_metadata(event, metadata);
    writers::dispatch(event);
}

/// Dispatch a warning event with context and metadata
pub(super) fn dispatch_warning(
    message: impl Into<String>,
    context: crate::observe::EventContext,
    metadata: HashMap<String, serde_json::Value>,
) {
    let mut event = Event::new(EventType::Warning, message);
    event = event.with_context(context);
    event = apply_metadata(event, metadata);
    writers::dispatch(event);
}

/// Dispatch an error event and return a Problem
pub(super) fn dispatch_error_with_problem(
    message: impl Into<String>,
    context: crate::observe::EventContext,
    metadata: HashMap<String, serde_json::Value>,
) -> crate::observe::problem::Problem {
    let msg = message.into();
    let mut event = Event::new(EventType::ValidationError, &msg);
    event = event.with_context(context);
    event = apply_metadata(event, metadata);
    writers::dispatch(event);

    // Return a Problem for error handling
    crate::observe::problem::Problem::validation(msg)
}

/// Dispatch an error event (just logs, no Problem)
pub(super) fn dispatch_error(
    message: impl Into<String>,
    context: crate::observe::EventContext,
    metadata: HashMap<String, serde_json::Value>,
) {
    let mut event = Event::new(EventType::SystemError, message);
    event = event.with_context(context);
    event = apply_metadata(event, metadata);
    writers::dispatch(event);
}

/// Dispatch a critical event with context and metadata
pub(super) fn dispatch_critical(
    message: impl Into<String>,
    context: crate::observe::EventContext,
    metadata: HashMap<String, serde_json::Value>,
) {
    let mut event = Event::new(EventType::SystemError, message);
    event = event.with_context(context);
    event = apply_metadata(event, metadata);
    writers::dispatch(event);
}

/// Dispatch a success event with context and metadata
pub(super) fn dispatch_success(
    message: impl Into<String>,
    context: crate::observe::EventContext,
    metadata: HashMap<String, serde_json::Value>,
) {
    let mut event = Event::new(EventType::ResourceCreated, message);
    event = event.with_context(context);
    event = apply_metadata(event, metadata);
    writers::dispatch(event);
}

/// Dispatch a trace event if TRACE env var is set
pub(super) fn dispatch_trace(
    message: impl Into<String>,
    context: crate::observe::EventContext,
    metadata: HashMap<String, serde_json::Value>,
) {
    if std::env::var("TRACE").is_ok() {
        let mut event = Event::new(EventType::Debug, message);
        event = event.with_context(context);
        event = apply_metadata(event, metadata);
        writers::dispatch(event);
    }
}

/// Dispatch an authentication success event
pub(super) fn dispatch_auth_success(user: &str, context: crate::observe::EventContext) {
    let msg = format!("User {} authenticated successfully", user);
    let mut event = Event::new(EventType::LoginSuccess, msg);
    event = event.with_context(context);
    writers::dispatch(event);
}

/// Dispatch an authentication failure event
pub(super) fn dispatch_auth_failure(
    user: &str,
    reason: &str,
    context: crate::observe::EventContext,
) {
    let msg = format!("Authentication failed for user {}: {}", user, reason);
    let mut event = Event::new(EventType::LoginFailure, msg);
    event = event.with_context(context);
    writers::dispatch(event);
}

/// Extract username from message (helper for builder)
///
/// Looks for "user:" pattern in message and extracts the username.
/// Returns empty string if pattern not found.
pub(super) fn extract_user_from_message(message: &str) -> &str {
    if message.contains("user:") {
        message.split("user:").nth(1).unwrap_or("").trim()
    } else {
        ""
    }
}

/// Dispatch auth success from message (parses user from message)
pub(super) fn dispatch_auth_success_from_message(
    message: String,
    context: crate::observe::EventContext,
) {
    let user = extract_user_from_message(&message);
    dispatch_auth_success(user, context);
}

/// Dispatch auth failure from message (parses user from message)
pub(super) fn dispatch_auth_failure_from_message(
    message: String,
    context: crate::observe::EventContext,
) {
    let user = extract_user_from_message(&message);
    dispatch_auth_failure(user, "Authentication failed", context);
}

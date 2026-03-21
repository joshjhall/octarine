//! Problem creation implementation functions (INTERNAL)
//!
//! These functions create problems and dispatch observability events.
//! Access these through the builder pattern or shortcuts, not directly.
//!
//! # Event Dispatch Policy
//!
//! Problem types are categorized by whether they warrant automatic observability events.
//! This is an intentional design decision based on the nature of the problem.
//!
//! ## Events Dispatched (security/user-action relevant)
//!
//! These problems create audit trails because they indicate security-relevant or
//! user-attributable issues:
//!
//! | Problem Type | Event Level | Rationale |
//! |--------------|-------------|-----------|
//! | `validation` | Warning | User input errors - attributable to user |
//! | `conversion` | Warning | Data format issues - bad input data |
//! | `sanitization` | Error | Potential attack attempts |
//! | `permission_denied` | Warning | Authorization failures - security relevant |
//! | `security` | Critical | Attack detection - immediate attention needed |
//!
//! ## No Events Dispatched (operational/infrastructure)
//!
//! These problems do NOT dispatch events because they represent operational issues
//! that are typically logged at call sites with more context:
//!
//! - `config` - Configuration errors (startup time, no user context)
//! - `not_found` - Resource not found (often expected, logged by caller)
//! - `auth` - Authentication errors (logged by auth middleware)
//! - `network` - Network errors (logged with retry/circuit breaker context)
//! - `database` - Database errors (logged with query context)
//! - `parse` - Parse errors (logged with input context)
//! - `timeout` - Timeout errors (logged with operation context)
//! - `operation_failed` - Generic failures (logged by caller)
//! - `other` - Edge cases (logged by caller)
//!
//! ## Rationale
//!
//! Security-relevant problems warrant automatic audit trails to ensure they are
//! never silently swallowed. Operational problems are better logged at call sites
//! where more context is available (retry count, connection pool state, etc.).

use super::types::Problem;
use crate::observe::types::{Event, EventType};
use crate::observe::writers;

// Implementation functions for problem creation
// These are pub(super) so the builder can delegate to them

/// Create a validation problem and dispatch event
pub(super) fn create_validation(
    msg: impl Into<String>,
    context: crate::observe::EventContext,
) -> Problem {
    let message = msg.into();

    // Validation failures are warnings - likely user error, not system error
    let mut event = Event::new(EventType::Warning, &message);
    event = event.with_context(context);
    writers::dispatch(event);

    Problem::Validation(message)
}

/// Create a conversion problem and dispatch event
pub(super) fn create_conversion(
    msg: impl Into<String>,
    context: crate::observe::EventContext,
) -> Problem {
    let message = msg.into();

    // Conversion failures are warnings - bad data format, not system error
    let mut event = Event::new(EventType::Warning, &message);
    event = event.with_context(context);
    writers::dispatch(event);

    Problem::Conversion(message)
}

/// Create a sanitization problem and dispatch event
/// Sanitization failures might indicate attacks, so they log at ERROR level
pub(super) fn create_sanitization(
    msg: impl Into<String>,
    context: crate::observe::EventContext,
) -> Problem {
    let message = msg.into();

    // Sanitization failures could be attacks - log as error
    let mut event = Event::new(EventType::SanitizationError, &message);
    event = event.with_context(context);
    writers::dispatch(event);

    Problem::Sanitization(message)
}

/// Create a config problem (no event dispatched)
pub(super) fn create_config(msg: impl Into<String>) -> Problem {
    Problem::Config(msg.into())
}

/// Create a not found problem (no event dispatched)
pub(super) fn create_not_found(what: impl Into<String>) -> Problem {
    Problem::NotFound(what.into())
}

/// Create an auth problem (no event dispatched)
pub(super) fn create_auth(msg: impl Into<String>) -> Problem {
    Problem::Auth(msg.into())
}

/// Create a permission denied problem and dispatch event
pub(super) fn create_permission_denied(
    msg: impl Into<String>,
    context: crate::observe::EventContext,
) -> Problem {
    let message = msg.into();

    // Log as warning - permission issues are notable
    let mut event = Event::new(EventType::AuthorizationError, &message);
    event = event.with_context(context);
    writers::dispatch(event);

    Problem::PermissionDenied(message)
}

/// Create a security problem and dispatch critical event
/// Use for: attack detection, injection attempts, privilege escalation, data exfiltration
pub(super) fn create_security(
    msg: impl Into<String>,
    context: crate::observe::EventContext,
) -> Problem {
    let message = msg.into();

    // Security issues are CRITICAL - they need immediate attention
    let mut event = Event::new(EventType::AuthorizationError, &message);
    event = event.with_context(context);
    writers::dispatch(event);

    // Also log as critical for immediate visibility
    crate::observe::event::critical(format!("SECURITY: {}", &message));

    Problem::PermissionDenied(message)
}

/// Create a network problem (no event dispatched)
pub(super) fn create_network(msg: impl Into<String>) -> Problem {
    Problem::Network(msg.into())
}

/// Create a database problem (no event dispatched)
pub(super) fn create_database(msg: impl Into<String>) -> Problem {
    Problem::Database(msg.into())
}

/// Create a parse problem (no event dispatched)
pub(super) fn create_parse(msg: impl Into<String>) -> Problem {
    Problem::Parse(msg.into())
}

/// Create a timeout problem (no event dispatched)
pub(super) fn create_timeout(msg: impl Into<String>) -> Problem {
    Problem::Timeout(msg.into())
}

/// Create an operation failed problem (no event dispatched)
pub(super) fn create_operation_failed(msg: impl Into<String>) -> Problem {
    Problem::OperationFailed(msg.into())
}

/// Create an "other" problem for edge cases (no event dispatched)
pub(super) fn create_other(msg: impl Into<String>) -> Problem {
    Problem::Other(msg.into())
}

// Note: From implementations are now in primitives::problem

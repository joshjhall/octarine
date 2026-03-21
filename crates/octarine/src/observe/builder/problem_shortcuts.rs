//! Shortcut functions for problem operations
//!
//! Provides convenient functions for creating problems.
//! These are scoped to problem operations only.

use super::ObserveBuilder;
use crate::observe::problem::Problem;

/// Create validation problem
pub fn validation(message: impl Into<String>) -> Problem {
    ObserveBuilder::new().message(message).validation_problem()
}

/// Create security problem
pub fn security(message: impl Into<String>) -> Problem {
    ObserveBuilder::new().message(message).security_problem()
}

/// Create permission denied problem
pub fn permission_denied(message: impl Into<String>) -> Problem {
    ObserveBuilder::new().message(message).permission_problem()
}

/// Create sanitization problem
pub fn sanitization(message: impl Into<String>) -> Problem {
    ObserveBuilder::new()
        .message(message)
        .sanitization_problem()
}

/// Create conversion problem
pub fn conversion(message: impl Into<String>) -> Problem {
    ObserveBuilder::new().message(message).conversion_problem()
}

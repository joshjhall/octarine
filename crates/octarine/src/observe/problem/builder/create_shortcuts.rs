//! Problem shortcuts for common error patterns
//!
//! These shortcuts provide quick ways to create problems without
//! needing to build them manually. They all capture appropriate context.
//!
//! For more control, use ProblemBuilder directly.

use crate::observe::context::shortcuts as context_shortcuts;
use crate::observe::problem::Problem;
use crate::observe::problem::builder::ProblemBuilder;

// ==========================================
// VALIDATION PROBLEMS
// ==========================================

/// Creates a validation problem immediately
pub fn validation(message: impl Into<String>) -> Problem {
    ProblemBuilder::new(message)
        .with_context(
            context_shortcuts::full_builder()
                .with_operation("validation")
                .build(),
        )
        .validation()
}

/// Creates a validation problem with minimal context
pub fn validation_minimal(message: impl Into<String>) -> Problem {
    ProblemBuilder::new(message)
        .with_context(context_shortcuts::minimal())
        .validation()
}

// ==========================================
// CONVERSION PROBLEMS
// ==========================================

/// Creates a conversion problem immediately
pub fn conversion(message: impl Into<String>) -> Problem {
    ProblemBuilder::new(message)
        .with_context(
            context_shortcuts::full_builder()
                .with_operation("conversion")
                .build(),
        )
        .conversion()
}

// ==========================================
// SANITIZATION PROBLEMS
// ==========================================

/// Creates a sanitization problem immediately
pub fn sanitization(message: impl Into<String>) -> Problem {
    ProblemBuilder::new(message)
        .with_context(
            context_shortcuts::security_builder()
                .with_operation("sanitization")
                .build(),
        )
        .sanitization()
}

// ==========================================
// PERMISSION PROBLEMS
// ==========================================

/// Creates a permission denied problem immediately
pub fn permission_denied(message: impl Into<String>) -> Problem {
    ProblemBuilder::new(message)
        .with_context(context_shortcuts::security())
        .permission_denied()
}

// ==========================================
// SECURITY PROBLEMS
// ==========================================

/// Creates a security problem immediately
pub fn security(message: impl Into<String>) -> Problem {
    ProblemBuilder::new(message)
        .with_context(context_shortcuts::security())
        .security()
}

/// Creates a security problem with full audit context
pub fn security_audit(message: impl Into<String>, user: &str) -> Problem {
    ProblemBuilder::new(message)
        .with_context(context_shortcuts::authentication(user))
        .security()
}

// ==========================================
// SYSTEM PROBLEMS
// ==========================================

/// Creates a system error problem immediately
pub fn system(message: impl Into<String>) -> Problem {
    ProblemBuilder::new(message)
        .with_context(context_shortcuts::full())
        .other() // system() doesn't exist, use other() for now
}

// ==========================================
// CONFIG PROBLEMS
// ==========================================

/// Creates a config problem immediately
pub fn config(message: impl Into<String>) -> Problem {
    ProblemBuilder::new(message).config()
}

// ==========================================
// NOT FOUND PROBLEMS
// ==========================================

/// Creates a not found problem immediately
pub fn not_found(what: impl Into<String>) -> Problem {
    ProblemBuilder::new(what).not_found()
}

// ==========================================
// AUTH PROBLEMS
// ==========================================

/// Creates an auth problem immediately
pub fn auth(message: impl Into<String>) -> Problem {
    ProblemBuilder::new(message).auth()
}

// ==========================================
// NETWORK PROBLEMS
// ==========================================

/// Creates a network problem immediately
pub fn network(message: impl Into<String>) -> Problem {
    ProblemBuilder::new(message).network()
}

// ==========================================
// DATABASE PROBLEMS
// ==========================================

/// Creates a database problem immediately
pub fn database(message: impl Into<String>) -> Problem {
    ProblemBuilder::new(message).database()
}

// ==========================================
// PARSE PROBLEMS
// ==========================================

/// Creates a parse problem immediately
pub fn parse(message: impl Into<String>) -> Problem {
    ProblemBuilder::new(message).parse()
}

// ==========================================
// TIMEOUT PROBLEMS
// ==========================================

/// Creates a timeout problem immediately
pub fn timeout(message: impl Into<String>) -> Problem {
    ProblemBuilder::new(message).timeout()
}

// ==========================================
// OPERATION FAILED PROBLEMS
// ==========================================

/// Creates an operation failed problem immediately
pub fn operation_failed(message: impl Into<String>) -> Problem {
    ProblemBuilder::new(message).operation_failed()
}

// ==========================================
// OTHER PROBLEMS
// ==========================================

/// Creates an other problem immediately
pub fn other(message: impl Into<String>) -> Problem {
    ProblemBuilder::new(message).other()
}

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

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // Note on surprising mappings verified against observe/problem/create.rs:
    //   security() and security_audit() → Problem::PermissionDenied
    //     (the Problem enum has no Security variant; create_security wraps in
    //      PermissionDenied and emits a critical audit event as a side effect).
    //   system() → Problem::Other
    //     (per create_shortcuts.rs note: "system() doesn't exist, use other() for now").

    #[test]
    fn validation_returns_validation_variant() {
        let p = validation("bad input");
        assert!(matches!(&p, Problem::Validation(m) if m == "bad input"));
    }

    #[test]
    fn validation_minimal_returns_validation_variant() {
        let p = validation_minimal("bad input");
        assert!(matches!(&p, Problem::Validation(m) if m == "bad input"));
    }

    #[test]
    fn conversion_returns_conversion_variant() {
        let p = conversion("cannot convert");
        assert!(matches!(&p, Problem::Conversion(m) if m == "cannot convert"));
    }

    #[test]
    fn sanitization_returns_sanitization_variant() {
        let p = sanitization("contains shell meta");
        assert!(matches!(&p, Problem::Sanitization(m) if m == "contains shell meta"));
    }

    #[test]
    fn permission_denied_returns_permission_denied_variant() {
        let p = permission_denied("access denied");
        assert!(matches!(&p, Problem::PermissionDenied(m) if m == "access denied"));
    }

    #[test]
    fn security_returns_permission_denied_variant() {
        // NOTE: shortcut is named `security` but wraps in PermissionDenied — see module comment.
        let p = security("SQL injection attempt");
        assert!(matches!(&p, Problem::PermissionDenied(m) if m == "SQL injection attempt"));
    }

    #[test]
    fn security_audit_returns_permission_denied_variant() {
        let p = security_audit("privilege escalation", "alice");
        assert!(matches!(&p, Problem::PermissionDenied(m) if m == "privilege escalation"));
    }

    #[test]
    fn system_returns_other_variant() {
        // NOTE: shortcut is named `system` but returns Problem::Other — see module comment.
        let p = system("disk full");
        assert!(matches!(&p, Problem::Other(m) if m == "disk full"));
    }

    #[test]
    fn config_returns_config_variant() {
        let p = config("missing API key");
        assert!(matches!(&p, Problem::Config(m) if m == "missing API key"));
    }

    #[test]
    fn not_found_returns_not_found_variant() {
        let p = not_found("user#42");
        assert!(matches!(&p, Problem::NotFound(m) if m == "user#42"));
    }

    #[test]
    fn auth_returns_auth_variant() {
        let p = auth("invalid token");
        assert!(matches!(&p, Problem::Auth(m) if m == "invalid token"));
    }

    #[test]
    fn network_returns_network_variant() {
        let p = network("connection refused");
        assert!(matches!(&p, Problem::Network(m) if m == "connection refused"));
    }

    #[test]
    fn database_returns_database_variant() {
        let p = database("deadlock detected");
        assert!(matches!(&p, Problem::Database(m) if m == "deadlock detected"));
    }

    #[test]
    fn parse_returns_parse_variant() {
        let p = parse("unexpected token");
        assert!(matches!(&p, Problem::Parse(m) if m == "unexpected token"));
    }

    #[test]
    fn timeout_returns_timeout_variant() {
        let p = timeout("request timed out after 30s");
        assert!(matches!(&p, Problem::Timeout(m) if m == "request timed out after 30s"));
    }

    #[test]
    fn operation_failed_returns_operation_failed_variant() {
        let p = operation_failed("retry budget exhausted");
        assert!(matches!(&p, Problem::OperationFailed(m) if m == "retry budget exhausted"));
    }

    #[test]
    fn other_returns_other_variant() {
        let p = other("unclassified error");
        assert!(matches!(&p, Problem::Other(m) if m == "unclassified error"));
    }
}

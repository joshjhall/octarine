//! Create extensions for ProblemBuilder
//!
//! Extends ProblemBuilder with methods that delegate to create implementation.
//! NO business logic here - only delegation to implementation.
//! Implements DUAL FUNCTION pattern for each problem type.

use super::ProblemBuilder;
use crate::observe::problem::Problem;

// Import the create functions we're delegating to
use crate::observe::problem::create::{
    create_auth, create_config, create_conversion, create_database, create_network,
    create_not_found, create_operation_failed, create_other, create_parse,
    create_permission_denied, create_sanitization, create_security, create_timeout,
    create_validation,
};

/// Extensions for ProblemBuilder related to problem creation
impl ProblemBuilder {
    // ==========================================
    // VALIDATION PROBLEMS
    // ==========================================

    /// Returns a builder configured for validation problem (customizable)
    pub fn validation_builder(self) -> Self {
        self // Just return self for further configuration
    }

    /// Create and return a validation problem immediately
    pub fn validation(self) -> Problem {
        let context = self.context.unwrap_or_else(|| {
            crate::observe::context::shortcuts::full_builder()
                .with_operation("validation")
                .build()
        });
        create_validation(self.message, context)
    }

    // ==========================================
    // CONVERSION PROBLEMS
    // ==========================================

    /// Returns a builder configured for conversion problem (customizable)
    pub fn conversion_builder(self) -> Self {
        self
    }

    /// Create and return a conversion problem immediately
    pub fn conversion(self) -> Problem {
        let context = self.context.unwrap_or_else(|| {
            crate::observe::context::shortcuts::full_builder()
                .with_operation("conversion")
                .build()
        });
        create_conversion(self.message, context)
    }

    // ==========================================
    // SANITIZATION PROBLEMS
    // ==========================================

    /// Returns a builder configured for sanitization problem (customizable)
    pub fn sanitization_builder(self) -> Self {
        self
    }

    /// Create and return a sanitization problem immediately
    pub fn sanitization(self) -> Problem {
        let context = self.context.unwrap_or_else(|| {
            crate::observe::context::shortcuts::security_builder()
                .with_operation("sanitization")
                .build()
        });
        create_sanitization(self.message, context)
    }

    // ==========================================
    // PERMISSION PROBLEMS
    // ==========================================

    /// Returns a builder configured for permission denied problem (customizable)
    pub fn permission_denied_builder(self) -> Self {
        self
    }

    /// Create and return a permission denied problem immediately
    pub fn permission_denied(self) -> Problem {
        let context = self.context.unwrap_or_else(|| {
            crate::observe::context::shortcuts::security_builder()
                .with_operation("authorization")
                .build()
        });
        create_permission_denied(self.message, context)
    }

    // ==========================================
    // SECURITY PROBLEMS
    // ==========================================

    /// Returns a builder configured for security problem (customizable)
    pub fn security_builder(self) -> Self {
        self
    }

    /// Create and return a security problem immediately
    pub fn security(self) -> Problem {
        let context = self.context.unwrap_or_else(|| {
            crate::observe::context::shortcuts::security_builder()
                .with_operation("security")
                .build()
        });
        create_security(self.message, context)
    }

    // ==========================================
    // CONFIG PROBLEMS (no events)
    // ==========================================

    /// Returns a builder configured for config problem (customizable)
    pub fn config_builder(self) -> Self {
        self
    }

    /// Create and return a config problem immediately
    pub fn config(self) -> Problem {
        create_config(self.message)
    }

    // ==========================================
    // NOT FOUND PROBLEMS (no events)
    // ==========================================

    /// Returns a builder configured for not found problem (customizable)
    pub fn not_found_builder(self) -> Self {
        self
    }

    /// Create and return a not found problem immediately
    pub fn not_found(self) -> Problem {
        create_not_found(self.message)
    }

    // ==========================================
    // AUTH PROBLEMS (no events)
    // ==========================================

    /// Returns a builder configured for auth problem (customizable)
    pub fn auth_builder(self) -> Self {
        self
    }

    /// Create and return an auth problem immediately
    pub fn auth(self) -> Problem {
        create_auth(self.message)
    }

    // ==========================================
    // NETWORK PROBLEMS (no events)
    // ==========================================

    /// Returns a builder configured for network problem (customizable)
    pub fn network_builder(self) -> Self {
        self
    }

    /// Create and return a network problem immediately
    pub fn network(self) -> Problem {
        create_network(self.message)
    }

    // ==========================================
    // DATABASE PROBLEMS (no events)
    // ==========================================

    /// Returns a builder configured for database problem (customizable)
    pub fn database_builder(self) -> Self {
        self
    }

    /// Create and return a database problem immediately
    pub fn database(self) -> Problem {
        create_database(self.message)
    }

    // ==========================================
    // PARSE PROBLEMS (no events)
    // ==========================================

    /// Returns a builder configured for parse problem (customizable)
    pub fn parse_builder(self) -> Self {
        self
    }

    /// Create and return a parse problem immediately
    pub fn parse(self) -> Problem {
        create_parse(self.message)
    }

    // ==========================================
    // TIMEOUT PROBLEMS (no events)
    // ==========================================

    /// Returns a builder configured for timeout problem (customizable)
    pub fn timeout_builder(self) -> Self {
        self
    }

    /// Create and return a timeout problem immediately
    pub fn timeout(self) -> Problem {
        create_timeout(self.message)
    }

    // ==========================================
    // OPERATION FAILED PROBLEMS (no events)
    // ==========================================

    /// Returns a builder configured for operation failed problem (customizable)
    pub fn operation_failed_builder(self) -> Self {
        self
    }

    /// Create and return an operation failed problem immediately
    pub fn operation_failed(self) -> Problem {
        create_operation_failed(self.message)
    }

    // ==========================================
    // OTHER PROBLEMS (no events)
    // ==========================================

    /// Returns a builder configured for other problem (customizable)
    pub fn other_builder(self) -> Self {
        self
    }

    /// Create and return an other problem immediately
    pub fn other(self) -> Problem {
        create_other(self.message)
    }
}

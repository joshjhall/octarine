//! Aggregate operation extensions for ObserveBuilder
//!
//! Provides high-level operations that combine logging + error handling.
//! These delegate to the aggregate domain functions.

use super::ObserveBuilder;
use crate::observe::aggregate::{
    fail_permission_with_context, fail_security_with_operation, fail_validation_for_field,
    fail_with_operation, mark_todo,
};
use crate::observe::problem::Problem;

/// Extensions for ObserveBuilder related to aggregate operations
impl ObserveBuilder {
    /// Log error and return Problem (combines error event + problem)
    pub fn fail(self) -> Problem {
        fail_with_operation(&self.operation, self.message)
    }

    /// Log security error and return Problem
    pub fn fail_security_agg(self) -> Problem {
        fail_security_with_operation(&self.operation, self.message)
    }

    /// Log permission denied and return Problem
    pub fn fail_permission_agg(self, user: &str, resource: &str) -> Problem {
        fail_permission_with_context(&self.operation, user, resource)
    }

    /// Log validation error for field and return Problem
    pub fn fail_validation_agg(self, field: &str) -> Problem {
        fail_validation_for_field(field, self.message)
    }

    /// Mark as TODO and return Problem
    pub fn todo_agg(self) -> Problem {
        mark_todo(&self.operation)
    }
}

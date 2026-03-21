//! Problem extensions for ObserveBuilder
//!
//! Provides error handling methods that delegate to ProblemBuilder internally.

use super::ObserveBuilder;
use crate::observe::problem::{Problem, ProblemBuilder};

/// Extensions for ObserveBuilder related to problem creation
impl ObserveBuilder {
    /// Create validation problem
    pub fn validation_problem(self) -> Problem {
        ProblemBuilder::new(&self.message)
            .with_context(self.build_context())
            .validation()
    }

    /// Create security problem
    pub fn security_problem(self) -> Problem {
        ProblemBuilder::new(&self.message)
            .with_context(self.build_context())
            .security()
    }

    /// Create permission denied problem
    pub fn permission_problem(self) -> Problem {
        ProblemBuilder::new(&self.message)
            .with_context(self.build_context())
            .permission_denied()
    }

    /// Create sanitization problem
    pub fn sanitization_problem(self) -> Problem {
        ProblemBuilder::new(&self.message)
            .with_context(self.build_context())
            .sanitization()
    }

    /// Create conversion problem
    pub fn conversion_problem(self) -> Problem {
        ProblemBuilder::new(&self.message)
            .with_context(self.build_context())
            .conversion()
    }

    /// Create config problem
    pub fn config_problem(self) -> Problem {
        Problem::config(&self.message)
    }

    /// Create not found problem
    pub fn not_found_problem(self) -> Problem {
        Problem::not_found(&self.message)
    }

    /// Create network problem
    pub fn network_problem(self) -> Problem {
        Problem::network(&self.message)
    }

    /// Create database problem
    pub fn database_problem(self) -> Problem {
        Problem::database(&self.message)
    }
}

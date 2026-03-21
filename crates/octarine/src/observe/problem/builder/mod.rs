//! Problem builder for configurable problem creation
//!
//! Provides a builder pattern for constructing Problems with events.
//! This follows the three-layer pattern where the builder orchestrates
//! but doesn't implement business logic - it delegates to the create implementation.

use crate::observe::EventContext;

// Domain-specific shortcuts module
mod create_shortcuts;

// Re-export domain-specific shortcuts (pub(in crate::observe) for internal observe module use)
pub(in crate::observe) mod shortcuts {
    // Create domain shortcuts
    pub use super::create_shortcuts::*;

    // Future domains could be added here:
    // pub use super::chain_shortcuts::*;
    // pub use super::transform_shortcuts::*;
}

// Extension modules that add methods to ProblemBuilder
mod create;

/// Main problem builder for constructing Problems
#[derive(Debug, Clone)]
pub(in crate::observe) struct ProblemBuilder {
    // Problem configuration
    pub(super) message: String,
    pub(super) context: Option<EventContext>,
}

impl ProblemBuilder {
    /// Create a new problem builder with a message
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            context: None,
        }
    }

    /// Set the event context
    pub fn with_context(mut self, context: EventContext) -> Self {
        self.context = Some(context);
        self
    }
}

impl Default for ProblemBuilder {
    fn default() -> Self {
        Self::new("")
    }
}

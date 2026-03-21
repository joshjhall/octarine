//! Environment extensions for ContextBuilder
//!
//! Extends ContextBuilder with environment-specific methods.
//! NO business logic here - only delegation to implementation.

use super::ContextBuilder;

// Import ONLY the environment functions we're delegating to
use super::super::environment::{is_ci, is_development, is_production};

/// Extensions for ContextBuilder related to environment
impl ContextBuilder {
    /// Add environment metadata to context
    pub fn with_environment_info(self) -> Self {
        // This would populate environment-related fields if they existed in EventContext
        // For now, we can add this info via metadata when that's available
        self
    }

    /// Set security relevance based on environment
    pub fn with_production_security(mut self) -> Self {
        if is_production() {
            self.security_relevant = true;
        }
        self
    }

    /// Enable debug mode if in development
    pub fn with_dev_debug(self) -> Self {
        if is_development() || is_ci() {
            // Would set debug flag if EventContext had one
        }
        self
    }
}

//! Environment identifier builder with observability
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.

use crate::observe::Problem;
use crate::primitives::identifiers::EnvironmentBuilder as PrimitiveEnvironmentBuilder;

/// Environment identifier builder with observability
#[derive(Debug, Clone)]
pub struct EnvironmentBuilder {
    inner: PrimitiveEnvironmentBuilder,
    emit_events: bool,
}

impl Default for EnvironmentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl EnvironmentBuilder {
    /// Create a new EnvironmentBuilder with default configuration and observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PrimitiveEnvironmentBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: PrimitiveEnvironmentBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    /// Create a permissive builder that doesn't check reserved vars
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            inner: PrimitiveEnvironmentBuilder::permissive(),
            emit_events: true,
        }
    }

    /// Set custom maximum variable name length
    #[must_use]
    pub fn with_max_length(mut self, length: usize) -> Self {
        self.inner = self.inner.with_max_length(length);
        self
    }

    /// Disable reserved variable checking
    #[must_use]
    pub fn without_reserved_check(mut self) -> Self {
        self.inner = self.inner.without_reserved_check();
        self
    }

    /// Disable injection pattern checking
    #[must_use]
    pub fn without_injection_check(mut self) -> Self {
        self.inner = self.inner.without_injection_check();
        self
    }

    // ========================================================================
    // Detection Methods (bool)
    // ========================================================================

    /// Check if a variable name is reserved
    #[must_use]
    pub fn is_reserved_var(&self, name: &str) -> bool {
        self.inner.is_reserved_var(name)
    }

    /// Check if a variable is critical (security-sensitive)
    #[must_use]
    pub fn is_critical_var(&self, name: &str) -> bool {
        self.inner.is_critical_var(name)
    }

    /// Check if an environment variable name is valid (returns bool)
    #[must_use]
    pub fn is_valid_env_var(&self, name: &str) -> bool {
        self.inner.is_valid_env_var(name)
    }

    // ========================================================================
    // Validation Methods (Result)
    // ========================================================================

    /// Validate an environment variable name (returns Result)
    pub fn validate_env_var(&self, name: &str) -> Result<(), Problem> {
        self.inner.validate_env_var(name)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = EnvironmentBuilder::new();
        assert!(builder.emit_events);

        let silent = EnvironmentBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = EnvironmentBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_env_var_detection() {
        let builder = EnvironmentBuilder::silent();
        assert!(builder.is_valid_env_var("MY_VAR"));
        assert!(!builder.is_valid_env_var("PATH")); // reserved
    }

    #[test]
    fn test_permissive() {
        let builder = EnvironmentBuilder::permissive();
        assert!(builder.is_valid_env_var("PATH")); // allowed in permissive mode
    }

    #[test]
    fn test_validation() {
        let builder = EnvironmentBuilder::new();
        assert!(builder.validate_env_var("MY_VAR").is_ok());
        assert!(builder.validate_env_var("PATH").is_err());
    }
}

//! Generic identifier builder with observability
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.

use crate::observe::Problem;
use crate::primitives::identifiers::GenericBuilder as PrimitiveGenericBuilder;

/// Generic identifier builder with observability
#[derive(Debug, Clone)]
pub struct GenericBuilder {
    inner: PrimitiveGenericBuilder,
    emit_events: bool,
}

impl Default for GenericBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GenericBuilder {
    /// Create a new GenericBuilder with default configuration and observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PrimitiveGenericBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: PrimitiveGenericBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    /// Create a permissive builder without injection checking
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            inner: PrimitiveGenericBuilder::permissive(),
            emit_events: true,
        }
    }

    /// Set custom maximum identifier length
    #[must_use]
    pub fn with_max_length(mut self, length: usize) -> Self {
        self.inner = self.inner.with_max_length(length);
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

    /// Check if a generic identifier is valid (returns bool)
    #[must_use]
    pub fn is_valid_identifier(&self, name: &str) -> bool {
        self.inner.is_valid_identifier(name)
    }

    // ========================================================================
    // Validation Methods (Result)
    // ========================================================================

    /// Validate a generic identifier (returns Result)
    pub fn validate_identifier(&self, name: &str) -> Result<(), Problem> {
        self.inner.validate_identifier(name)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = GenericBuilder::new();
        assert!(builder.emit_events);

        let silent = GenericBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = GenericBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_identifier_detection() {
        let builder = GenericBuilder::silent();
        assert!(builder.is_valid_identifier("api-key-123"));
        assert!(!builder.is_valid_identifier("$(cmd)"));
    }

    #[test]
    fn test_permissive() {
        let builder = GenericBuilder::permissive();
        assert!(builder.is_valid_identifier("normal-id"));
    }

    #[test]
    fn test_validation() {
        let builder = GenericBuilder::new();
        assert!(builder.validate_identifier("api-key-v2").is_ok());
        assert!(builder.validate_identifier("").is_err());
    }
}

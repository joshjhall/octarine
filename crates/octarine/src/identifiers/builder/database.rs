//! Database identifier builder with observability
//!
//! Wraps `primitives::identifiers::DatabaseBuilder` with observe instrumentation.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.

use crate::observe::Problem;
use crate::primitives::identifiers::DatabaseBuilder as PrimitiveDatabaseBuilder;

/// Database identifier builder with observability
#[derive(Debug, Clone)]
pub struct DatabaseBuilder {
    inner: PrimitiveDatabaseBuilder,
    emit_events: bool,
}

impl Default for DatabaseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DatabaseBuilder {
    /// Create a new DatabaseBuilder with default configuration and observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PrimitiveDatabaseBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: PrimitiveDatabaseBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    /// Create a builder configured for PostgreSQL
    #[must_use]
    pub fn postgresql() -> Self {
        Self {
            inner: PrimitiveDatabaseBuilder::postgresql(),
            emit_events: true,
        }
    }

    /// Create a builder configured for MySQL
    #[must_use]
    pub fn mysql() -> Self {
        Self {
            inner: PrimitiveDatabaseBuilder::mysql(),
            emit_events: true,
        }
    }

    /// Create a builder configured for Oracle
    #[must_use]
    pub fn oracle() -> Self {
        Self {
            inner: PrimitiveDatabaseBuilder::oracle(),
            emit_events: true,
        }
    }

    /// Create a builder configured for SQL Server
    #[must_use]
    pub fn sqlserver() -> Self {
        Self {
            inner: PrimitiveDatabaseBuilder::sqlserver(),
            emit_events: true,
        }
    }

    /// Set custom maximum identifier length
    #[must_use]
    pub fn with_max_length(mut self, length: usize) -> Self {
        self.inner = self.inner.with_max_length(length);
        self
    }

    /// Disable reserved keyword checking
    #[must_use]
    pub fn without_reserved_check(mut self) -> Self {
        self.inner = self.inner.without_reserved_check();
        self
    }

    // ========================================================================
    // Detection Methods (bool)
    // ========================================================================

    /// Check if a string is a reserved SQL keyword
    #[must_use]
    pub fn is_reserved_keyword(&self, name: &str) -> bool {
        self.inner.is_reserved_keyword(name)
    }

    /// Check if a database identifier is valid (returns bool)
    #[must_use]
    pub fn is_valid_identifier(&self, name: &str) -> bool {
        self.inner.is_valid_identifier(name)
    }

    // ========================================================================
    // Validation Methods (Result)
    // ========================================================================

    /// Validate a database identifier (returns Result)
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
        let builder = DatabaseBuilder::new();
        assert!(builder.emit_events);

        let silent = DatabaseBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = DatabaseBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_identifier_detection() {
        let builder = DatabaseBuilder::silent();
        assert!(builder.is_valid_identifier("users"));
        assert!(builder.validate_identifier("users").is_ok());
    }
}

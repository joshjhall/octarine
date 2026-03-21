//! Database builder for convenient access to all database identifier functions
//!
//! The DatabaseBuilder provides a unified interface for detection
//! and validation of database identifiers.

use super::MAX_IDENTIFIER_LENGTH;
use super::{detection, validation};
use crate::primitives::types::Problem;

/// Builder for database identifier validation and detection
///
/// Provides configurable access to all database identifier functions with optional
/// custom limits.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::database::DatabaseBuilder;
///
/// let db = DatabaseBuilder::new();
///
/// // Detection (bool)
/// if db.is_valid_identifier("users") {
///     println!("Valid!");
/// }
///
/// // Validation (Result)
/// db.validate_identifier("users")?;
/// ```
#[derive(Debug, Clone)]
pub struct DatabaseBuilder {
    max_length: usize,
    check_reserved: bool,
}

impl Default for DatabaseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DatabaseBuilder {
    /// Create a new DatabaseBuilder with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_length: MAX_IDENTIFIER_LENGTH,
            check_reserved: true,
        }
    }

    /// Create a builder configured for PostgreSQL
    #[must_use]
    pub fn postgresql() -> Self {
        Self::new().with_max_length(super::POSTGRESQL_IDENTIFIER_LIMIT)
    }

    /// Create a builder configured for MySQL
    #[must_use]
    pub fn mysql() -> Self {
        Self::new().with_max_length(super::MYSQL_IDENTIFIER_LIMIT)
    }

    /// Create a builder configured for Oracle
    #[must_use]
    pub fn oracle() -> Self {
        Self::new().with_max_length(super::ORACLE_IDENTIFIER_LIMIT)
    }

    /// Create a builder configured for SQL Server
    #[must_use]
    pub fn sqlserver() -> Self {
        Self::new().with_max_length(super::SQL_SERVER_IDENTIFIER_LIMIT)
    }

    /// Set custom maximum identifier length
    #[must_use]
    pub fn with_max_length(mut self, length: usize) -> Self {
        self.max_length = length;
        self
    }

    /// Disable reserved keyword checking
    #[must_use]
    pub fn without_reserved_check(mut self) -> Self {
        self.check_reserved = false;
        self
    }

    // ========================================================================
    // Detection Methods
    // ========================================================================

    /// Check if a string is a reserved SQL keyword
    #[must_use]
    pub fn is_reserved_keyword(&self, name: &str) -> bool {
        detection::is_reserved_keyword(name)
    }

    // ========================================================================
    // Detection Methods (bool)
    // ========================================================================

    /// Check if a database identifier is valid (returns bool)
    #[must_use]
    pub fn is_valid_identifier(&self, name: &str) -> bool {
        detection::is_valid_identifier_with_config(name, self.max_length, self.check_reserved)
    }

    // ========================================================================
    // Validation Methods (Result)
    // ========================================================================

    /// Validate a database identifier (returns Result)
    pub fn validate_identifier(&self, name: &str) -> Result<(), Problem> {
        validation::validate_identifier_with_config(name, self.max_length, self.check_reserved)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_default() {
        let db = DatabaseBuilder::new();
        assert!(db.is_valid_identifier("users"));
        assert!(!db.is_valid_identifier("select"));
    }

    #[test]
    fn test_builder_custom_length() {
        let db = DatabaseBuilder::new().with_max_length(10);

        assert!(db.is_valid_identifier("short"));
        assert!(!db.is_valid_identifier("this_is_too_long"));
    }

    #[test]
    fn test_builder_without_reserved_check() {
        let db = DatabaseBuilder::new().without_reserved_check();

        // Now reserved words are allowed
        assert!(db.is_valid_identifier("select"));
        assert!(db.is_valid_identifier("table"));
    }

    #[test]
    fn test_builder_database_specific() {
        let postgres = DatabaseBuilder::postgresql();
        let oracle = DatabaseBuilder::oracle();

        // PostgreSQL: 63 chars
        assert!(postgres.is_valid_identifier(&"a".repeat(63)));
        assert!(!postgres.is_valid_identifier(&"a".repeat(64)));

        // Oracle: 30 chars
        assert!(oracle.is_valid_identifier(&"a".repeat(30)));
        assert!(!oracle.is_valid_identifier(&"a".repeat(31)));
    }

    #[test]
    fn test_builder_validation() {
        let db = DatabaseBuilder::new();

        assert!(db.validate_identifier("users").is_ok());
        assert!(db.validate_identifier("select").is_err());
        assert!(db.validate_identifier("").is_err());
    }

    #[test]
    fn test_is_reserved_keyword() {
        let db = DatabaseBuilder::new();

        assert!(db.is_reserved_keyword("SELECT"));
        assert!(db.is_reserved_keyword("from"));
        assert!(!db.is_reserved_keyword("users"));
    }
}

//! Database identifier validation and detection
//!
//! Pure functions for validating and sanitizing database identifiers
//! (table names, column names, schema names, etc.).
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies (uses Problem type from primitives::types)
//! - Returns data, no side effects
//! - Used by security modules for database operations
//!
//! # Security Threats Addressed
//!
//! 1. **SQL Injection**: Malicious identifiers used in queries
//! 2. **Reserved Keywords**: Accidental use of SQL keywords as identifiers
//! 3. **Length Attacks**: Overly long identifiers causing buffer issues
//! 4. **Invalid Characters**: Characters that could break SQL syntax
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::identifiers::database::DatabaseBuilder;
//!
//! let db = DatabaseBuilder::new();
//!
//! // Detection (bool)
//! if db.is_valid_identifier("users") {
//!     println!("Valid table name");
//! }
//!
//! // Validation (Result)
//! db.validate_identifier("users")?;
//! ```

// Internal modules - not directly accessible outside database/
mod detection;
mod validation;

// Public builder module
pub mod builder;

// Re-export builder for convenience
pub use builder::DatabaseBuilder;

/// Default maximum length for database identifiers (common across DBs)
pub const MAX_IDENTIFIER_LENGTH: usize = 128;

/// PostgreSQL identifier limit
pub const POSTGRESQL_IDENTIFIER_LIMIT: usize = 63;

/// MySQL identifier limit
pub const MYSQL_IDENTIFIER_LIMIT: usize = 64;

/// Oracle identifier limit
pub const ORACLE_IDENTIFIER_LIMIT: usize = 30;

/// SQL Server identifier limit
pub const SQL_SERVER_IDENTIFIER_LIMIT: usize = 128;

/// Reserved SQL keywords (basic set - extend as needed)
pub const RESERVED_KEYWORDS: &[&str] = &[
    "select", "from", "where", "insert", "update", "delete", "create", "drop", "alter", "table",
    "index", "view", "user", "role", "grant", "revoke", "commit", "rollback", "and", "or", "not",
    "null", "true", "false", "join", "left", "right", "inner", "outer", "on", "as", "order", "by",
    "group", "having", "limit", "offset",
];

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_module_integration() {
        // Detection
        assert!(detection::is_valid_identifier("users"));
        assert!(detection::is_valid_identifier("user_accounts"));
        assert!(!detection::is_valid_identifier("123table"));
        assert!(!detection::is_valid_identifier("select")); // Reserved

        // Validation
        assert!(validation::validate_identifier("users").is_ok());
        assert!(validation::validate_identifier("").is_err());
        assert!(validation::validate_identifier("select").is_err());
    }

    #[test]
    fn test_builder_integration() {
        let db = DatabaseBuilder::new();

        // Detection via builder (bool)
        assert!(db.is_valid_identifier("users"));
        assert!(!db.is_valid_identifier("select"));

        // Validation via builder (Result)
        assert!(db.validate_identifier("users").is_ok());
        assert!(db.validate_identifier("drop").is_err());
    }

    #[test]
    fn test_database_specific_limits() {
        let db_postgres = DatabaseBuilder::new().with_max_length(POSTGRESQL_IDENTIFIER_LIMIT);
        let db_oracle = DatabaseBuilder::new().with_max_length(ORACLE_IDENTIFIER_LIMIT);

        let long_63 = "a".repeat(63);
        let long_64 = "a".repeat(64);
        let long_30 = "a".repeat(30);
        let long_31 = "a".repeat(31);

        // PostgreSQL
        assert!(db_postgres.is_valid_identifier(&long_63));
        assert!(!db_postgres.is_valid_identifier(&long_64));

        // Oracle
        assert!(db_oracle.is_valid_identifier(&long_30));
        assert!(!db_oracle.is_valid_identifier(&long_31));
    }
}

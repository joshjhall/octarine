//! Database identifier validation functions
//!
//! Result-returning validation functions for database identifiers.
//! These are the "validate_*" functions that return Result<(), Problem>.

use super::detection;
use super::{MAX_IDENTIFIER_LENGTH, RESERVED_KEYWORDS};
use crate::primitives::types::Problem;

/// Result type for validation operations
pub type ValidationResult = Result<(), Problem>;

// ============================================================================
// Identifier Validation
// ============================================================================

/// Validate a database identifier
///
/// Returns `Ok(())` if valid, or `Err(Problem)` with details if invalid.
///
/// # Errors
///
/// Returns error if:
/// - Identifier is empty
/// - Identifier exceeds MAX_IDENTIFIER_LENGTH
/// - Identifier starts with invalid character
/// - Identifier contains invalid characters
/// - Identifier is a reserved SQL keyword
pub fn validate_identifier(name: &str) -> ValidationResult {
    validate_identifier_with_config(name, MAX_IDENTIFIER_LENGTH, true)
}

/// Validate a database identifier with custom configuration
pub fn validate_identifier_with_config(
    name: &str,
    max_length: usize,
    check_reserved: bool,
) -> ValidationResult {
    if name.is_empty() {
        return Err(Problem::validation("Database identifier cannot be empty"));
    }

    if name.len() > max_length {
        return Err(Problem::validation(format!(
            "Database identifier exceeds {} characters",
            max_length
        )));
    }

    if !super::super::common::is_valid_start_char(name) {
        return Err(Problem::validation(
            "Database identifier must start with letter or underscore",
        ));
    }

    if !super::super::common::is_identifier_chars(name, &['$']) {
        return Err(Problem::validation(
            "Database identifier contains invalid characters (use alphanumeric, underscore, or dollar sign)",
        ));
    }

    if check_reserved && detection::is_reserved_keyword(name) {
        return Err(Problem::validation(format!(
            "'{}' is a reserved SQL keyword",
            name
        )));
    }

    Ok(())
}

/// Validate for PostgreSQL (63 char limit)
pub fn validate_postgresql_identifier(name: &str) -> ValidationResult {
    validate_identifier_with_config(name, super::POSTGRESQL_IDENTIFIER_LIMIT, true)
}

/// Validate for MySQL (64 char limit)
pub fn validate_mysql_identifier(name: &str) -> ValidationResult {
    validate_identifier_with_config(name, super::MYSQL_IDENTIFIER_LIMIT, true)
}

/// Validate for Oracle (30 char limit)
pub fn validate_oracle_identifier(name: &str) -> ValidationResult {
    validate_identifier_with_config(name, super::ORACLE_IDENTIFIER_LIMIT, true)
}

/// Validate for SQL Server (128 char limit)
pub fn validate_sqlserver_identifier(name: &str) -> ValidationResult {
    validate_identifier_with_config(name, super::SQL_SERVER_IDENTIFIER_LIMIT, true)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validate_valid_identifiers() {
        assert!(validate_identifier("users").is_ok());
        assert!(validate_identifier("user_accounts").is_ok());
        assert!(validate_identifier("_temp").is_ok());
    }

    #[test]
    fn test_validate_empty() {
        let result = validate_identifier("");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected error")
                .to_string()
                .contains("empty")
        );
    }

    #[test]
    fn test_validate_too_long() {
        let too_long = "a".repeat(MAX_IDENTIFIER_LENGTH + 1);
        let result = validate_identifier(&too_long);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected error")
                .to_string()
                .contains("exceeds")
        );
    }

    #[test]
    fn test_validate_invalid_start() {
        let result = validate_identifier("123table");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected error")
                .to_string()
                .contains("start")
        );
    }

    #[test]
    fn test_validate_reserved_keyword() {
        let result = validate_identifier("select");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected error")
                .to_string()
                .contains("reserved")
        );
    }

    #[test]
    fn test_validate_database_specific() {
        // PostgreSQL: 63 chars
        assert!(validate_postgresql_identifier(&"a".repeat(63)).is_ok());
        assert!(validate_postgresql_identifier(&"a".repeat(64)).is_err());

        // Oracle: 30 chars
        assert!(validate_oracle_identifier(&"a".repeat(30)).is_ok());
        assert!(validate_oracle_identifier(&"a".repeat(31)).is_err());
    }
}

//! Database identifier detection functions
//!
//! Boolean detection functions for database identifiers.
//! These are the "is_*" functions that return bool.

use super::super::common::{is_identifier_chars, is_valid_start_char};
use super::{MAX_IDENTIFIER_LENGTH, RESERVED_KEYWORDS};

// ============================================================================
// Identifier Detection
// ============================================================================

/// Check if a database identifier is valid
///
/// A valid database identifier:
/// - Is not empty
/// - Does not exceed MAX_IDENTIFIER_LENGTH (128) characters
/// - Starts with a letter or underscore
/// - Contains only alphanumeric characters, underscores, and dollar signs
/// - Is not a reserved SQL keyword
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::identifiers::database::detection;
///
/// assert!(detection::is_valid_identifier("users"));
/// assert!(detection::is_valid_identifier("user_accounts"));
/// assert!(!detection::is_valid_identifier("123table")); // starts with number
/// assert!(!detection::is_valid_identifier("select")); // reserved keyword
/// ```
#[must_use]
pub fn is_valid_identifier(name: &str) -> bool {
    is_valid_identifier_with_config(name, MAX_IDENTIFIER_LENGTH, true)
}

/// Check if a database identifier is valid with custom configuration
#[must_use]
pub fn is_valid_identifier_with_config(
    name: &str,
    max_length: usize,
    check_reserved: bool,
) -> bool {
    !name.is_empty()
        && name.len() <= max_length
        && is_valid_start_char(name)
        && is_identifier_chars(name, &['$']) // Database allows $ in identifiers
        && (!check_reserved || !is_reserved_keyword(name))
}

/// Check if a string is a reserved SQL keyword
#[must_use]
pub fn is_reserved_keyword(name: &str) -> bool {
    RESERVED_KEYWORDS.contains(&name.to_lowercase().as_str())
}

/// Check if identifier is valid for PostgreSQL (63 char limit)
#[must_use]
pub fn is_valid_postgresql_identifier(name: &str) -> bool {
    is_valid_identifier_with_config(name, super::POSTGRESQL_IDENTIFIER_LIMIT, true)
}

/// Check if identifier is valid for MySQL (64 char limit)
#[must_use]
pub fn is_valid_mysql_identifier(name: &str) -> bool {
    is_valid_identifier_with_config(name, super::MYSQL_IDENTIFIER_LIMIT, true)
}

/// Check if identifier is valid for Oracle (30 char limit)
#[must_use]
pub fn is_valid_oracle_identifier(name: &str) -> bool {
    is_valid_identifier_with_config(name, super::ORACLE_IDENTIFIER_LIMIT, true)
}

/// Check if identifier is valid for SQL Server (128 char limit)
#[must_use]
pub fn is_valid_sqlserver_identifier(name: &str) -> bool {
    is_valid_identifier_with_config(name, super::SQL_SERVER_IDENTIFIER_LIMIT, true)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_valid_identifiers() {
        assert!(is_valid_identifier("users"));
        assert!(is_valid_identifier("user_accounts"));
        assert!(is_valid_identifier("UserAccounts"));
        assert!(is_valid_identifier("table123"));
        assert!(is_valid_identifier("_temp_table"));
        assert!(is_valid_identifier("table$data"));
        assert!(is_valid_identifier("t"));
    }

    #[test]
    fn test_invalid_identifiers() {
        assert!(!is_valid_identifier("")); // Empty
        assert!(!is_valid_identifier("123table")); // Starts with number
        assert!(!is_valid_identifier("$table")); // Starts with dollar
        assert!(!is_valid_identifier("-table")); // Starts with hyphen
        assert!(!is_valid_identifier("my-table")); // Contains hyphen
        assert!(!is_valid_identifier("my.table")); // Contains period
        assert!(!is_valid_identifier("my table")); // Contains space
    }

    #[test]
    fn test_reserved_keywords() {
        assert!(!is_valid_identifier("select"));
        assert!(!is_valid_identifier("SELECT"));
        assert!(!is_valid_identifier("Select"));
        assert!(!is_valid_identifier("from"));
        assert!(!is_valid_identifier("table"));
        assert!(!is_valid_identifier("drop"));
    }

    #[test]
    fn test_length_limits() {
        let at_limit = "a".repeat(MAX_IDENTIFIER_LENGTH);
        let over_limit = "a".repeat(MAX_IDENTIFIER_LENGTH + 1);

        assert!(is_valid_identifier(&at_limit));
        assert!(!is_valid_identifier(&over_limit));
    }

    #[test]
    fn test_database_specific() {
        // PostgreSQL: 63 chars
        assert!(is_valid_postgresql_identifier(&"a".repeat(63)));
        assert!(!is_valid_postgresql_identifier(&"a".repeat(64)));

        // Oracle: 30 chars
        assert!(is_valid_oracle_identifier(&"a".repeat(30)));
        assert!(!is_valid_oracle_identifier(&"a".repeat(31)));

        // MySQL: 64 chars
        assert!(is_valid_mysql_identifier(&"a".repeat(64)));
        assert!(!is_valid_mysql_identifier(&"a".repeat(65)));

        // SQL Server: 128 chars
        assert!(is_valid_sqlserver_identifier(&"a".repeat(128)));
        assert!(!is_valid_sqlserver_identifier(&"a".repeat(129)));
    }

    #[test]
    fn test_is_reserved_keyword() {
        assert!(is_reserved_keyword("select"));
        assert!(is_reserved_keyword("SELECT"));
        assert!(is_reserved_keyword("SeLeCt"));
        assert!(!is_reserved_keyword("users"));
        assert!(!is_reserved_keyword("my_table"));
    }
}

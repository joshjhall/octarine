// Allow arithmetic - string capacity estimation is safe
#![allow(clippy::arithmetic_side_effects)]

//! SQL escaping and sanitization
//!
//! Functions for escaping SQL strings and identifiers.
//!
//! # Warning
//!
//! While these functions provide escaping, **parameterized queries**
//! are the recommended approach for SQL injection prevention.
//! Use these functions only when parameterization is not possible.

// ============================================================================
// String Escaping
// ============================================================================

/// Escape a string for use in SQL queries
///
/// This escapes single quotes by doubling them, which is the standard
/// SQL escaping mechanism.
///
/// # Arguments
///
/// * `input` - The string to escape
///
/// # Returns
///
/// The escaped string safe for SQL interpolation
///
/// # Example
///
/// ```ignore
/// use octarine::primitives::security::queries::sql::sanitization;
///
/// let name = "O'Brien";
/// let escaped = sanitization::escape_sql_string(name);
/// assert_eq!(escaped, "O''Brien");
/// ```
///
/// # Note
///
/// This function escapes for ANSI SQL. Some databases may require
/// additional escaping for backslashes or other characters.
#[must_use]
pub fn escape_sql_string(input: &str) -> String {
    let mut result = String::with_capacity(input.len());

    for c in input.chars() {
        match c {
            // Double single quotes
            '\'' => result.push_str("''"),
            // Escape backslash (for MySQL, PostgreSQL)
            '\\' => result.push_str("\\\\"),
            // Escape null bytes
            '\0' => result.push_str("\\0"),
            // Pass through everything else
            _ => result.push(c),
        }
    }

    result
}

/// Escape a string for use in SQL queries (PostgreSQL-specific)
///
/// Uses PostgreSQL's E'' escape string syntax for special characters.
#[must_use]
pub fn escape_sql_string_postgres(input: &str) -> String {
    let mut result = String::with_capacity(input.len());

    for c in input.chars() {
        match c {
            '\'' => result.push_str("''"),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '\0' => {} // Remove null bytes
            _ => result.push(c),
        }
    }

    result
}

/// Escape a string for use in SQL queries (MySQL-specific)
///
/// Escapes characters according to MySQL's escaping rules.
#[must_use]
pub fn escape_sql_string_mysql(input: &str) -> String {
    let mut result = String::with_capacity(input.len());

    for c in input.chars() {
        match c {
            '\'' => result.push_str("\\'"),
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '\0' => result.push_str("\\0"),
            '\x1a' => result.push_str("\\Z"), // Ctrl+Z
            _ => result.push(c),
        }
    }

    result
}

// ============================================================================
// Identifier Escaping
// ============================================================================

/// Escape a SQL identifier (table name, column name, etc.)
///
/// Uses double quotes for quoting, which is ANSI SQL standard.
/// The identifier is wrapped in double quotes with any embedded
/// double quotes escaped by doubling them.
///
/// # Arguments
///
/// * `identifier` - The identifier to escape
///
/// # Returns
///
/// The quoted identifier safe for SQL
///
/// # Example
///
/// ```ignore
/// use octarine::primitives::security::queries::sql::sanitization;
///
/// let table = "user-data";
/// let escaped = sanitization::escape_sql_identifier(table);
/// assert_eq!(escaped, "\"user-data\"");
/// ```
#[must_use]
pub fn escape_sql_identifier(identifier: &str) -> String {
    let mut result = String::with_capacity(identifier.len() + 2);
    result.push('"');

    for c in identifier.chars() {
        match c {
            '"' => result.push_str("\"\""),
            '\0' => {} // Remove null bytes
            _ => result.push(c),
        }
    }

    result.push('"');
    result
}

/// Escape a SQL identifier using backticks (MySQL-specific)
#[must_use]
pub fn escape_sql_identifier_mysql(identifier: &str) -> String {
    let mut result = String::with_capacity(identifier.len() + 2);
    result.push('`');

    for c in identifier.chars() {
        match c {
            '`' => result.push_str("``"),
            '\0' => {} // Remove null bytes
            _ => result.push(c),
        }
    }

    result.push('`');
    result
}

/// Escape a SQL identifier using brackets (SQL Server-specific)
#[must_use]
pub fn escape_sql_identifier_sqlserver(identifier: &str) -> String {
    let mut result = String::with_capacity(identifier.len() + 2);
    result.push('[');

    for c in identifier.chars() {
        match c {
            ']' => result.push_str("]]"),
            '\0' => {} // Remove null bytes
            _ => result.push(c),
        }
    }

    result.push(']');
    result
}

// ============================================================================
// LIKE Pattern Escaping
// ============================================================================

/// Escape special characters in a LIKE pattern
///
/// Escapes % and _ so they are treated as literal characters,
/// not wildcards.
///
/// # Arguments
///
/// * `pattern` - The pattern to escape
///
/// # Returns
///
/// The escaped pattern with wildcards escaped
#[must_use]
pub fn escape_sql_like_pattern(pattern: &str) -> String {
    let mut result = String::with_capacity(pattern.len());

    for c in pattern.chars() {
        match c {
            '%' => result.push_str("\\%"),
            '_' => result.push_str("\\_"),
            '\\' => result.push_str("\\\\"),
            '\'' => result.push_str("''"),
            _ => result.push(c),
        }
    }

    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_sql_string_basic() {
        assert_eq!(escape_sql_string("hello"), "hello");
        assert_eq!(escape_sql_string("O'Brien"), "O''Brien");
        assert_eq!(escape_sql_string("test'test"), "test''test");
        assert_eq!(escape_sql_string("''"), "''''");
    }

    #[test]
    fn test_escape_sql_string_backslash() {
        assert_eq!(escape_sql_string("path\\file"), "path\\\\file");
        assert_eq!(escape_sql_string("a\\b\\c"), "a\\\\b\\\\c");
    }

    #[test]
    fn test_escape_sql_string_null() {
        assert_eq!(escape_sql_string("test\0test"), "test\\0test");
    }

    #[test]
    fn test_escape_sql_string_injection() {
        // Even with escaping, injection patterns become harmless
        assert_eq!(
            escape_sql_string("'; DROP TABLE users; --"),
            "''; DROP TABLE users; --"
        );
        assert_eq!(escape_sql_string("' OR 1=1 --"), "'' OR 1=1 --");
    }

    #[test]
    fn test_escape_sql_string_postgres() {
        assert_eq!(escape_sql_string_postgres("hello\nworld"), "hello\\nworld");
        assert_eq!(escape_sql_string_postgres("tab\there"), "tab\\there");
        assert_eq!(escape_sql_string_postgres("O'Brien"), "O''Brien");
    }

    #[test]
    fn test_escape_sql_string_mysql() {
        assert_eq!(escape_sql_string_mysql("O'Brien"), "O\\'Brien");
        assert_eq!(escape_sql_string_mysql("hello\nworld"), "hello\\nworld");
        assert_eq!(escape_sql_string_mysql("\"quoted\""), "\\\"quoted\\\"");
    }

    #[test]
    fn test_escape_sql_identifier() {
        assert_eq!(escape_sql_identifier("users"), "\"users\"");
        assert_eq!(escape_sql_identifier("user-data"), "\"user-data\"");
        assert_eq!(escape_sql_identifier("my\"table"), "\"my\"\"table\"");
    }

    #[test]
    fn test_escape_sql_identifier_mysql() {
        assert_eq!(escape_sql_identifier_mysql("users"), "`users`");
        assert_eq!(escape_sql_identifier_mysql("my`table"), "`my``table`");
    }

    #[test]
    fn test_escape_sql_identifier_sqlserver() {
        assert_eq!(escape_sql_identifier_sqlserver("users"), "[users]");
        assert_eq!(escape_sql_identifier_sqlserver("my]table"), "[my]]table]");
    }

    #[test]
    fn test_escape_sql_like_pattern() {
        assert_eq!(escape_sql_like_pattern("hello"), "hello");
        assert_eq!(escape_sql_like_pattern("100%"), "100\\%");
        assert_eq!(escape_sql_like_pattern("user_name"), "user\\_name");
        assert_eq!(escape_sql_like_pattern("50% off!"), "50\\% off!");
    }

    #[test]
    fn test_escape_preserves_unicode() {
        assert_eq!(escape_sql_string("你好"), "你好");
        assert_eq!(escape_sql_string("émoji: 🎉"), "émoji: 🎉");
        assert_eq!(escape_sql_identifier("日本語"), "\"日本語\"");
    }

    #[test]
    fn test_escape_empty_string() {
        assert_eq!(escape_sql_string(""), "");
        assert_eq!(escape_sql_identifier(""), "\"\"");
        assert_eq!(escape_sql_like_pattern(""), "");
    }
}

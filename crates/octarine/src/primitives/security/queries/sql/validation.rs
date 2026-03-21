//! SQL parameter validation
//!
//! Validation functions for SQL parameters to prevent injection.

use super::detection;
use crate::primitives::types::Problem;

// ============================================================================
// Validation Functions
// ============================================================================

/// Validate that a SQL parameter is safe
///
/// This checks for injection patterns and returns an error if any are found.
/// Use this before interpolating user input into SQL queries.
///
/// # Arguments
///
/// * `param` - The parameter value to validate
///
/// # Returns
///
/// `Ok(())` if the parameter is safe, `Err(Problem)` if injection detected
///
/// # Example
///
/// ```ignore
/// use octarine::primitives::security::queries::sql::validation;
///
/// // Safe parameter
/// assert!(validation::validate_sql_parameter("hello").is_ok());
///
/// // Injection attempt
/// assert!(validation::validate_sql_parameter("' OR 1=1 --").is_err());
/// ```
///
/// # Note
///
/// Even with validation, you should prefer parameterized queries over
/// string interpolation for SQL.
pub fn validate_sql_parameter(param: &str) -> Result<(), Problem> {
    if detection::is_sql_injection_present(param) {
        let threats = detection::detect_sql_threats(param);
        let threat_desc = threats
            .iter()
            .map(|t| t.description())
            .collect::<Vec<_>>()
            .join(", ");

        return Err(Problem::validation(format!(
            "SQL injection detected in parameter: {threat_desc}"
        )));
    }

    Ok(())
}

/// Validate a SQL identifier (table name, column name, etc.)
///
/// Identifiers have stricter requirements than general parameters.
/// They should only contain alphanumeric characters, underscores, and
/// should not start with a digit.
///
/// # Arguments
///
/// * `identifier` - The identifier to validate
///
/// # Returns
///
/// `Ok(())` if the identifier is valid, `Err(Problem)` otherwise
pub fn validate_sql_identifier(identifier: &str) -> Result<(), Problem> {
    // Check for empty
    if identifier.is_empty() {
        return Err(Problem::validation("SQL identifier cannot be empty"));
    }

    // Check length (most databases have limits around 128)
    if identifier.len() > 128 {
        return Err(Problem::validation(
            "SQL identifier exceeds maximum length of 128 characters",
        ));
    }

    // Check first character (must be letter or underscore)
    if let Some(c) = identifier.chars().next()
        && !c.is_ascii_alphabetic()
        && c != '_'
    {
        return Err(Problem::validation(
            "SQL identifier must start with a letter or underscore",
        ));
    }

    // Check all characters (letters, digits, underscores only)
    for c in identifier.chars() {
        if !c.is_ascii_alphanumeric() && c != '_' {
            return Err(Problem::validation(format!(
                "SQL identifier contains invalid character: '{c}'"
            )));
        }
    }

    // Check for SQL injection patterns (even in identifiers)
    if detection::is_sql_keywords_in_input(identifier) {
        // Only block if it's EXACTLY a keyword (not containing one)
        let upper = identifier.to_uppercase();
        if super::patterns::SQL_KEYWORDS.contains(&upper.as_str()) {
            return Err(Problem::validation(format!(
                "SQL identifier cannot be a reserved keyword: '{identifier}'"
            )));
        }
    }

    Ok(())
}

/// Validate a SQL LIKE pattern
///
/// LIKE patterns can contain % and _ wildcards. This validates that
/// the pattern doesn't contain injection attempts while allowing
/// legitimate wildcards.
///
/// # Arguments
///
/// * `pattern` - The LIKE pattern to validate
///
/// # Returns
///
/// `Ok(())` if the pattern is safe, `Err(Problem)` otherwise
pub fn validate_sql_like_pattern(pattern: &str) -> Result<(), Problem> {
    // Check for injection patterns (but allow % and _)
    if detection::is_sql_comments_in_input(pattern)
        || detection::is_stacked_queries_in_input(pattern)
        || detection::is_union_based_in_input(pattern)
    {
        return Err(Problem::validation(
            "SQL injection detected in LIKE pattern",
        ));
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_sql_parameter_safe() {
        assert!(validate_sql_parameter("hello").is_ok());
        assert!(validate_sql_parameter("john.doe@example.com").is_ok());
        assert!(validate_sql_parameter("123456").is_ok());
        assert!(validate_sql_parameter("O'Brien").is_ok()); // Name with apostrophe
        assert!(validate_sql_parameter("").is_ok());
    }

    #[test]
    fn test_validate_sql_parameter_injection() {
        assert!(validate_sql_parameter("' OR 1=1 --").is_err());
        assert!(validate_sql_parameter("'; DROP TABLE users; --").is_err());
        assert!(validate_sql_parameter("admin'--").is_err());
        assert!(validate_sql_parameter("' UNION SELECT password FROM users").is_err());
    }

    #[test]
    fn test_validate_sql_identifier_valid() {
        assert!(validate_sql_identifier("users").is_ok());
        assert!(validate_sql_identifier("user_name").is_ok());
        assert!(validate_sql_identifier("_private").is_ok());
        assert!(validate_sql_identifier("table1").is_ok());
        assert!(validate_sql_identifier("MyTable").is_ok());
    }

    #[test]
    fn test_validate_sql_identifier_invalid() {
        // Empty
        assert!(validate_sql_identifier("").is_err());

        // Starts with digit
        assert!(validate_sql_identifier("1table").is_err());

        // Contains special chars
        assert!(validate_sql_identifier("table-name").is_err());
        assert!(validate_sql_identifier("table.name").is_err());
        assert!(validate_sql_identifier("table name").is_err());
        assert!(validate_sql_identifier("table;drop").is_err());

        // SQL keywords
        assert!(validate_sql_identifier("SELECT").is_err());
        assert!(validate_sql_identifier("DROP").is_err());
        assert!(validate_sql_identifier("DELETE").is_err());
    }

    #[test]
    fn test_validate_sql_identifier_length() {
        // Valid length
        let valid = "a".repeat(128);
        assert!(validate_sql_identifier(&valid).is_ok());

        // Too long
        let too_long = "a".repeat(129);
        assert!(validate_sql_identifier(&too_long).is_err());
    }

    #[test]
    fn test_validate_sql_like_pattern_valid() {
        assert!(validate_sql_like_pattern("%search%").is_ok());
        assert!(validate_sql_like_pattern("user_").is_ok());
        assert!(validate_sql_like_pattern("%@example.com").is_ok());
        assert!(validate_sql_like_pattern("%.txt").is_ok());
    }

    #[test]
    fn test_validate_sql_like_pattern_injection() {
        assert!(validate_sql_like_pattern("%; DROP TABLE users; --").is_err());
        assert!(validate_sql_like_pattern("% UNION SELECT * FROM passwords").is_err());
    }
}

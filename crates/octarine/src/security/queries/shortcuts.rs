//! Shortcut functions for query security
//!
//! Convenience functions for common query security operations.
//! These wrap the QueryBuilder for simple use cases.

use super::{GraphqlAnalysis, QueryBuilder, QueryThreat, QueryType};
use crate::primitives::types::Problem;

// ============================================================================
// SQL Shortcuts
// ============================================================================

/// Check if input contains SQL injection patterns
///
/// # Example
///
/// ```ignore
/// use octarine::security::queries::is_sql_injection_present;
///
/// if is_sql_injection_present(user_input) {
///     // Handle threat
/// }
/// ```
#[must_use]
pub fn is_sql_injection_present(input: &str) -> bool {
    QueryBuilder::new().is_sql_injection_present(input)
}

/// Detect all SQL injection threats in input
#[must_use]
pub fn detect_sql_threats(input: &str) -> Vec<QueryThreat> {
    QueryBuilder::new().detect_sql_threats(input)
}

/// Validate that a SQL parameter is safe
///
/// # Example
///
/// ```ignore
/// use octarine::security::queries::validate_sql_parameter;
///
/// validate_sql_parameter(user_input)?;
/// // Safe to use in parameterized query
/// ```
pub fn validate_sql_parameter(param: &str) -> Result<(), Problem> {
    QueryBuilder::new().validate_sql_parameter(param)
}

/// Escape a string for SQL queries
///
/// # Warning
///
/// Prefer parameterized queries. Use this only when parameterization
/// is not possible.
#[must_use]
pub fn escape_sql_string(input: &str) -> String {
    QueryBuilder::new().escape_sql_string(input)
}

/// Escape a SQL identifier (table/column name)
#[must_use]
pub fn escape_sql_identifier(name: &str) -> String {
    QueryBuilder::new().escape_sql_identifier(name)
}

// ============================================================================
// NoSQL Shortcuts
// ============================================================================

/// Check if input contains NoSQL injection patterns
#[must_use]
pub fn is_nosql_injection_present(input: &str) -> bool {
    QueryBuilder::new().is_nosql_injection_present(input)
}

/// Detect all NoSQL injection threats in input
#[must_use]
pub fn detect_nosql_threats(input: &str) -> Vec<QueryThreat> {
    QueryBuilder::new().detect_nosql_threats(input)
}

/// Validate that a NoSQL value is safe
pub fn validate_nosql_value(value: &str) -> Result<(), Problem> {
    QueryBuilder::new().validate_nosql_value(value)
}

/// Escape a NoSQL field name to prevent operator injection
///
/// Replaces leading `$` with `_` and escapes prototype pollution keys.
#[must_use]
pub fn escape_nosql_field(name: &str) -> String {
    QueryBuilder::new().escape_nosql_field(name)
}

/// Escape a NoSQL field path (handles dots for nested fields)
#[must_use]
pub fn escape_nosql_path(path: &str) -> String {
    QueryBuilder::new().escape_nosql_path(path)
}

/// Sanitize a value for NoSQL queries
///
/// Strips operators and prototype pollution patterns.
#[must_use]
pub fn sanitize_nosql_value(input: &str) -> String {
    QueryBuilder::new().sanitize_nosql_value(input)
}

/// Strip MongoDB operators from input
#[must_use]
pub fn strip_nosql_operators(input: &str) -> String {
    QueryBuilder::new().strip_nosql_operators(input)
}

// ============================================================================
// LDAP Shortcuts
// ============================================================================

/// Check if input contains LDAP injection patterns
#[must_use]
pub fn is_ldap_injection_present(input: &str) -> bool {
    QueryBuilder::new().is_ldap_injection_present(input)
}

/// Detect all LDAP injection threats in input
#[must_use]
pub fn detect_ldap_threats(input: &str) -> Vec<QueryThreat> {
    QueryBuilder::new().detect_ldap_threats(input)
}

/// Validate that an LDAP filter is safe
pub fn validate_ldap_filter(filter: &str) -> Result<(), Problem> {
    QueryBuilder::new().validate_ldap_filter(filter)
}

/// Escape a string for LDAP filters (RFC 4515)
#[must_use]
pub fn escape_ldap_filter(input: &str) -> String {
    QueryBuilder::new().escape_ldap_filter(input)
}

/// Escape a string for LDAP distinguished names (RFC 4514)
#[must_use]
pub fn escape_ldap_dn(input: &str) -> String {
    QueryBuilder::new().escape_ldap_dn(input)
}

// ============================================================================
// GraphQL Shortcuts
// ============================================================================

/// Check if query contains GraphQL abuse patterns
#[must_use]
pub fn is_graphql_injection_present(query: &str) -> bool {
    QueryBuilder::new().is_graphql_injection_present(query)
}

/// Detect all GraphQL threats in query
#[must_use]
pub fn detect_graphql_threats(query: &str) -> Vec<QueryThreat> {
    QueryBuilder::new().detect_graphql_threats(query)
}

/// Analyze a GraphQL query for security concerns
///
/// Returns detailed analysis including depth, alias count, field count,
/// and detected threats.
#[must_use]
pub fn analyze_graphql_query(query: &str) -> GraphqlAnalysis {
    QueryBuilder::new().analyze_graphql_query(query)
}

// ============================================================================
// Generic Shortcuts
// ============================================================================

/// Detect threats for a specific query type
///
/// Use this when you need to handle multiple query types dynamically.
#[must_use]
pub fn detect_threats(input: &str, query_type: QueryType) -> Vec<QueryThreat> {
    QueryBuilder::new().detect_threats(input, query_type)
}

/// Check if input contains injection patterns for a specific query type
///
/// Use this when you need to handle multiple query types dynamically.
#[must_use]
pub fn is_injection_present(input: &str, query_type: QueryType) -> bool {
    QueryBuilder::new().is_injection_present(input, query_type)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_shortcuts() {
        assert!(is_sql_injection_present("' OR 1=1 --"));
        assert!(!is_sql_injection_present("hello"));
        assert!(validate_sql_parameter("hello").is_ok());
        assert!(validate_sql_parameter("' OR 1=1").is_err());
        assert_eq!(escape_sql_string("O'Brien"), "O''Brien");
    }

    #[test]
    fn test_nosql_shortcuts() {
        assert!(is_nosql_injection_present(r#"{ "$gt": "" }"#));
        assert!(!is_nosql_injection_present("hello"));
        assert!(validate_nosql_value("hello").is_ok());
    }

    #[test]
    fn test_ldap_shortcuts() {
        assert!(is_ldap_injection_present("admin)("));
        assert!(!is_ldap_injection_present("admin"));
        assert!(validate_ldap_filter("admin").is_ok());
        assert_eq!(escape_ldap_filter("test*"), "test\\2a");
    }

    #[test]
    fn test_graphql_shortcuts() {
        assert!(is_graphql_injection_present(
            "{ __schema { types { name } } }"
        ));
        assert!(!is_graphql_injection_present("{ user { name } }"));

        // Test analyze_graphql_query
        let analysis = analyze_graphql_query("{ user { name } }");
        assert!(!analysis.has_introspection);
    }

    #[test]
    fn test_generic_shortcuts() {
        // Test is_injection_present with different query types
        assert!(is_injection_present("' OR 1=1 --", QueryType::Sql));
        assert!(is_injection_present("$gt", QueryType::NoSql));
        assert!(is_injection_present("admin)(", QueryType::Ldap));
        assert!(is_injection_present("{ __schema }", QueryType::GraphQL));

        // Test detect_threats
        let sql_threats = detect_threats("' OR 1=1 --", QueryType::Sql);
        assert!(!sql_threats.is_empty());
    }

    #[test]
    fn test_escape_sql_identifier() {
        // Plain identifier gets wrapped in double quotes.
        assert_eq!(escape_sql_identifier("users"), "\"users\"");
        // Embedded double quotes are doubled.
        assert_eq!(escape_sql_identifier("u\"ser"), "\"u\"\"ser\"");
    }

    #[test]
    fn test_escape_nosql_path() {
        // Leading `$` on a path segment is replaced with `_`.
        assert_eq!(escape_nosql_path("$set.value"), "_set.value");
        // Paths without operators pass through.
        assert_eq!(escape_nosql_path("user.name"), "user.name");
    }

    #[test]
    fn test_sanitize_nosql_value() {
        // Operator `$gt` has the `$` stripped.
        assert_eq!(sanitize_nosql_value("$gt"), "gt");
        // Prototype pollution key gets mangled.
        assert_eq!(sanitize_nosql_value("__proto__"), "_proto_");
        // Safe values pass through.
        assert_eq!(sanitize_nosql_value("hello"), "hello");
    }

    #[test]
    fn test_strip_nosql_operators() {
        // Known operator is stripped.
        assert_eq!(strip_nosql_operators("$gt"), "gt");
        // Non-operators pass through.
        assert_eq!(strip_nosql_operators("hello"), "hello");
        assert_eq!(strip_nosql_operators("$100"), "$100");
    }

    #[test]
    fn test_detect_ldap_threats() {
        let threats = detect_ldap_threats("admin)(");
        assert!(!threats.is_empty());

        let safe = detect_ldap_threats("admin");
        assert!(safe.is_empty());
    }

    #[test]
    fn test_escape_ldap_dn() {
        // Commas in DN are escaped with backslash.
        assert_eq!(escape_ldap_dn("user,name"), "user\\,name");
        // Plain strings pass through.
        assert_eq!(escape_ldap_dn("plain"), "plain");
    }

    #[test]
    fn test_detect_graphql_threats() {
        let threats = detect_graphql_threats("{ __schema { types { name } } }");
        assert!(!threats.is_empty());

        let safe = detect_graphql_threats("{ user { name } }");
        assert!(safe.is_empty());
    }
}

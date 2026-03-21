//! Query security builder
//!
//! Unified API for query injection detection, validation, and sanitization.

use super::graphql::{self, GraphqlSchema};
use super::ldap;
use super::nosql;
use super::sql;
use super::types::{GraphqlAnalysis, GraphqlConfig, QueryThreat, QueryType};
use crate::primitives::types::Problem;

// ============================================================================
// Query Security Builder
// ============================================================================

/// Unified builder for query security operations
///
/// Provides a consistent API for detecting, validating, and sanitizing
/// queries across SQL, NoSQL, LDAP, and GraphQL.
///
/// # Example
///
/// ```ignore
/// use octarine::primitives::security::queries::QuerySecurityBuilder;
///
/// let builder = QuerySecurityBuilder::new();
///
/// // SQL injection detection
/// if builder.is_sql_injection_present(user_input) {
///     // Handle threat
/// }
///
/// // Validate parameter
/// builder.validate_sql_parameter(user_input)?;
///
/// // Escape for safe interpolation
/// let safe = builder.escape_sql_string(user_input);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct QuerySecurityBuilder;

impl QuerySecurityBuilder {
    /// Create a new query security builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // ========================================================================
    // SQL Methods
    // ========================================================================

    /// Check if input contains SQL injection patterns
    ///
    /// This is a comprehensive check that looks for multiple attack vectors.
    #[must_use]
    pub fn is_sql_injection_present(&self, input: &str) -> bool {
        sql::is_sql_injection_present(input)
    }

    /// Detect all SQL injection threats in input
    ///
    /// Returns a list of all detected threat types for logging/analysis.
    #[must_use]
    pub fn detect_sql_threats(&self, input: &str) -> Vec<QueryThreat> {
        sql::detect_sql_threats(input)
    }

    /// Validate that a SQL parameter is safe
    ///
    /// Returns an error if injection patterns are detected.
    pub fn validate_sql_parameter(&self, param: &str) -> Result<(), Problem> {
        sql::validate_sql_parameter(param)
    }

    /// Escape a string for SQL queries (ANSI standard)
    ///
    /// # Warning
    ///
    /// Prefer parameterized queries. Use this only when necessary.
    #[must_use]
    pub fn escape_sql_string(&self, input: &str) -> String {
        sql::escape_sql_string(input)
    }

    /// Escape a SQL identifier (table/column name)
    ///
    /// Wraps in double quotes and escapes embedded quotes.
    #[must_use]
    pub fn escape_sql_identifier(&self, name: &str) -> String {
        sql::escape_sql_identifier(name)
    }

    // ========================================================================
    // NoSQL Methods
    // ========================================================================

    /// Check if input contains NoSQL injection patterns
    #[must_use]
    pub fn is_nosql_injection_present(&self, input: &str) -> bool {
        nosql::is_nosql_injection_present(input)
    }

    /// Detect all NoSQL injection threats in input
    #[must_use]
    pub fn detect_nosql_threats(&self, input: &str) -> Vec<QueryThreat> {
        nosql::detect_nosql_threats(input)
    }

    /// Validate that a NoSQL value is safe
    pub fn validate_nosql_value(&self, value: &str) -> Result<(), Problem> {
        nosql::validate_nosql_value(value)
    }

    /// Escape a NoSQL field name to prevent operator injection
    ///
    /// Replaces leading `$` with `_` and escapes prototype pollution keys.
    #[must_use]
    pub fn escape_nosql_field(&self, name: &str) -> String {
        nosql::escape_nosql_field(name)
    }

    /// Escape a NoSQL field path (handles dots for nested fields)
    #[must_use]
    pub fn escape_nosql_path(&self, path: &str) -> String {
        nosql::escape_nosql_path(path)
    }

    /// Sanitize a value for NoSQL queries
    ///
    /// Strips operators and prototype pollution patterns.
    #[must_use]
    pub fn sanitize_nosql_value(&self, input: &str) -> String {
        nosql::sanitize_nosql_value(input)
    }

    /// Strip MongoDB operators from input
    #[must_use]
    pub fn strip_nosql_operators(&self, input: &str) -> String {
        nosql::strip_nosql_operators(input)
    }

    // ========================================================================
    // LDAP Methods
    // ========================================================================

    /// Check if input contains LDAP injection patterns
    #[must_use]
    pub fn is_ldap_injection_present(&self, input: &str) -> bool {
        ldap::is_ldap_injection_present(input)
    }

    /// Detect all LDAP injection threats in input
    #[must_use]
    pub fn detect_ldap_threats(&self, input: &str) -> Vec<QueryThreat> {
        ldap::detect_ldap_threats(input)
    }

    /// Validate that an LDAP filter is safe
    pub fn validate_ldap_filter(&self, filter: &str) -> Result<(), Problem> {
        ldap::validate_ldap_filter(filter)
    }

    /// Escape a string for LDAP filters (RFC 4515)
    #[must_use]
    pub fn escape_ldap_filter(&self, input: &str) -> String {
        ldap::escape_ldap_filter(input)
    }

    /// Escape a string for LDAP distinguished names (RFC 4514)
    #[must_use]
    pub fn escape_ldap_dn(&self, input: &str) -> String {
        ldap::escape_ldap_dn(input)
    }

    // ========================================================================
    // GraphQL Methods
    // ========================================================================

    /// Check if query contains GraphQL abuse patterns
    #[must_use]
    pub fn is_graphql_injection_present(&self, query: &str) -> bool {
        graphql::is_graphql_injection_present(query)
    }

    /// Detect all GraphQL threats in query
    #[must_use]
    pub fn detect_graphql_threats(&self, query: &str) -> Vec<QueryThreat> {
        graphql::detect_graphql_threats(query)
    }

    /// Analyze a GraphQL query for security concerns
    #[must_use]
    pub fn analyze_graphql_query(&self, query: &str) -> GraphqlAnalysis {
        graphql::analyze_graphql_query(query)
    }

    /// Validate a GraphQL query against a schema and security config
    pub fn validate_graphql_query(
        &self,
        query: &str,
        schema: &GraphqlSchema,
        config: &GraphqlConfig,
    ) -> Result<(), Problem> {
        graphql::validate_graphql_query(query, schema, config)
    }

    // ========================================================================
    // Generic Methods
    // ========================================================================

    /// Detect threats for a specific query type
    #[must_use]
    pub fn detect_threats(&self, input: &str, query_type: QueryType) -> Vec<QueryThreat> {
        match query_type {
            QueryType::Sql => self.detect_sql_threats(input),
            QueryType::NoSql => self.detect_nosql_threats(input),
            QueryType::Ldap => self.detect_ldap_threats(input),
            QueryType::GraphQL => self.detect_graphql_threats(input),
        }
    }

    /// Check if input contains injection patterns for a specific query type
    #[must_use]
    pub fn is_injection_present(&self, input: &str, query_type: QueryType) -> bool {
        match query_type {
            QueryType::Sql => self.is_sql_injection_present(input),
            QueryType::NoSql => self.is_nosql_injection_present(input),
            QueryType::Ldap => self.is_ldap_injection_present(input),
            QueryType::GraphQL => self.is_graphql_injection_present(input),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_sql_detection() {
        let builder = QuerySecurityBuilder::new();

        assert!(builder.is_sql_injection_present("' OR 1=1 --"));
        assert!(!builder.is_sql_injection_present("hello world"));
    }

    #[test]
    fn test_builder_sql_validation() {
        let builder = QuerySecurityBuilder::new();

        assert!(builder.validate_sql_parameter("hello").is_ok());
        assert!(builder.validate_sql_parameter("' OR 1=1 --").is_err());
    }

    #[test]
    fn test_builder_sql_escaping() {
        let builder = QuerySecurityBuilder::new();

        assert_eq!(builder.escape_sql_string("O'Brien"), "O''Brien");
        assert_eq!(builder.escape_sql_identifier("user"), "\"user\"");
    }

    #[test]
    fn test_builder_nosql_detection() {
        let builder = QuerySecurityBuilder::new();

        assert!(builder.is_nosql_injection_present(r#"{ "$gt": "" }"#));
        assert!(builder.is_nosql_injection_present("__proto__"));
        assert!(!builder.is_nosql_injection_present("hello"));
    }

    #[test]
    fn test_builder_ldap_detection() {
        let builder = QuerySecurityBuilder::new();

        assert!(builder.is_ldap_injection_present("admin)("));
        assert!(builder.is_ldap_injection_present("test*"));
        assert!(!builder.is_ldap_injection_present("hello"));
    }

    #[test]
    fn test_builder_ldap_escaping() {
        let builder = QuerySecurityBuilder::new();

        assert_eq!(builder.escape_ldap_filter("test*"), "test\\2a");
        assert_eq!(builder.escape_ldap_dn("user,name"), "user\\,name");
    }

    #[test]
    fn test_builder_graphql_detection() {
        let builder = QuerySecurityBuilder::new();

        assert!(builder.is_graphql_injection_present("{ __schema { types { name } } }"));
        assert!(!builder.is_graphql_injection_present("{ user { name } }"));
    }

    #[test]
    fn test_builder_generic_detect() {
        let builder = QuerySecurityBuilder::new();

        let sql_threats = builder.detect_threats("' OR 1=1 --", QueryType::Sql);
        assert!(!sql_threats.is_empty());

        let nosql_threats = builder.detect_threats("__proto__", QueryType::NoSql);
        assert!(!nosql_threats.is_empty());
    }

    #[test]
    fn test_builder_generic_is_injection() {
        let builder = QuerySecurityBuilder::new();

        assert!(builder.is_injection_present("' OR 1=1 --", QueryType::Sql));
        assert!(builder.is_injection_present("__proto__", QueryType::NoSql));
        assert!(builder.is_injection_present("admin)(", QueryType::Ldap));
        assert!(builder.is_injection_present("{ __schema }", QueryType::GraphQL));
    }
}

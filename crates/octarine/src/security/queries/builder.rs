//! Query security builder with observability
//!
//! Wraps the primitives query security builder with observe instrumentation.

use crate::observe::event;
use crate::primitives::security::queries::{
    GraphqlAnalysis, GraphqlConfig, GraphqlSchema, QuerySecurityBuilder as PrimitiveBuilder,
    QueryThreat, QueryType,
};
use crate::primitives::types::Problem;

/// Query security builder with observability
///
/// Provides a unified API for query injection detection, validation,
/// and sanitization with automatic observe instrumentation.
///
/// # Example
///
/// ```ignore
/// use octarine::security::queries::QueryBuilder;
///
/// let builder = QueryBuilder::new();
///
/// // Validate user input for SQL
/// builder.validate_sql_parameter(user_input)?;
///
/// // Escape if parameterization isn't possible
/// let safe = builder.escape_sql_string(user_input);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct QueryBuilder {
    inner: PrimitiveBuilder,
}

impl QueryBuilder {
    /// Create a new query security builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PrimitiveBuilder::new(),
        }
    }

    // ========================================================================
    // SQL Methods
    // ========================================================================

    /// Check if input contains SQL injection patterns
    #[must_use]
    pub fn is_sql_injection_present(&self, input: &str) -> bool {
        let result = self.inner.is_sql_injection_present(input);
        if result {
            event::warn("security: SQL injection pattern detected");
        }
        result
    }

    /// Detect all SQL injection threats in input
    #[must_use]
    pub fn detect_sql_threats(&self, input: &str) -> Vec<QueryThreat> {
        let threats = self.inner.detect_sql_threats(input);
        if !threats.is_empty() {
            event::warn(format!(
                "security: Detected {} SQL injection threats",
                threats.len()
            ));
        }
        threats
    }

    /// Validate that a SQL parameter is safe
    pub fn validate_sql_parameter(&self, param: &str) -> Result<(), Problem> {
        let result = self.inner.validate_sql_parameter(param);
        if result.is_err() {
            event::warn("security: SQL parameter validation failed");
        }
        result
    }

    /// Escape a string for SQL queries
    #[must_use]
    pub fn escape_sql_string(&self, input: &str) -> String {
        self.inner.escape_sql_string(input)
    }

    /// Escape a SQL identifier (table/column name)
    #[must_use]
    pub fn escape_sql_identifier(&self, name: &str) -> String {
        self.inner.escape_sql_identifier(name)
    }

    // ========================================================================
    // NoSQL Methods
    // ========================================================================

    /// Check if input contains NoSQL injection patterns
    #[must_use]
    pub fn is_nosql_injection_present(&self, input: &str) -> bool {
        let result = self.inner.is_nosql_injection_present(input);
        if result {
            event::warn("security: NoSQL injection pattern detected");
        }
        result
    }

    /// Detect all NoSQL injection threats in input
    #[must_use]
    pub fn detect_nosql_threats(&self, input: &str) -> Vec<QueryThreat> {
        let threats = self.inner.detect_nosql_threats(input);
        if !threats.is_empty() {
            event::warn(format!(
                "security: Detected {} NoSQL injection threats",
                threats.len()
            ));
        }
        threats
    }

    /// Validate that a NoSQL value is safe
    pub fn validate_nosql_value(&self, value: &str) -> Result<(), Problem> {
        let result = self.inner.validate_nosql_value(value);
        if result.is_err() {
            event::warn("security: NoSQL value validation failed");
        }
        result
    }

    /// Escape a NoSQL field name to prevent operator injection
    #[must_use]
    pub fn escape_nosql_field(&self, name: &str) -> String {
        self.inner.escape_nosql_field(name)
    }

    /// Escape a NoSQL field path (handles dots for nested fields)
    #[must_use]
    pub fn escape_nosql_path(&self, path: &str) -> String {
        self.inner.escape_nosql_path(path)
    }

    /// Sanitize a value for NoSQL queries
    #[must_use]
    pub fn sanitize_nosql_value(&self, input: &str) -> String {
        self.inner.sanitize_nosql_value(input)
    }

    /// Strip MongoDB operators from input
    #[must_use]
    pub fn strip_nosql_operators(&self, input: &str) -> String {
        self.inner.strip_nosql_operators(input)
    }

    // ========================================================================
    // LDAP Methods
    // ========================================================================

    /// Check if input contains LDAP injection patterns
    #[must_use]
    pub fn is_ldap_injection_present(&self, input: &str) -> bool {
        let result = self.inner.is_ldap_injection_present(input);
        if result {
            event::warn("security: LDAP injection pattern detected");
        }
        result
    }

    /// Detect all LDAP injection threats in input
    #[must_use]
    pub fn detect_ldap_threats(&self, input: &str) -> Vec<QueryThreat> {
        let threats = self.inner.detect_ldap_threats(input);
        if !threats.is_empty() {
            event::warn(format!(
                "security: Detected {} LDAP injection threats",
                threats.len()
            ));
        }
        threats
    }

    /// Validate that an LDAP filter is safe
    pub fn validate_ldap_filter(&self, filter: &str) -> Result<(), Problem> {
        let result = self.inner.validate_ldap_filter(filter);
        if result.is_err() {
            event::warn("security: LDAP filter validation failed");
        }
        result
    }

    /// Escape a string for LDAP filters (RFC 4515)
    #[must_use]
    pub fn escape_ldap_filter(&self, input: &str) -> String {
        self.inner.escape_ldap_filter(input)
    }

    /// Escape a string for LDAP distinguished names (RFC 4514)
    #[must_use]
    pub fn escape_ldap_dn(&self, input: &str) -> String {
        self.inner.escape_ldap_dn(input)
    }

    // ========================================================================
    // GraphQL Methods
    // ========================================================================

    /// Check if query contains GraphQL abuse patterns
    #[must_use]
    pub fn is_graphql_injection_present(&self, query: &str) -> bool {
        let result = self.inner.is_graphql_injection_present(query);
        if result {
            event::warn("security: GraphQL abuse pattern detected");
        }
        result
    }

    /// Detect all GraphQL threats in query
    #[must_use]
    pub fn detect_graphql_threats(&self, query: &str) -> Vec<QueryThreat> {
        let threats = self.inner.detect_graphql_threats(query);
        if !threats.is_empty() {
            event::warn(format!(
                "security: Detected {} GraphQL threats",
                threats.len()
            ));
        }
        threats
    }

    /// Analyze a GraphQL query for security concerns
    #[must_use]
    pub fn analyze_graphql_query(&self, query: &str) -> GraphqlAnalysis {
        self.inner.analyze_graphql_query(query)
    }

    /// Validate a GraphQL query against a schema and security config
    pub fn validate_graphql_query(
        &self,
        query: &str,
        schema: &GraphqlSchema,
        config: &GraphqlConfig,
    ) -> Result<(), Problem> {
        let result = self.inner.validate_graphql_query(query, schema, config);
        if result.is_err() {
            event::warn("security: GraphQL query validation failed");
        }
        result
    }

    // ========================================================================
    // Generic Methods
    // ========================================================================

    /// Detect threats for a specific query type
    #[must_use]
    pub fn detect_threats(&self, input: &str, query_type: QueryType) -> Vec<QueryThreat> {
        let threats = self.inner.detect_threats(input, query_type);
        if !threats.is_empty() {
            event::warn(format!(
                "security: Detected {} {} threats",
                threats.len(),
                query_type
            ));
        }
        threats
    }

    /// Check if input contains injection patterns for a specific query type
    #[must_use]
    pub fn is_injection_present(&self, input: &str, query_type: QueryType) -> bool {
        let result = self.inner.is_injection_present(input, query_type);
        if result {
            event::warn(format!(
                "security: {} injection pattern detected",
                query_type
            ));
        }
        result
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
        let builder = QueryBuilder::new();
        assert!(builder.is_sql_injection_present("' OR 1=1 --"));
        assert!(!builder.is_sql_injection_present("hello"));
    }

    #[test]
    fn test_builder_sql_validation() {
        let builder = QueryBuilder::new();
        assert!(builder.validate_sql_parameter("hello").is_ok());
        assert!(builder.validate_sql_parameter("' OR 1=1 --").is_err());
    }

    #[test]
    fn test_builder_sql_escaping() {
        let builder = QueryBuilder::new();
        assert_eq!(builder.escape_sql_string("O'Brien"), "O''Brien");
    }

    #[test]
    fn test_builder_nosql_detection() {
        let builder = QueryBuilder::new();
        assert!(builder.is_nosql_injection_present(r#"{ "$gt": "" }"#));
        assert!(!builder.is_nosql_injection_present("hello"));
    }

    #[test]
    fn test_builder_ldap_detection() {
        let builder = QueryBuilder::new();
        assert!(builder.is_ldap_injection_present("admin)("));
        assert!(!builder.is_ldap_injection_present("admin"));
    }

    #[test]
    fn test_builder_graphql_detection() {
        let builder = QueryBuilder::new();
        assert!(builder.is_graphql_injection_present("{ __schema { types { name } } }"));
        assert!(!builder.is_graphql_injection_present("{ user { name } }"));
    }
}

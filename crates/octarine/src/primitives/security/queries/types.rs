//! Query security types
//!
//! Core types for query injection detection and prevention.

use std::fmt;

// ============================================================================
// Query Type
// ============================================================================

/// Type of query being analyzed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryType {
    /// SQL queries (PostgreSQL, MySQL, SQLite, etc.)
    Sql,
    /// NoSQL queries (MongoDB, etc.)
    NoSql,
    /// LDAP filters and distinguished names
    Ldap,
    /// GraphQL queries and mutations
    GraphQL,
}

impl fmt::Display for QueryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sql => write!(f, "SQL"),
            Self::NoSql => write!(f, "NoSQL"),
            Self::Ldap => write!(f, "LDAP"),
            Self::GraphQL => write!(f, "GraphQL"),
        }
    }
}

// ============================================================================
// Query Threat
// ============================================================================

/// Types of query injection threats
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum QueryThreat {
    // ========== SQL Threats ==========
    /// SQL keywords in user input (SELECT, UNION, DROP, etc.)
    SqlKeywordInInput,
    /// Comment sequences that can bypass filters (--, /*, #)
    SqlCommentSequence,
    /// String terminators that can break out of quoted contexts (' or ")
    SqlStringTerminator,
    /// Boolean logic injection (OR 1=1, AND 1=0)
    SqlBooleanLogic,
    /// Time-based blind injection (SLEEP, WAITFOR, pg_sleep)
    SqlTimeBasedBlind,
    /// Stacked queries using semicolon
    SqlStackedQueries,
    /// UNION-based injection
    SqlUnionBased,
    /// Hex-encoded strings for filter bypass (0x...)
    SqlHexEncoding,
    /// CHAR() function abuse for filter bypass
    SqlCharFunction,

    // ========== NoSQL Threats ==========
    /// MongoDB operators in input ($where, $gt, $ne, $regex, etc.)
    NoSqlOperator,
    /// JavaScript injection in $where clauses
    NoSqlJsInjection,
    /// Prototype pollution (__proto__, constructor, prototype)
    NoSqlPrototypePollution,
    /// Array operator abuse
    NoSqlArrayInjection,

    // ========== LDAP Threats ==========
    /// LDAP filter injection ()( , *(, etc.)
    LdapFilterInjection,
    /// Null byte to truncate filter
    LdapNullByte,
    /// Unescaped wildcard for enumeration
    LdapWildcard,

    // ========== GraphQL Threats ==========
    /// Introspection queries (__schema, __type)
    GraphqlIntrospection,
    /// Excessive aliases for DoS
    GraphqlAliasBombing,
    /// Query batching abuse
    GraphqlBatching,
    /// Duplicate fields for DoS
    GraphqlFieldDuplication,
    /// Excessive query depth
    GraphqlDepthExceeded,
    /// Too many fields in query
    GraphqlFieldCountExceeded,
}

impl QueryThreat {
    /// Get the query type this threat belongs to
    #[must_use]
    pub fn query_type(&self) -> QueryType {
        match self {
            Self::SqlKeywordInInput
            | Self::SqlCommentSequence
            | Self::SqlStringTerminator
            | Self::SqlBooleanLogic
            | Self::SqlTimeBasedBlind
            | Self::SqlStackedQueries
            | Self::SqlUnionBased
            | Self::SqlHexEncoding
            | Self::SqlCharFunction => QueryType::Sql,

            Self::NoSqlOperator
            | Self::NoSqlJsInjection
            | Self::NoSqlPrototypePollution
            | Self::NoSqlArrayInjection => QueryType::NoSql,

            Self::LdapFilterInjection | Self::LdapNullByte | Self::LdapWildcard => QueryType::Ldap,

            Self::GraphqlIntrospection
            | Self::GraphqlAliasBombing
            | Self::GraphqlBatching
            | Self::GraphqlFieldDuplication
            | Self::GraphqlDepthExceeded
            | Self::GraphqlFieldCountExceeded => QueryType::GraphQL,
        }
    }

    /// Get the CWE identifier for this threat
    #[must_use]
    pub fn cwe(&self) -> &'static str {
        match self.query_type() {
            QueryType::Sql => "CWE-89",
            QueryType::NoSql => "CWE-943",
            QueryType::Ldap => "CWE-90",
            QueryType::GraphQL => "CWE-1021",
        }
    }

    /// Get a human-readable description
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::SqlKeywordInInput => "SQL keyword detected in user input",
            Self::SqlCommentSequence => "SQL comment sequence detected",
            Self::SqlStringTerminator => "String terminator detected",
            Self::SqlBooleanLogic => "Boolean logic injection pattern detected",
            Self::SqlTimeBasedBlind => "Time-based blind injection pattern detected",
            Self::SqlStackedQueries => "Stacked query attempt detected",
            Self::SqlUnionBased => "UNION-based injection pattern detected",
            Self::SqlHexEncoding => "Hex-encoded string detected (filter bypass attempt)",
            Self::SqlCharFunction => "CHAR() function abuse detected (filter bypass attempt)",

            Self::NoSqlOperator => "NoSQL operator detected in user input",
            Self::NoSqlJsInjection => "JavaScript injection in query detected",
            Self::NoSqlPrototypePollution => "Prototype pollution attempt detected",
            Self::NoSqlArrayInjection => "Array injection pattern detected",

            Self::LdapFilterInjection => "LDAP filter injection pattern detected",
            Self::LdapNullByte => "Null byte in LDAP filter detected",
            Self::LdapWildcard => "Unescaped wildcard in LDAP filter",

            Self::GraphqlIntrospection => "GraphQL introspection query detected",
            Self::GraphqlAliasBombing => "Excessive GraphQL aliases detected",
            Self::GraphqlBatching => "GraphQL query batching abuse detected",
            Self::GraphqlFieldDuplication => "Excessive field duplication detected",
            Self::GraphqlDepthExceeded => "GraphQL query depth exceeded limit",
            Self::GraphqlFieldCountExceeded => "GraphQL field count exceeded limit",
        }
    }
}

impl fmt::Display for QueryThreat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.cwe(), self.description())
    }
}

// ============================================================================
// GraphQL Configuration
// ============================================================================

/// Configuration for GraphQL query validation
#[derive(Debug, Clone)]
pub struct GraphqlConfig {
    /// Allow introspection queries (default: false)
    pub allow_introspection: bool,
    /// Maximum query depth (default: 10)
    pub max_depth: usize,
    /// Maximum number of aliases (default: 10)
    pub max_aliases: usize,
    /// Maximum number of fields (default: 100)
    pub max_fields: usize,
    /// Maximum batch size for query batching (default: 10)
    pub max_batch_size: usize,
}

impl Default for GraphqlConfig {
    fn default() -> Self {
        Self {
            allow_introspection: false,
            max_depth: 10,
            max_aliases: 10,
            max_fields: 100,
            max_batch_size: 10,
        }
    }
}

impl GraphqlConfig {
    /// Create a new GraphQL configuration with defaults
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow introspection queries (use with caution in production)
    #[must_use]
    pub fn with_introspection(mut self) -> Self {
        self.allow_introspection = true;
        self
    }

    /// Set maximum query depth
    #[must_use]
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Set maximum aliases
    #[must_use]
    pub fn with_max_aliases(mut self, aliases: usize) -> Self {
        self.max_aliases = aliases;
        self
    }

    /// Set maximum fields
    #[must_use]
    pub fn with_max_fields(mut self, fields: usize) -> Self {
        self.max_fields = fields;
        self
    }

    /// Set maximum batch size
    #[must_use]
    pub fn with_max_batch_size(mut self, size: usize) -> Self {
        self.max_batch_size = size;
        self
    }

    /// Create a strict configuration for high-security environments
    #[must_use]
    pub fn strict() -> Self {
        Self {
            allow_introspection: false,
            max_depth: 5,
            max_aliases: 5,
            max_fields: 50,
            max_batch_size: 5,
        }
    }

    /// Create a relaxed configuration for development
    #[must_use]
    pub fn development() -> Self {
        Self {
            allow_introspection: true,
            max_depth: 20,
            max_aliases: 50,
            max_fields: 500,
            max_batch_size: 50,
        }
    }
}

// ============================================================================
// GraphQL Analysis Result
// ============================================================================

/// Result of analyzing a GraphQL query
#[derive(Debug, Clone, Default)]
pub struct GraphqlAnalysis {
    /// Maximum depth of the query
    pub depth: usize,
    /// Number of aliases used
    pub alias_count: usize,
    /// Total number of fields
    pub field_count: usize,
    /// Whether introspection queries are present
    pub has_introspection: bool,
    /// Number of operations (for batching detection)
    pub operation_count: usize,
    /// Detected threats
    pub threats: Vec<QueryThreat>,
}

impl GraphqlAnalysis {
    /// Check if any threats were detected
    #[must_use]
    pub fn is_threat_detected(&self) -> bool {
        !self.threats.is_empty()
    }

    /// Check if the analysis passes the given configuration
    #[must_use]
    pub fn passes_config(&self, config: &GraphqlConfig) -> bool {
        if self.has_introspection && !config.allow_introspection {
            return false;
        }
        if self.depth > config.max_depth {
            return false;
        }
        if self.alias_count > config.max_aliases {
            return false;
        }
        if self.field_count > config.max_fields {
            return false;
        }
        if self.operation_count > config.max_batch_size {
            return false;
        }
        true
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_type_display() {
        assert_eq!(QueryType::Sql.to_string(), "SQL");
        assert_eq!(QueryType::NoSql.to_string(), "NoSQL");
        assert_eq!(QueryType::Ldap.to_string(), "LDAP");
        assert_eq!(QueryType::GraphQL.to_string(), "GraphQL");
    }

    #[test]
    fn test_query_threat_cwe() {
        assert_eq!(QueryThreat::SqlKeywordInInput.cwe(), "CWE-89");
        assert_eq!(QueryThreat::NoSqlOperator.cwe(), "CWE-943");
        assert_eq!(QueryThreat::LdapFilterInjection.cwe(), "CWE-90");
        assert_eq!(QueryThreat::GraphqlIntrospection.cwe(), "CWE-1021");
    }

    #[test]
    fn test_query_threat_query_type() {
        assert_eq!(QueryThreat::SqlUnionBased.query_type(), QueryType::Sql);
        assert_eq!(
            QueryThreat::NoSqlPrototypePollution.query_type(),
            QueryType::NoSql
        );
        assert_eq!(QueryThreat::LdapNullByte.query_type(), QueryType::Ldap);
        assert_eq!(
            QueryThreat::GraphqlAliasBombing.query_type(),
            QueryType::GraphQL
        );
    }

    #[test]
    fn test_graphql_config_defaults() {
        let config = GraphqlConfig::default();
        assert!(!config.allow_introspection);
        assert_eq!(config.max_depth, 10);
        assert_eq!(config.max_aliases, 10);
        assert_eq!(config.max_fields, 100);
        assert_eq!(config.max_batch_size, 10);
    }

    #[test]
    fn test_graphql_config_strict() {
        let config = GraphqlConfig::strict();
        assert!(!config.allow_introspection);
        assert_eq!(config.max_depth, 5);
    }

    #[test]
    fn test_graphql_config_development() {
        let config = GraphqlConfig::development();
        assert!(config.allow_introspection);
        assert_eq!(config.max_depth, 20);
    }

    #[test]
    fn test_graphql_analysis_passes_config() {
        let config = GraphqlConfig::default();

        let passing = GraphqlAnalysis {
            depth: 5,
            alias_count: 5,
            field_count: 50,
            has_introspection: false,
            operation_count: 1,
            threats: vec![],
        };
        assert!(passing.passes_config(&config));

        let failing_depth = GraphqlAnalysis {
            depth: 15,
            ..Default::default()
        };
        assert!(!failing_depth.passes_config(&config));

        let failing_introspection = GraphqlAnalysis {
            has_introspection: true,
            ..Default::default()
        };
        assert!(!failing_introspection.passes_config(&config));
    }
}

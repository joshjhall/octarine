//! Query security builder with observability
//!
//! Wraps the primitives query security builder with observe instrumentation.

use std::time::Instant;

use crate::observe::event;
use crate::observe::metrics::{increment_by, record};
use crate::primitives::security::queries::{
    GraphqlAnalysis, GraphqlConfig, GraphqlSchema, QuerySecurityBuilder as PrimitiveBuilder,
    QueryThreat, QueryType,
};
use crate::primitives::types::Problem;

crate::define_metrics! {
    validate_ms => "security.queries.validate_ms",
    detect_ms => "security.queries.detect_ms",
    threats_detected => "security.queries.threats_detected",
}

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
#[derive(Debug, Clone, Copy)]
pub struct QueryBuilder {
    inner: PrimitiveBuilder,
    emit_events: bool,
}

impl Default for QueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryBuilder {
    /// Create a new query security builder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PrimitiveBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: PrimitiveBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // SQL Methods
    // ========================================================================

    /// Check if input contains SQL injection patterns
    #[must_use]
    pub fn is_sql_injection_present(&self, input: &str) -> bool {
        let result = self.inner.is_sql_injection_present(input);
        if self.emit_events && result {
            event::warn("security: SQL injection pattern detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Detect all SQL injection threats in input
    #[must_use]
    pub fn detect_sql_threats(&self, input: &str) -> Vec<QueryThreat> {
        let start = Instant::now();
        let threats = self.inner.detect_sql_threats(input);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !threats.is_empty() {
                event::warn(format!(
                    "security: Detected {} SQL injection threats",
                    threats.len()
                ));
                increment_by(metric_names::threats_detected(), threats.len() as u64);
            }
        }
        threats
    }

    /// Validate that a SQL parameter is safe
    pub fn validate_sql_parameter(&self, param: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_sql_parameter(param);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
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
        if self.emit_events && result {
            event::warn("security: NoSQL injection pattern detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Detect all NoSQL injection threats in input
    #[must_use]
    pub fn detect_nosql_threats(&self, input: &str) -> Vec<QueryThreat> {
        let start = Instant::now();
        let threats = self.inner.detect_nosql_threats(input);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !threats.is_empty() {
                event::warn(format!(
                    "security: Detected {} NoSQL injection threats",
                    threats.len()
                ));
                increment_by(metric_names::threats_detected(), threats.len() as u64);
            }
        }
        threats
    }

    /// Validate that a NoSQL value is safe
    pub fn validate_nosql_value(&self, value: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_nosql_value(value);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
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
        if self.emit_events && result {
            event::warn("security: LDAP injection pattern detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Detect all LDAP injection threats in input
    #[must_use]
    pub fn detect_ldap_threats(&self, input: &str) -> Vec<QueryThreat> {
        let start = Instant::now();
        let threats = self.inner.detect_ldap_threats(input);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !threats.is_empty() {
                event::warn(format!(
                    "security: Detected {} LDAP injection threats",
                    threats.len()
                ));
                increment_by(metric_names::threats_detected(), threats.len() as u64);
            }
        }
        threats
    }

    /// Validate that an LDAP filter is safe
    pub fn validate_ldap_filter(&self, filter: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_ldap_filter(filter);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
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
        if self.emit_events && result {
            event::warn("security: GraphQL abuse pattern detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Detect all GraphQL threats in query
    #[must_use]
    pub fn detect_graphql_threats(&self, query: &str) -> Vec<QueryThreat> {
        let start = Instant::now();
        let threats = self.inner.detect_graphql_threats(query);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !threats.is_empty() {
                event::warn(format!(
                    "security: Detected {} GraphQL threats",
                    threats.len()
                ));
                increment_by(metric_names::threats_detected(), threats.len() as u64);
            }
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
        let start = Instant::now();
        let result = self.inner.validate_graphql_query(query, schema, config);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
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
        let start = Instant::now();
        let threats = self.inner.detect_threats(input, query_type);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !threats.is_empty() {
                event::warn(format!(
                    "security: Detected {} {} threats",
                    threats.len(),
                    query_type
                ));
                increment_by(metric_names::threats_detected(), threats.len() as u64);
            }
        }
        threats
    }

    /// Check if input contains injection patterns for a specific query type
    #[must_use]
    pub fn is_injection_present(&self, input: &str, query_type: QueryType) -> bool {
        let result = self.inner.is_injection_present(input, query_type);
        if self.emit_events && result {
            event::warn(format!(
                "security: {} injection pattern detected",
                query_type
            ));
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::observe::metrics::{flush_for_testing, snapshot};
    use std::sync::Mutex;

    static METRICS_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_builder_creation() {
        let builder = QueryBuilder::new();
        assert!(builder.emit_events);

        let silent = QueryBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events_toggle() {
        let builder = QueryBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_builder_sql_detection() {
        let builder = QueryBuilder::silent();
        assert!(builder.is_sql_injection_present("' OR 1=1 --"));
        assert!(!builder.is_sql_injection_present("hello"));
    }

    #[test]
    fn test_builder_sql_validation() {
        let builder = QueryBuilder::silent();
        assert!(builder.validate_sql_parameter("hello").is_ok());
        assert!(builder.validate_sql_parameter("' OR 1=1 --").is_err());
    }

    #[test]
    fn test_builder_sql_escaping() {
        let builder = QueryBuilder::silent();
        assert_eq!(builder.escape_sql_string("O'Brien"), "O''Brien");
    }

    #[test]
    fn test_builder_nosql_detection() {
        let builder = QueryBuilder::silent();
        assert!(builder.is_nosql_injection_present(r#"{ "$gt": "" }"#));
        assert!(!builder.is_nosql_injection_present("hello"));
    }

    #[test]
    fn test_builder_ldap_detection() {
        let builder = QueryBuilder::silent();
        assert!(builder.is_ldap_injection_present("admin)("));
        assert!(!builder.is_ldap_injection_present("admin"));
    }

    #[test]
    fn test_builder_graphql_detection() {
        let builder = QueryBuilder::silent();
        assert!(builder.is_graphql_injection_present("{ __schema { types { name } } }"));
        assert!(!builder.is_graphql_injection_present("{ user { name } }"));
    }

    #[test]
    fn test_metrics_validate_ms_recorded() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let builder = QueryBuilder::new();
        flush_for_testing();
        let before = snapshot()
            .histograms
            .get("security.queries.validate_ms")
            .map_or(0, |h| h.count);

        let _ = builder.validate_sql_parameter("hello");
        flush_for_testing();

        let after = snapshot()
            .histograms
            .get("security.queries.validate_ms")
            .map_or(0, |h| h.count);
        assert!(after > before);
    }

    #[test]
    fn test_metrics_threats_detected_counter() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let builder = QueryBuilder::new();
        flush_for_testing();
        let before = snapshot()
            .counters
            .get("security.queries.threats_detected")
            .map_or(0, |c| c.value);

        assert!(builder.is_sql_injection_present("' OR 1=1 --"));
        flush_for_testing();

        let after = snapshot()
            .counters
            .get("security.queries.threats_detected")
            .map_or(0, |c| c.value);
        assert!(after > before);
    }

    #[test]
    fn test_silent_mode_emits_no_metrics() {
        // Structural test: `silent()` returns a builder with emit_events=false,
        // and every metric call site in this module is gated by `if self.emit_events`.
        // A behavioral delta-assertion would race with concurrent tests across the
        // workspace that hit these same global metric names via shortcuts/facade.
        let builder = QueryBuilder::silent();
        assert!(!builder.emit_events);

        // Sanity: invoking through the silent builder still works functionally.
        assert!(builder.is_sql_injection_present("' OR 1=1 --"));
        assert!(builder.validate_sql_parameter("hello").is_ok());
    }
}

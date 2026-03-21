//! GraphQL query validation
//!
//! Validation functions for GraphQL queries.
//! Full implementation in Phase 4.

use super::{analysis, schema::GraphqlSchema};
use crate::primitives::security::queries::types::{GraphqlConfig, QueryThreat};
use crate::primitives::types::Problem;

/// Validate a GraphQL query against a schema and security config
///
/// # Arguments
///
/// * `query` - The GraphQL query to validate
/// * `schema` - The GraphQL schema to validate against
/// * `config` - Security configuration
///
/// # Returns
///
/// `Ok(())` if the query is valid and safe, `Err(Problem)` otherwise
pub fn validate_graphql_query(
    query: &str,
    _schema: &GraphqlSchema,
    config: &GraphqlConfig,
) -> Result<(), Problem> {
    if query.is_empty() {
        return Err(Problem::validation("GraphQL query cannot be empty"));
    }

    // Analyze the query
    let analysis = analysis::analyze_graphql_query(query);

    // Check introspection
    if analysis.has_introspection && !config.allow_introspection {
        return Err(Problem::validation(
            "GraphQL introspection queries are not allowed",
        ));
    }

    // Check depth
    if analysis.depth > config.max_depth {
        return Err(Problem::validation(format!(
            "GraphQL query depth {} exceeds maximum of {}",
            analysis.depth, config.max_depth
        )));
    }

    // Check aliases
    if analysis.alias_count > config.max_aliases {
        return Err(Problem::validation(format!(
            "GraphQL query has {} aliases, exceeding maximum of {}",
            analysis.alias_count, config.max_aliases
        )));
    }

    // Check field count
    if analysis.field_count > config.max_fields {
        return Err(Problem::validation(format!(
            "GraphQL query has {} fields, exceeding maximum of {}",
            analysis.field_count, config.max_fields
        )));
    }

    // Check batch size
    if analysis.operation_count > config.max_batch_size {
        return Err(Problem::validation(format!(
            "GraphQL batch has {} operations, exceeding maximum of {}",
            analysis.operation_count, config.max_batch_size
        )));
    }

    // Check for specific threats
    for threat in &analysis.threats {
        match threat {
            QueryThreat::GraphqlAliasBombing => {
                return Err(Problem::validation("GraphQL alias bombing detected"));
            }
            QueryThreat::GraphqlDepthExceeded => {
                return Err(Problem::validation("GraphQL query depth exceeded"));
            }
            _ => {}
        }
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn test_schema() -> GraphqlSchema {
        GraphqlSchema::parse("type Query { user: User } type User { name: String }")
            .expect("test schema")
    }

    #[test]
    fn test_validate_simple_query() {
        let query = "{ user { name } }";
        let schema = test_schema();
        let config = GraphqlConfig::default();

        let result = validate_graphql_query(query, &schema, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_empty_query() {
        let schema = test_schema();
        let config = GraphqlConfig::default();

        let result = validate_graphql_query("", &schema, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_introspection_blocked() {
        let query = "{ __schema { types { name } } }";
        let schema = test_schema();
        let config = GraphqlConfig::default(); // introspection disabled by default

        let result = validate_graphql_query(query, &schema, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_introspection_allowed() {
        let query = "{ __schema { types { name } } }";
        let schema = test_schema();
        let config = GraphqlConfig::default().with_introspection();

        let result = validate_graphql_query(query, &schema, &config);
        assert!(result.is_ok());
    }
}

// Allow arithmetic - depth/field counting is bounded by query length
#![allow(clippy::arithmetic_side_effects)]

//! GraphQL query analysis
//!
//! Analysis functions for understanding GraphQL query structure.
//! Full implementation in Phase 4.

use super::patterns;
use crate::primitives::security::queries::types::{GraphqlAnalysis, QueryThreat};

/// Analyze a GraphQL query for security concerns
///
/// This provides a basic analysis without full parsing.
/// Full parsing requires the graphql-parser crate.
#[must_use]
pub fn analyze_graphql_query(query: &str) -> GraphqlAnalysis {
    let mut analysis = GraphqlAnalysis::default();

    if query.is_empty() {
        return analysis;
    }

    // Check for introspection
    analysis.has_introspection = patterns::is_introspection_present(query);
    if analysis.has_introspection {
        analysis.threats.push(QueryThreat::GraphqlIntrospection);
    }

    // Count aliases (approximate)
    analysis.alias_count = patterns::count_aliases(query);
    if analysis.alias_count > 10 {
        analysis.threats.push(QueryThreat::GraphqlAliasBombing);
    }

    // Estimate depth by counting nested braces
    let mut max_depth: usize = 0;
    let mut current_depth: usize = 0;
    for c in query.chars() {
        match c {
            '{' => {
                current_depth += 1;
                if current_depth > max_depth {
                    max_depth = current_depth;
                }
            }
            '}' => {
                current_depth = current_depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    analysis.depth = max_depth;

    // Count fields (approximate - count word followed by { or ,)
    analysis.field_count = query.matches('{').count().saturating_sub(1);

    // Count operations (queries, mutations, subscriptions)
    let query_lower = query.to_lowercase();
    analysis.operation_count = query_lower.matches("query").count()
        + query_lower.matches("mutation").count()
        + query_lower.matches("subscription").count();
    if analysis.operation_count == 0 {
        analysis.operation_count = 1; // Anonymous query
    }

    analysis
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_empty() {
        let analysis = analyze_graphql_query("");
        assert!(!analysis.is_threat_detected());
        assert_eq!(analysis.depth, 0);
    }

    #[test]
    fn test_analyze_simple_query() {
        let query = "{ user { name } }";
        let analysis = analyze_graphql_query(query);
        assert!(!analysis.has_introspection);
        assert_eq!(analysis.depth, 2);
    }

    #[test]
    fn test_analyze_introspection() {
        let query = "{ __schema { types { name } } }";
        let analysis = analyze_graphql_query(query);
        assert!(analysis.has_introspection);
        assert!(
            analysis
                .threats
                .contains(&QueryThreat::GraphqlIntrospection)
        );
    }
}

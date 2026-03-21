//! GraphQL injection detection
//!
//! Detection functions for identifying GraphQL abuse patterns.
//!
//! # Attack Vectors
//!
//! | Vector | Description | Risk |
//! |--------|-------------|------|
//! | Introspection | Schema discovery | Information disclosure |
//! | Alias bombing | DoS via aliased fields | Resource exhaustion |
//! | Query batching | Multiple operations | Resource exhaustion |
//! | Field duplication | Repeated field resolution | Resource exhaustion |
//! | Deep nesting | Excessive query depth | Resource exhaustion |

use super::patterns;
use crate::primitives::security::queries::types::QueryThreat;

/// Default threshold for alias bombing detection
const DEFAULT_ALIAS_THRESHOLD: usize = 10;

/// Default threshold for field duplication detection
const DEFAULT_FIELD_THRESHOLD: usize = 100;

/// Default threshold for query depth detection
const DEFAULT_DEPTH_THRESHOLD: usize = 10;

/// Check if query contains any GraphQL abuse patterns
///
/// This is a comprehensive check that looks for multiple attack vectors.
///
/// # Arguments
///
/// * `query` - The GraphQL query to check
///
/// # Returns
///
/// `true` if any abuse pattern is detected
#[must_use]
pub fn is_graphql_injection_present(query: &str) -> bool {
    if query.is_empty() {
        return false;
    }

    // Check for introspection
    if patterns::is_introspection_present(query) {
        return true;
    }

    // Check for alias bombing
    if patterns::count_aliases(query) > DEFAULT_ALIAS_THRESHOLD {
        return true;
    }

    // Check for deep nesting
    if estimate_depth(query) > DEFAULT_DEPTH_THRESHOLD {
        return true;
    }

    false
}

/// Detect all GraphQL threats in query
///
/// Returns a list of all detected threat types for logging/analysis.
///
/// # Arguments
///
/// * `query` - The GraphQL query to analyze
///
/// # Returns
///
/// Vector of all detected threat types
#[must_use]
pub fn detect_graphql_threats(query: &str) -> Vec<QueryThreat> {
    let mut threats = Vec::new();

    if query.is_empty() {
        return threats;
    }

    // Introspection detection
    if patterns::is_introspection_present(query) {
        threats.push(QueryThreat::GraphqlIntrospection);
    }

    // Alias bombing detection
    let alias_count = patterns::count_aliases(query);
    if alias_count > DEFAULT_ALIAS_THRESHOLD {
        threats.push(QueryThreat::GraphqlAliasBombing);
    }

    // Query batching detection (multiple operations)
    if count_operations(query) > 1 {
        threats.push(QueryThreat::GraphqlBatching);
    }

    // Field duplication detection
    if estimate_field_count(query) > DEFAULT_FIELD_THRESHOLD {
        threats.push(QueryThreat::GraphqlFieldDuplication);
    }

    // Depth exceeded detection
    if estimate_depth(query) > DEFAULT_DEPTH_THRESHOLD {
        threats.push(QueryThreat::GraphqlDepthExceeded);
    }

    threats
}

/// Estimate query depth by counting nested braces
#[must_use]
fn estimate_depth(query: &str) -> usize {
    let mut max_depth: usize = 0;
    let mut current_depth: usize = 0;

    for c in query.chars() {
        match c {
            '{' => {
                current_depth = current_depth.saturating_add(1);
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

    max_depth
}

/// Estimate field count by counting selection occurrences
#[must_use]
fn estimate_field_count(query: &str) -> usize {
    // Simple heuristic: count word-like tokens before : or {
    let mut count: usize = 0;
    let mut in_word = false;

    for c in query.chars() {
        if c.is_alphanumeric() || c == '_' {
            if !in_word {
                count = count.saturating_add(1);
                in_word = true;
            }
        } else {
            in_word = false;
        }
    }

    count
}

/// Count operations in query
#[must_use]
fn count_operations(query: &str) -> usize {
    let lower = query.to_lowercase();
    let query_count = lower.matches("query").count();
    let mutation_count = lower.matches("mutation").count();
    let subscription_count = lower.matches("subscription").count();

    let named = query_count
        .saturating_add(mutation_count)
        .saturating_add(subscription_count);

    // At least 1 for anonymous queries
    if named == 0 && query.contains('{') {
        1
    } else {
        named
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_graphql_injection_present_introspection() {
        assert!(is_graphql_injection_present(
            "{ __schema { types { name } } }"
        ));
        assert!(is_graphql_injection_present(
            "query { __type(name: \"User\") { name } }"
        ));
    }

    #[test]
    fn test_is_graphql_injection_present_safe() {
        assert!(!is_graphql_injection_present("{ user { name } }"));
        assert!(!is_graphql_injection_present(
            "query GetUser { user { name email } }"
        ));
        assert!(!is_graphql_injection_present(""));
    }

    #[test]
    fn test_detect_graphql_threats_comprehensive() {
        // Introspection
        let threats = detect_graphql_threats("{ __schema { types { name } } }");
        assert!(threats.contains(&QueryThreat::GraphqlIntrospection));

        // Alias bombing (would need many aliases to trigger)
        let many_aliases = "{ a1: user { name } a2: user { name } a3: user { name } a4: user { name } a5: user { name } a6: user { name } a7: user { name } a8: user { name } a9: user { name } a10: user { name } a11: user { name } }";
        let threats = detect_graphql_threats(many_aliases);
        assert!(threats.contains(&QueryThreat::GraphqlAliasBombing));
    }

    #[test]
    fn test_detect_graphql_threats_empty() {
        let threats = detect_graphql_threats("");
        assert!(threats.is_empty());
    }

    #[test]
    fn test_estimate_depth() {
        assert_eq!(estimate_depth("{ user { name } }"), 2);
        assert_eq!(estimate_depth("{ user { profile { avatar } } }"), 3);
        assert_eq!(estimate_depth("{ a }"), 1);
        assert_eq!(estimate_depth(""), 0);
    }

    #[test]
    fn test_count_operations() {
        assert_eq!(count_operations("query GetUser { user { name } }"), 1);
        assert_eq!(count_operations("mutation CreateUser { create { id } }"), 1);
        assert_eq!(count_operations("{ user { name } }"), 1); // Anonymous
    }

    #[test]
    fn test_graphql_attack_patterns() {
        // Deep nesting attack
        let deep = "{ a { b { c { d { e { f { g { h { i { j { k } } } } } } } } } } }";
        assert!(estimate_depth(deep) > DEFAULT_DEPTH_THRESHOLD);

        // Introspection for schema discovery
        assert!(is_graphql_injection_present(
            "{ __schema { queryType { name } mutationType { name } } }"
        ));
    }
}

// SAFETY: All expect() calls in this module are on regex patterns that are
// guaranteed to compile (simple fallback patterns like r"^$").
#![allow(clippy::expect_used)]

//! GraphQL detection patterns
//!
//! Patterns for detecting GraphQL abuse.
//! Full implementation in Phase 4.

use once_cell::sync::Lazy;
use regex::Regex;

/// GraphQL introspection field names
pub const GRAPHQL_INTROSPECTION_FIELDS: &[&str] = &[
    "__schema",
    "__type",
    "__typename",
    "__directive",
    "__field",
    "__inputValue",
    "__enumValue",
];

/// Pattern for detecting introspection queries
pub static INTROSPECTION_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)__schema|__type\s*\(|__typename")
        .unwrap_or_else(|_| Regex::new(r"^$").expect("fallback regex should compile"))
});

/// Pattern for detecting aliases
pub static ALIAS_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\w+\s*:\s*\w+")
        .unwrap_or_else(|_| Regex::new(r"^$").expect("fallback regex should compile"))
});

/// Check if query contains introspection
#[must_use]
pub fn is_introspection_present(query: &str) -> bool {
    INTROSPECTION_PATTERN.is_match(query)
}

/// Count aliases in query (approximate)
#[must_use]
pub fn count_aliases(query: &str) -> usize {
    ALIAS_PATTERN.find_iter(query).count()
}

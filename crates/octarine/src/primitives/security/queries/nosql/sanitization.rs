//! NoSQL sanitization functions
//!
//! Functions for escaping and sanitizing NoSQL values to prevent injection.
//!
//! # Overview
//!
//! Unlike SQL, NoSQL databases (particularly MongoDB) don't have a standard
//! escape mechanism. Instead, we provide functions to:
//!
//! - Strip dangerous operators from user input
//! - Validate and escape field names
//! - Remove prototype pollution patterns
//!
//! # Warning
//!
//! The best protection against NoSQL injection is proper input validation
//! and using the driver's built-in parameterization. These functions are
//! a defense-in-depth measure.
//!
//! # Example
//!
//! ```ignore
//! use octarine::security::queries::{
//!     strip_nosql_operators,
//!     escape_nosql_field,
//! };
//!
//! // Strip operators from user input
//! let safe = strip_nosql_operators("$gt");
//! assert_eq!(safe, "gt");
//!
//! // Escape field names
//! let field = escape_nosql_field("$set");
//! assert_eq!(field, "_set");
//! ```

use super::patterns::{NOSQL_OPERATORS, PROTOTYPE_KEYS};

// ============================================================================
// Field Name Sanitization
// ============================================================================

/// Escape a field name to prevent operator injection
///
/// Replaces leading `$` with `_` to prevent the field from being
/// interpreted as a MongoDB operator.
///
/// # Example
///
/// ```ignore
/// use octarine::security::queries::escape_nosql_field;
///
/// assert_eq!(escape_nosql_field("name"), "name");
/// assert_eq!(escape_nosql_field("$set"), "_set");
/// assert_eq!(escape_nosql_field("$gt"), "_gt");
/// ```
#[must_use]
pub fn escape_nosql_field(name: &str) -> String {
    if let Some(stripped) = name.strip_prefix('$') {
        format!("_{stripped}")
    } else if PROTOTYPE_KEYS.contains(&name) {
        format!("_{name}")
    } else {
        name.to_string()
    }
}

/// Escape a field name, also handling dots (nested paths)
///
/// MongoDB uses dots for nested field access. This function escapes
/// each path segment individually.
///
/// # Example
///
/// ```ignore
/// use octarine::security::queries::escape_nosql_path;
///
/// assert_eq!(escape_nosql_path("user.name"), "user.name");
/// assert_eq!(escape_nosql_path("$set.value"), "_set.value");
/// assert_eq!(escape_nosql_path("a.$gt.b"), "a._gt.b");
/// ```
#[must_use]
pub fn escape_nosql_path(path: &str) -> String {
    path.split('.')
        .map(escape_nosql_field)
        .collect::<Vec<_>>()
        .join(".")
}

// ============================================================================
// Value Sanitization
// ============================================================================

/// Strip MongoDB operators from a string value
///
/// Removes the leading `$` from any MongoDB operator patterns found
/// in the input string. This is useful for sanitizing user input that
/// will be used as a string value.
///
/// # Example
///
/// ```ignore
/// use octarine::security::queries::strip_nosql_operators;
///
/// assert_eq!(strip_nosql_operators("hello"), "hello");
/// assert_eq!(strip_nosql_operators("$gt"), "gt");
/// assert_eq!(strip_nosql_operators("$where"), "where");
/// assert_eq!(strip_nosql_operators("$100"), "$100"); // Not an operator
/// ```
#[must_use]
pub fn strip_nosql_operators(input: &str) -> String {
    let mut result = input.to_string();

    // Check if input starts with a known operator
    for op in NOSQL_OPERATORS {
        if input.eq_ignore_ascii_case(op) {
            // Remove the leading $
            return input[1..].to_string();
        }
    }

    // Also handle operators appearing in JSON-like strings
    for op in NOSQL_OPERATORS {
        // Replace "$operator" with "operator" (case-insensitive)
        let pattern = format!(r#""{op}""#);
        let replacement = format!(r#""{}""#, &op[1..]);
        result = result.replace(&pattern, &replacement);

        // Also handle single quotes
        let pattern_sq = format!("'{op}'");
        let replacement_sq = format!("'{}'", &op[1..]);
        result = result.replace(&pattern_sq, &replacement_sq);
    }

    result
}

/// Strip prototype pollution patterns from input
///
/// Removes or escapes patterns that could be used for prototype pollution
/// attacks in JavaScript/Node.js environments.
///
/// # Example
///
/// ```ignore
/// // This is an internal function; use sanitize_nosql_value() from the public API
/// assert_eq!(strip_prototype_patterns("hello"), "hello");
/// assert_eq!(strip_prototype_patterns("__proto__"), "_proto_");
/// assert_eq!(strip_prototype_patterns("constructor"), "_constructor");
/// assert_eq!(strip_prototype_patterns("prototype"), "_prototype");
/// ```
#[must_use]
pub fn strip_prototype_patterns(input: &str) -> String {
    let mut result = input.to_string();

    // Handle __proto__ specifically - remove one underscore pair
    if result == "__proto__" {
        return "_proto_".to_string();
    }

    // Prefix other dangerous patterns
    for key in &["constructor", "prototype"] {
        if result.eq_ignore_ascii_case(key) {
            return format!("_{result}");
        }
    }

    // Also handle these patterns within larger strings
    result = result.replace("__proto__", "_proto_");
    result = result.replace("constructor.prototype", "_constructor._prototype");

    result
}

/// Sanitize a value for safe use in NoSQL queries
///
/// Combines operator stripping and prototype pattern removal.
/// This is a convenience function for comprehensive sanitization.
///
/// # Example
///
/// ```ignore
/// use octarine::security::queries::sanitize_nosql_value;
///
/// assert_eq!(sanitize_nosql_value("hello"), "hello");
/// assert_eq!(sanitize_nosql_value("$gt"), "gt");
/// assert_eq!(sanitize_nosql_value("__proto__"), "_proto_");
/// ```
#[must_use]
pub fn sanitize_nosql_value(input: &str) -> String {
    let stripped = strip_nosql_operators(input);
    strip_prototype_patterns(&stripped)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Field Name Tests
    // ========================================================================

    #[test]
    fn test_escape_nosql_field_safe() {
        assert_eq!(escape_nosql_field("name"), "name");
        assert_eq!(escape_nosql_field("user_id"), "user_id");
        assert_eq!(escape_nosql_field("createdAt"), "createdAt");
    }

    #[test]
    fn test_escape_nosql_field_operators() {
        assert_eq!(escape_nosql_field("$set"), "_set");
        assert_eq!(escape_nosql_field("$gt"), "_gt");
        assert_eq!(escape_nosql_field("$where"), "_where");
        assert_eq!(escape_nosql_field("$or"), "_or");
    }

    #[test]
    fn test_escape_nosql_field_prototype() {
        assert_eq!(escape_nosql_field("__proto__"), "___proto__");
        assert_eq!(escape_nosql_field("constructor"), "_constructor");
        assert_eq!(escape_nosql_field("prototype"), "_prototype");
    }

    #[test]
    fn test_escape_nosql_path() {
        assert_eq!(escape_nosql_path("user.name"), "user.name");
        assert_eq!(escape_nosql_path("$set.value"), "_set.value");
        assert_eq!(escape_nosql_path("a.$gt.b"), "a._gt.b");
        assert_eq!(escape_nosql_path("__proto__.x"), "___proto__.x");
    }

    // ========================================================================
    // Value Stripping Tests
    // ========================================================================

    #[test]
    fn test_strip_nosql_operators_bare() {
        assert_eq!(strip_nosql_operators("$gt"), "gt");
        assert_eq!(strip_nosql_operators("$where"), "where");
        assert_eq!(strip_nosql_operators("$or"), "or");
        assert_eq!(strip_nosql_operators("$elemMatch"), "elemMatch");
    }

    #[test]
    fn test_strip_nosql_operators_safe() {
        assert_eq!(strip_nosql_operators("hello"), "hello");
        assert_eq!(strip_nosql_operators("$100"), "$100"); // Not an operator
        assert_eq!(
            strip_nosql_operators("user@example.com"),
            "user@example.com"
        );
    }

    #[test]
    fn test_strip_nosql_operators_in_json() {
        let input = r#"{"$gt": 5}"#;
        let result = strip_nosql_operators(input);
        assert_eq!(result, r#"{"gt": 5}"#);
    }

    #[test]
    fn test_strip_prototype_patterns() {
        assert_eq!(strip_prototype_patterns("__proto__"), "_proto_");
        assert_eq!(strip_prototype_patterns("constructor"), "_constructor");
        assert_eq!(strip_prototype_patterns("prototype"), "_prototype");
        assert_eq!(strip_prototype_patterns("hello"), "hello");
    }

    #[test]
    fn test_strip_prototype_in_string() {
        let input = "set __proto__ value";
        let result = strip_prototype_patterns(input);
        assert_eq!(result, "set _proto_ value");
    }

    // ========================================================================
    // Combined Sanitization Tests
    // ========================================================================

    #[test]
    fn test_sanitize_nosql_value() {
        assert_eq!(sanitize_nosql_value("hello"), "hello");
        assert_eq!(sanitize_nosql_value("$gt"), "gt");
        assert_eq!(sanitize_nosql_value("__proto__"), "_proto_");
    }

    #[test]
    fn test_sanitize_complex_input() {
        // Both operator and prototype pollution
        let input = "$where with __proto__";
        let result = sanitize_nosql_value(input);
        assert!(result.contains("_proto_"));
        // Note: $where in the middle of a string won't be stripped
        // because it's not a bare operator match
    }
}

// SAFETY: All expect() calls in this module are on regex patterns that are
// guaranteed to compile (simple fallback patterns like r"^$").
#![allow(clippy::expect_used)]

//! NoSQL injection detection patterns
//!
//! Compiled regex patterns for detecting NoSQL injection attacks.
//!
//! # Attack Patterns
//!
//! | Pattern | Description | Example |
//! |---------|-------------|---------|
//! | Operator injection | MongoDB operators in input | `{ "$gt": "" }` |
//! | JavaScript injection | Code execution via $where | `$where: 'this.a > 1'` |
//! | Prototype pollution | Object manipulation | `__proto__` |
//! | Array injection | Array operator abuse | `$elemMatch` |

use once_cell::sync::Lazy;
use regex::Regex;

// ============================================================================
// Constants
// ============================================================================

/// MongoDB comparison operators
pub const NOSQL_COMPARISON_OPERATORS: &[&str] =
    &["$gt", "$gte", "$lt", "$lte", "$ne", "$eq", "$in", "$nin"];

/// MongoDB logical operators
pub const NOSQL_LOGICAL_OPERATORS: &[&str] = &["$or", "$and", "$not", "$nor"];

/// MongoDB query operators
pub const NOSQL_QUERY_OPERATORS: &[&str] = &["$regex", "$exists", "$type", "$mod", "$text"];

/// MongoDB array operators
pub const NOSQL_ARRAY_OPERATORS: &[&str] = &["$elemMatch", "$size", "$all"];

/// Dangerous MongoDB operators (execution context)
pub const NOSQL_DANGEROUS_OPERATORS: &[&str] = &[
    "$where",
    "$function",
    "$accumulator",
    "$expr",
    "$jsonSchema",
];

/// All MongoDB operators combined
pub const NOSQL_OPERATORS: &[&str] = &[
    "$where",
    "$gt",
    "$gte",
    "$lt",
    "$lte",
    "$ne",
    "$eq",
    "$in",
    "$nin",
    "$or",
    "$and",
    "$not",
    "$nor",
    "$regex",
    "$exists",
    "$type",
    "$mod",
    "$text",
    "$elemMatch",
    "$size",
    "$all",
    "$function",
    "$accumulator",
    "$expr",
    "$jsonSchema",
];

/// Prototype pollution keys
pub const PROTOTYPE_KEYS: &[&str] = &["__proto__", "constructor", "prototype"];

/// JavaScript keywords that indicate $where injection
pub const JS_KEYWORDS: &[&str] = &[
    "function",
    "this.",
    "return",
    "eval(",
    "Function(",
    "setTimeout",
    "setInterval",
];

// ============================================================================
// Compiled Patterns
// ============================================================================

/// Helper to create fallback regex
fn fallback_regex() -> Regex {
    Regex::new(r"^$").expect("fallback regex should compile")
}

/// Pattern for detecting MongoDB operators in JSON-like context
pub static NOSQL_OPERATOR_PATTERN: Lazy<Regex> = Lazy::new(|| {
    // Matches "$operator" patterns in JSON context
    Regex::new(r#"(?i)["']\s*\$\w+"#).unwrap_or_else(|_| fallback_regex())
});

/// Pattern for detecting bare $ operators (without quotes)
pub static NOSQL_BARE_OPERATOR_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\$(?:where|gt|gte|lt|lte|ne|eq|in|nin|or|and|not|nor|regex|exists|type|mod|text|elemMatch|size|all|function|accumulator|expr)\b")
        .unwrap_or_else(|_| fallback_regex())
});

/// Pattern for detecting prototype pollution
pub static PROTOTYPE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(__proto__|constructor\.prototype|prototype\s*\[)")
        .unwrap_or_else(|_| fallback_regex())
});

/// Pattern for detecting JavaScript injection in $where
pub static JS_INJECTION_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(function\s*\(|this\.\w+|eval\s*\(|new\s+Function)")
        .unwrap_or_else(|_| fallback_regex())
});

/// Pattern for detecting array operator abuse
pub static ARRAY_INJECTION_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\[\s*["']\s*\$\w+"#).unwrap_or_else(|_| fallback_regex()));

// ============================================================================
// Detection Functions
// ============================================================================

/// Check if input contains NoSQL operators
#[must_use]
pub fn is_nosql_operators_present(input: &str) -> bool {
    NOSQL_OPERATOR_PATTERN.is_match(input) || NOSQL_BARE_OPERATOR_PATTERN.is_match(input)
}

/// Check if input contains prototype pollution patterns
#[must_use]
pub fn is_prototype_pollution_present(input: &str) -> bool {
    PROTOTYPE_PATTERN.is_match(input)
}

/// Check if input contains JavaScript injection patterns
#[must_use]
pub fn is_js_injection_present(input: &str) -> bool {
    JS_INJECTION_PATTERN.is_match(input)
}

/// Check if input contains array operator abuse patterns
#[must_use]
pub fn is_array_injection_present(input: &str) -> bool {
    ARRAY_INJECTION_PATTERN.is_match(input)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nosql_operator_detection() {
        // JSON-style operators
        assert!(is_nosql_operators_present(r#"{ "$gt": "" }"#));
        assert!(is_nosql_operators_present(r#"{ "$ne": null }"#));
        assert!(is_nosql_operators_present(r#"{"$where": "1"}"#));

        // Bare operators
        assert!(is_nosql_operators_present("$gt"));
        assert!(is_nosql_operators_present("$where"));

        // Safe inputs
        assert!(!is_nosql_operators_present("hello"));
        assert!(!is_nosql_operators_present("user@example.com"));
        assert!(!is_nosql_operators_present("$100 dollars")); // Not an operator
    }

    #[test]
    fn test_prototype_pollution_detection() {
        assert!(is_prototype_pollution_present("__proto__"));
        assert!(is_prototype_pollution_present("constructor.prototype"));
        assert!(is_prototype_pollution_present("prototype["));

        assert!(!is_prototype_pollution_present("hello"));
        assert!(!is_prototype_pollution_present("construction")); // Not a match
    }

    #[test]
    fn test_js_injection_detection() {
        assert!(is_js_injection_present("function() { return true; }"));
        assert!(is_js_injection_present("this.password"));
        assert!(is_js_injection_present("eval('code')"));
        assert!(is_js_injection_present("new Function('return 1')"));

        assert!(!is_js_injection_present("hello"));
        assert!(!is_js_injection_present("functional"));
    }

    #[test]
    fn test_array_injection_detection() {
        assert!(is_array_injection_present(r#"[ "$gt" ]"#));
        assert!(is_array_injection_present(r#"['$or']"#));

        assert!(!is_array_injection_present("[1, 2, 3]"));
        assert!(!is_array_injection_present(r#"["hello"]"#));
    }
}

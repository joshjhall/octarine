//! NoSQL injection detection
//!
//! Detection functions for identifying NoSQL injection patterns.
//!
//! # Attack Vectors
//!
//! | Vector | Description | Example |
//! |--------|-------------|---------|
//! | Operator injection | MongoDB operators | `{ "$gt": "" }` |
//! | JavaScript injection | $where code execution | `function() {}` |
//! | Prototype pollution | Object manipulation | `__proto__` |
//! | Array injection | Array operator abuse | `[ "$gt" ]` |

use super::patterns;
use crate::primitives::security::queries::types::QueryThreat;

/// Check if input contains any NoSQL injection patterns
///
/// This is a comprehensive check that looks for multiple attack vectors.
///
/// # Arguments
///
/// * `input` - The string to check for injection patterns
///
/// # Returns
///
/// `true` if any injection pattern is detected
#[must_use]
pub fn is_nosql_injection_present(input: &str) -> bool {
    if input.is_empty() {
        return false;
    }

    patterns::is_nosql_operators_present(input)
        || patterns::is_prototype_pollution_present(input)
        || patterns::is_js_injection_present(input)
        || patterns::is_array_injection_present(input)
}

/// Detect all NoSQL injection threats in input
///
/// Returns a list of all detected threat types for logging/analysis.
///
/// # Arguments
///
/// * `input` - The string to analyze for injection patterns
///
/// # Returns
///
/// Vector of all detected threat types
#[must_use]
pub fn detect_nosql_threats(input: &str) -> Vec<QueryThreat> {
    let mut threats = Vec::new();

    if input.is_empty() {
        return threats;
    }

    if patterns::is_nosql_operators_present(input) {
        threats.push(QueryThreat::NoSqlOperator);
    }

    if patterns::is_js_injection_present(input) {
        threats.push(QueryThreat::NoSqlJsInjection);
    }

    if patterns::is_prototype_pollution_present(input) {
        threats.push(QueryThreat::NoSqlPrototypePollution);
    }

    if patterns::is_array_injection_present(input) {
        threats.push(QueryThreat::NoSqlArrayInjection);
    }

    threats
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_nosql_injection_present_operators() {
        assert!(is_nosql_injection_present(r#"{ "$gt": "" }"#));
        assert!(is_nosql_injection_present(r#"{ "$ne": null }"#));
        assert!(is_nosql_injection_present("$where"));
    }

    #[test]
    fn test_is_nosql_injection_present_js() {
        assert!(is_nosql_injection_present("function() { return true; }"));
        assert!(is_nosql_injection_present("this.password == 'secret'"));
    }

    #[test]
    fn test_is_nosql_injection_present_prototype() {
        assert!(is_nosql_injection_present("__proto__"));
        assert!(is_nosql_injection_present("constructor.prototype"));
    }

    #[test]
    fn test_is_nosql_injection_present_safe_inputs() {
        assert!(!is_nosql_injection_present("hello"));
        assert!(!is_nosql_injection_present("user@example.com"));
        assert!(!is_nosql_injection_present(""));
        assert!(!is_nosql_injection_present("John Doe"));
    }

    #[test]
    fn test_detect_nosql_threats_comprehensive() {
        // Operator injection
        let threats = detect_nosql_threats(r#"{ "$gt": "" }"#);
        assert!(threats.contains(&QueryThreat::NoSqlOperator));

        // JavaScript injection
        let threats = detect_nosql_threats("function() {}");
        assert!(threats.contains(&QueryThreat::NoSqlJsInjection));

        // Prototype pollution
        let threats = detect_nosql_threats("__proto__");
        assert!(threats.contains(&QueryThreat::NoSqlPrototypePollution));

        // Array injection
        let threats = detect_nosql_threats(r#"[ "$gt" ]"#);
        assert!(threats.contains(&QueryThreat::NoSqlArrayInjection));

        // Multiple threats
        let threats = detect_nosql_threats(r#"{ "$gt": "", "__proto__": {} }"#);
        assert!(threats.len() >= 2);
    }

    #[test]
    fn test_detect_nosql_threats_empty() {
        let threats = detect_nosql_threats("");
        assert!(threats.is_empty());
    }

    #[test]
    fn test_common_nosql_payloads() {
        // MongoDB operator injection
        assert!(is_nosql_injection_present(r#"{"username": {"$gt": ""}}"#));
        assert!(is_nosql_injection_present(r#"{"password": {"$ne": ""}}"#));

        // $where injection with JavaScript
        assert!(is_nosql_injection_present("' || this.password == 'admin"));

        // Prototype pollution
        assert!(is_nosql_injection_present(
            r#"{"__proto__": {"admin": true}}"#
        ));
    }
}

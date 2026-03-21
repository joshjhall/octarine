//! JSON security validation
//!
//! Validates JSON input against security policies.

use crate::primitives::types::{Problem, Result};

use super::super::types::JsonPolicy;
use super::detection::{exceeds_depth, exceeds_size};

/// Validate that JSON input is safe according to the given policy
///
/// Returns `Ok(())` if the input passes all security checks,
/// or an error describing the threat.
pub(crate) fn validate_json_safe(input: &str, policy: &JsonPolicy) -> Result<()> {
    // Check size limit
    if exceeds_size(input, policy.max_size) {
        return Err(Problem::Validation(format!(
            "JSON input exceeds maximum size: {} > {} bytes",
            input.len(),
            policy.max_size
        )));
    }

    // Check depth limit
    if exceeds_depth(input, policy.max_depth) {
        return Err(Problem::Validation(format!(
            "JSON input exceeds maximum nesting depth: limit is {}",
            policy.max_depth
        )));
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validate_clean_json() {
        let policy = JsonPolicy::default();
        let result = validate_json_safe(r#"{"key": "value"}"#, &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_rejects_oversized() {
        let policy = JsonPolicy {
            max_size: 10,
            max_depth: 64,
        };
        let large = r#"{"key": "this is way too long"}"#;

        let result = validate_json_safe(large, &policy);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should fail")
                .to_string()
                .contains("exceeds maximum size")
        );
    }

    #[test]
    fn test_validate_rejects_deep() {
        let policy = JsonPolicy {
            max_size: 10000,
            max_depth: 2,
        };
        let deep = r#"{"a": {"b": {"c": "too deep"}}}"#;

        let result = validate_json_safe(deep, &policy);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should fail")
                .to_string()
                .contains("exceeds maximum nesting depth")
        );
    }

    #[test]
    fn test_validate_strict_policy() {
        let policy = JsonPolicy::strict();

        // Normal JSON should pass
        let normal = r#"{"key": "value"}"#;
        assert!(validate_json_safe(normal, &policy).is_ok());
    }

    #[test]
    fn test_validate_depth_bomb() {
        let policy = JsonPolicy::default(); // max_depth: 64

        // Create a deeply nested structure (100 levels)
        let mut bomb = String::new();
        for _ in 0..100 {
            bomb.push_str(r#"{"a":"#);
        }
        bomb.push('1');
        for _ in 0..100 {
            bomb.push('}');
        }

        let result = validate_json_safe(&bomb, &policy);
        assert!(result.is_err());
    }
}

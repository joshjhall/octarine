//! JSON threat detection
//!
//! Detection for depth bombs and size violations.

use super::super::types::{FormatThreat, JsonPolicy};

/// Check if JSON content exceeds size limit
#[must_use]
pub(crate) fn exceeds_size(input: &str, max_size: usize) -> bool {
    input.len() > max_size
}

/// Check if JSON content exceeds nesting depth limit
///
/// This is a heuristic check that counts brackets and braces.
/// For precise depth checking, parse the JSON and walk the tree.
#[must_use]
pub(crate) fn exceeds_depth(input: &str, max_depth: usize) -> bool {
    let mut current_depth: usize = 0;
    let mut max_seen: usize = 0;

    for c in input.chars() {
        match c {
            '{' | '[' => {
                current_depth = current_depth.saturating_add(1);
                if current_depth > max_seen {
                    max_seen = current_depth;
                }
                if max_seen > max_depth {
                    return true;
                }
            }
            '}' | ']' => {
                current_depth = current_depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    false
}

/// Detect all JSON threats according to policy
#[must_use]
pub(crate) fn detect_json_threats(input: &str, policy: &JsonPolicy) -> Vec<FormatThreat> {
    let mut threats = Vec::new();

    if exceeds_size(input, policy.max_size) {
        threats.push(FormatThreat::JsonSizeExceeded);
    }

    if exceeds_depth(input, policy.max_depth) {
        threats.push(FormatThreat::JsonDepthExceeded);
    }

    threats
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_exceeds_size() {
        assert!(exceeds_size("hello world", 5));
        assert!(!exceeds_size("hello", 10));
        assert!(!exceeds_size("hello", 5));
    }

    #[test]
    fn test_exceeds_depth_simple() {
        // Depth 1
        assert!(!exceeds_depth("{}", 1));
        assert!(!exceeds_depth("[]", 1));

        // Depth 2
        assert!(!exceeds_depth(r#"{"a": {}}"#, 2));
        assert!(exceeds_depth(r#"{"a": {}}"#, 1));

        // Depth 3
        assert!(!exceeds_depth(r#"{"a": {"b": {}}}"#, 3));
        assert!(exceeds_depth(r#"{"a": {"b": {}}}"#, 2));
    }

    #[test]
    fn test_exceeds_depth_arrays() {
        assert!(!exceeds_depth("[[[]]]", 3));
        assert!(exceeds_depth("[[[]]]", 2));
    }

    #[test]
    fn test_exceeds_depth_mixed() {
        assert!(!exceeds_depth(r#"[{"a": [1, 2]}]"#, 3));
        assert!(exceeds_depth(r#"[{"a": [1, 2]}]"#, 2));
    }

    #[test]
    fn test_exceeds_depth_bomb() {
        // Create a deeply nested structure
        let mut bomb = String::new();
        for _ in 0..100 {
            bomb.push('{');
        }
        bomb.push_str(r#""deep": true"#);
        for _ in 0..100 {
            bomb.push('}');
        }

        assert!(exceeds_depth(&bomb, 64));
        assert!(!exceeds_depth(&bomb, 100));
    }

    #[test]
    fn test_detect_json_threats() {
        let policy = JsonPolicy {
            max_depth: 2,
            max_size: 100,
        };

        // Clean input
        let clean = r#"{"key": "value"}"#;
        assert!(detect_json_threats(clean, &policy).is_empty());

        // Depth exceeded
        let deep = r#"{"a": {"b": {"c": "deep"}}}"#;
        let threats = detect_json_threats(deep, &policy);
        assert!(threats.contains(&FormatThreat::JsonDepthExceeded));

        // Size exceeded
        let large = "a".repeat(101);
        let threats = detect_json_threats(&large, &policy);
        assert!(threats.contains(&FormatThreat::JsonSizeExceeded));
    }

    #[test]
    fn test_detect_json_threats_default_policy() {
        let policy = JsonPolicy::default();

        // Normal JSON should be fine
        let normal = r#"{"key": "value", "nested": {"inner": 123}}"#;
        assert!(detect_json_threats(normal, &policy).is_empty());
    }
}

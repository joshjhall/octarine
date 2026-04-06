//! YAML security validation
//!
//! Validates YAML input against security policies.

use crate::primitives::types::{Problem, Result};

use super::super::types::YamlPolicy;
use super::detection::{is_anchor_bomb_present, is_unsafe_tag_present};

/// Validate that YAML input is safe according to the given policy
///
/// Returns `Ok(())` if the input passes all security checks,
/// or an error describing the threat.
pub(crate) fn validate_yaml_safe(input: &str, policy: &YamlPolicy) -> Result<()> {
    // Check for unsafe tags
    if is_unsafe_tag_present(input) {
        return Err(Problem::Validation(
            "YAML contains unsafe tag (potential code execution)".into(),
        ));
    }

    // Check for anchor bomb patterns
    if is_anchor_bomb_present(input) {
        return Err(Problem::Validation(
            "YAML contains anchor/alias bomb pattern (DoS risk)".into(),
        ));
    }

    // Count aliases and check against policy
    let alias_count = count_aliases(input);
    if alias_count > policy.max_aliases {
        return Err(Problem::Validation(format!(
            "YAML contains too many alias references: {} > {} (limit)",
            alias_count, policy.max_aliases
        )));
    }

    Ok(())
}

/// Count alias references in YAML
#[allow(clippy::expect_used)]
fn count_aliases(input: &str) -> usize {
    use lazy_static::lazy_static;
    use regex::Regex;

    lazy_static! {
        static ref ALIAS_PATTERN: Regex = Regex::new(r"\*\w+").expect("valid regex");
    }

    ALIAS_PATTERN.find_iter(input).count()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validate_clean_yaml() {
        let policy = YamlPolicy::default();
        let result = validate_yaml_safe("key: value", &policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_rejects_unsafe_tag() {
        let policy = YamlPolicy::default();
        let yaml = "!!python/object/apply:os.system ['whoami']";

        let result = validate_yaml_safe(yaml, &policy);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should fail")
                .to_string()
                .contains("unsafe tag")
        );
    }

    #[test]
    fn test_validate_rejects_anchor_bomb() {
        let policy = YamlPolicy::default();
        let bomb = "&a [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a, *a, *a]";

        let result = validate_yaml_safe(bomb, &policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_alias_limit() {
        let policy = YamlPolicy {
            allowed_tags: Default::default(),
            max_aliases: 2,
        };
        let yaml = "&a 1\nx: *a\ny: *a\nz: *a"; // 3 aliases

        let result = validate_yaml_safe(yaml, &policy);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should fail")
                .to_string()
                .contains("too many alias")
        );
    }

    #[test]
    fn test_validate_permissive_policy() {
        let policy = YamlPolicy::permissive();

        // Normal YAML with aliases should pass
        let yaml = r"
defaults: &defaults
  timeout: 30

production:
  <<: *defaults
";
        assert!(validate_yaml_safe(yaml, &policy).is_ok());
    }

    #[test]
    fn test_validate_rejects_python_exec() {
        let policy = YamlPolicy::permissive();
        let yaml = r#"!!python/exec 'import os; os.system("rm -rf /")'"#;

        let result = validate_yaml_safe(yaml, &policy);
        assert!(result.is_err());
    }
}

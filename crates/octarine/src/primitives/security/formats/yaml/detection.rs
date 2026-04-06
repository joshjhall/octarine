//! YAML threat detection
//!
//! Pattern-based detection for unsafe tags and anchor bombs.

// Allow expect in lazy_static regex patterns - these are compile-time patterns that will not fail
#![allow(clippy::expect_used)]

use lazy_static::lazy_static;
use regex::Regex;

use super::super::types::{FormatThreat, YamlPolicy};

lazy_static! {
    /// Pattern for Python-specific unsafe tags
    static ref PYTHON_TAG_PATTERN: Regex = Regex::new(
        r"!!python/(object|module|name|exec|apply|import)"
    ).expect("valid regex");

    /// Pattern for Ruby-specific unsafe tags
    static ref RUBY_TAG_PATTERN: Regex = Regex::new(
        r"!!ruby/(object|hash|struct|sym|exception)"
    ).expect("valid regex");

    /// Pattern for PHP-specific unsafe tags
    static ref PHP_TAG_PATTERN: Regex = Regex::new(
        r"!!php/(object|class)"
    ).expect("valid regex");

    /// Pattern for Java-specific unsafe tags
    static ref JAVA_TAG_PATTERN: Regex = Regex::new(
        r"!!java/(object|class)"
    ).expect("valid regex");

    /// Pattern for generic object tags
    static ref OBJECT_TAG_PATTERN: Regex = Regex::new(
        r"!!(binary|tag:yaml\.org,2002:)"
    ).expect("valid regex");

    /// Pattern for anchor definitions
    static ref ANCHOR_PATTERN: Regex = Regex::new(
        r"&\w+"
    ).expect("valid regex");

    /// Pattern for alias references
    static ref ALIAS_PATTERN: Regex = Regex::new(
        r"\*\w+"
    ).expect("valid regex");
}

/// Common unsafe YAML tags that can lead to code execution
const UNSAFE_TAGS: &[&str] = &[
    "!!python/object",
    "!!python/object/apply",
    "!!python/object/new",
    "!!python/name",
    "!!python/module",
    "!!python/exec",
    "!!ruby/object",
    "!!ruby/hash",
    "!!ruby/struct",
    "!!ruby/sym",
    "!!php/object",
    "!!java/object",
    "!<tag:yaml.org,2002:python/object/apply>",
];

/// Check if input contains any unsafe YAML patterns
#[must_use]
pub(crate) fn is_yaml_unsafe(input: &str) -> bool {
    is_unsafe_tag_present(input) || is_anchor_bomb_present(input)
}

/// Check if input contains unsafe YAML tags
#[must_use]
pub(crate) fn is_unsafe_tag_present(input: &str) -> bool {
    // Check against known unsafe patterns
    PYTHON_TAG_PATTERN.is_match(input)
        || RUBY_TAG_PATTERN.is_match(input)
        || PHP_TAG_PATTERN.is_match(input)
        || JAVA_TAG_PATTERN.is_match(input)
        || UNSAFE_TAGS.iter().any(|tag| input.contains(tag))
}

/// Check if input shows signs of anchor/alias bomb
///
/// An anchor bomb uses YAML's alias feature to create
/// exponential expansion, similar to XML's billion laughs.
#[must_use]
pub(crate) fn is_anchor_bomb_present(input: &str) -> bool {
    // Count anchors and aliases
    let anchor_count = ANCHOR_PATTERN.find_iter(input).count();
    let alias_count = ALIAS_PATTERN.find_iter(input).count();

    // Suspicious if many aliases reference few anchors
    // (indicates potential exponential expansion)
    if anchor_count > 0 && alias_count > anchor_count.saturating_mul(3) {
        return true;
    }

    // Check for self-referential patterns
    // e.g., &a [*a, *a, *a] - the alias references appear after anchor
    if anchor_count > 0 && alias_count > 10 {
        return true;
    }

    false
}

/// Count the number of alias references in YAML
fn count_aliases(input: &str) -> usize {
    ALIAS_PATTERN.find_iter(input).count()
}

/// Detect all YAML threats according to policy
#[must_use]
pub(crate) fn detect_yaml_threats(input: &str, policy: &YamlPolicy) -> Vec<FormatThreat> {
    let mut threats = Vec::new();

    if is_unsafe_tag_present(input) {
        threats.push(FormatThreat::YamlUnsafeTag);
    }

    // Check alias count against policy
    let alias_count = count_aliases(input);
    if alias_count > policy.max_aliases {
        threats.push(FormatThreat::YamlAnchorBomb);
    }

    // Also check for bomb patterns regardless of policy
    if is_anchor_bomb_present(input) && !threats.contains(&FormatThreat::YamlAnchorBomb) {
        threats.push(FormatThreat::YamlAnchorBomb);
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
    fn test_is_unsafe_tag_present_python() {
        assert!(is_unsafe_tag_present("!!python/object"));
        assert!(is_unsafe_tag_present("!!python/object/apply:os.system"));
        assert!(is_unsafe_tag_present("!!python/exec 'import os'"));
        assert!(is_unsafe_tag_present("!!python/module:os"));
    }

    #[test]
    fn test_is_unsafe_tag_present_ruby() {
        assert!(is_unsafe_tag_present("!!ruby/object:Gem::Requirement"));
        assert!(is_unsafe_tag_present("!!ruby/hash"));
        assert!(is_unsafe_tag_present("!!ruby/struct"));
    }

    #[test]
    fn test_is_unsafe_tag_present_clean() {
        assert!(!is_unsafe_tag_present("key: value"));
        assert!(!is_unsafe_tag_present("- item1\n- item2"));
        assert!(!is_unsafe_tag_present("number: 123"));
    }

    #[test]
    fn test_is_anchor_bomb_present() {
        // Suspicious pattern: many aliases for few anchors
        let bomb = r"
x: &a
- *a
- *a
- *a
- *a
- *a
- *a
- *a
- *a
- *a
- *a
- *a
";
        assert!(is_anchor_bomb_present(bomb));
    }

    #[test]
    fn test_is_anchor_bomb_present_clean() {
        // Normal anchor/alias usage
        let normal = r"
defaults: &defaults
  timeout: 30
  retries: 3

production:
  <<: *defaults
  debug: false
";
        assert!(!is_anchor_bomb_present(normal));
    }

    #[test]
    fn test_is_yaml_unsafe() {
        assert!(is_yaml_unsafe("!!python/exec 'rm -rf /'"));
        assert!(!is_yaml_unsafe("key: value"));
    }

    #[test]
    fn test_detect_yaml_threats_unsafe_tag() {
        let policy = YamlPolicy::default();
        let yaml = "!!python/object/apply:os.system ['whoami']";

        let threats = detect_yaml_threats(yaml, &policy);
        assert!(threats.contains(&FormatThreat::YamlUnsafeTag));
    }

    #[test]
    fn test_detect_yaml_threats_alias_limit() {
        let policy = YamlPolicy {
            allowed_tags: Default::default(),
            max_aliases: 2,
        };
        let yaml = "&a 1\nx: *a\ny: *a\nz: *a";

        let threats = detect_yaml_threats(yaml, &policy);
        assert!(threats.contains(&FormatThreat::YamlAnchorBomb));
    }

    #[test]
    fn test_detect_yaml_threats_clean() {
        let policy = YamlPolicy::default();
        let yaml = "key: value\nlist:\n  - item1\n  - item2";

        let threats = detect_yaml_threats(yaml, &policy);
        assert!(threats.is_empty());
    }
}

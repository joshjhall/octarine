//! Generic identifier detection functions
//!
//! Boolean detection functions for generic identifiers.
//! These are the "is_*" functions that return bool.

use super::super::common::{
    is_identifier_chars, is_injection_pattern_present, is_sql_injection_pattern_present,
    is_valid_start_char,
};
use super::MAX_IDENTIFIER_LENGTH;

// ============================================================================
// Generic Identifier Detection
// ============================================================================

/// Check if a generic identifier is valid
///
/// A valid generic identifier:
/// - Is not empty
/// - Does not exceed MAX_IDENTIFIER_LENGTH (200) characters
/// - Starts with a letter or underscore
/// - Contains only alphanumeric characters, underscores, and hyphens
/// - Does not contain injection patterns
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::identifiers::generic::detection;
///
/// assert!(detection::is_valid_identifier("api-key-123"));
/// assert!(detection::is_valid_identifier("my_identifier"));
/// assert!(!detection::is_valid_identifier("123identifier")); // starts with number
/// assert!(!detection::is_valid_identifier("id';DROP")); // injection pattern
/// ```
#[must_use]
pub fn is_valid_identifier(name: &str) -> bool {
    is_valid_identifier_with_config(name, MAX_IDENTIFIER_LENGTH, true)
}

/// Check if a generic identifier is valid with custom configuration
#[must_use]
pub fn is_valid_identifier_with_config(
    name: &str,
    max_length: usize,
    check_injection: bool,
) -> bool {
    !name.is_empty()
        && name.len() <= max_length
        && is_valid_start_char(name)
        && is_identifier_chars(name, &['-']) // Generic allows hyphens
        && (!check_injection || !is_injection_pattern_present(name))
        && (!check_injection || !is_sql_injection_pattern_present(name))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_valid_identifiers() {
        // Standard identifiers
        assert!(is_valid_identifier("identifier"));
        assert!(is_valid_identifier("my_identifier"));
        assert!(is_valid_identifier("MyIdentifier"));
        assert!(is_valid_identifier("identifier123"));
        assert!(is_valid_identifier("_private"));

        // Kebab-case (allowed in generic)
        assert!(is_valid_identifier("my-identifier"));
        assert!(is_valid_identifier("api-key-v2"));
        assert!(is_valid_identifier("config-value"));
    }

    #[test]
    fn test_invalid_identifiers() {
        assert!(!is_valid_identifier("")); // Empty
        assert!(!is_valid_identifier("123identifier")); // Starts with number
        assert!(!is_valid_identifier("-identifier")); // Starts with hyphen
        assert!(!is_valid_identifier("$identifier")); // Starts with dollar
        assert!(!is_valid_identifier("my.identifier")); // Contains period
        assert!(!is_valid_identifier("my identifier")); // Contains space
    }

    #[test]
    fn test_injection_patterns() {
        // Command injection
        assert!(!is_valid_identifier("id${var}"));
        assert!(!is_valid_identifier("id$(command)"));
        assert!(!is_valid_identifier("id`ls`"));

        // SQL injection
        assert!(!is_valid_identifier("id--comment"));
        assert!(!is_valid_identifier("id/*comment*/"));
        assert!(!is_valid_identifier("id';DROP"));

        // Template/path injection
        assert!(!is_valid_identifier("{{template}}"));
        assert!(!is_valid_identifier("../id"));
    }

    #[test]
    fn test_length_limits() {
        let at_limit = "a".repeat(MAX_IDENTIFIER_LENGTH);
        let over_limit = "a".repeat(MAX_IDENTIFIER_LENGTH + 1);

        assert!(is_valid_identifier(&at_limit));
        assert!(!is_valid_identifier(&over_limit));
    }

    #[test]
    fn test_case_handling() {
        assert!(is_valid_identifier("lowercase"));
        assert!(is_valid_identifier("UPPERCASE"));
        assert!(is_valid_identifier("CamelCase"));
        assert!(is_valid_identifier("camelCase"));
        assert!(is_valid_identifier("snake_case"));
        assert!(is_valid_identifier("kebab-case"));
    }

    #[test]
    fn test_common_patterns() {
        // API keys
        assert!(is_valid_identifier("api-key-123abc"));
        assert!(is_valid_identifier("sk_live_abcd1234"));
        assert!(is_valid_identifier("pk_test_xyz789"));

        // Config keys
        assert!(is_valid_identifier("app_config_value"));
        assert!(is_valid_identifier("feature-flag-name"));
    }

    #[test]
    fn test_with_config() {
        // Custom length
        assert!(is_valid_identifier_with_config("short", 10, true));
        assert!(!is_valid_identifier_with_config(
            "this-is-too-long",
            10,
            true
        ));

        // Injection check disabled
        assert!(is_valid_identifier_with_config("normal-id", 200, false));
    }
}

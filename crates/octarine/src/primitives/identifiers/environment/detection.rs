//! Environment variable detection functions
//!
//! Boolean detection functions for environment variable names.
//! These are the "is_*" functions that return bool.

use super::super::common::{
    is_identifier_chars, is_injection_pattern_present, is_valid_start_char,
};
use super::{CRITICAL_VARS, MAX_ENV_VAR_LENGTH, RESERVED_VARS};

// ============================================================================
// Environment Variable Detection
// ============================================================================

/// Check if an environment variable name is valid
///
/// A valid environment variable name:
/// - Is not empty
/// - Does not exceed MAX_ENV_VAR_LENGTH (256) characters
/// - Starts with a letter or underscore
/// - Contains only alphanumeric characters and underscores
/// - Is not a reserved system variable
/// - Does not contain injection patterns
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::identifiers::environment::detection;
///
/// assert!(detection::is_valid_env_var("MY_APP_CONFIG"));
/// assert!(detection::is_valid_env_var("DEBUG_MODE"));
/// assert!(!detection::is_valid_env_var("123_VAR")); // starts with number
/// assert!(!detection::is_valid_env_var("PATH")); // reserved variable
/// ```
#[must_use]
pub fn is_valid_env_var(name: &str) -> bool {
    is_valid_env_var_with_config(name, MAX_ENV_VAR_LENGTH, true, true)
}

/// Check if an environment variable name is valid with custom configuration
#[must_use]
pub fn is_valid_env_var_with_config(
    name: &str,
    max_length: usize,
    check_reserved: bool,
    check_injection: bool,
) -> bool {
    !name.is_empty()
        && name.len() <= max_length
        && is_valid_start_char(name)
        && is_identifier_chars(name, &[]) // Env vars: alphanumeric + underscore only
        && (!check_reserved || !is_reserved_var(name))
        && (!check_injection || !is_injection_pattern_present(name))
}

/// Check if a variable name is reserved
#[must_use]
pub fn is_reserved_var(name: &str) -> bool {
    RESERVED_VARS.contains(&name) || CRITICAL_VARS.contains(&name)
}

/// Check if a variable is critical (security-sensitive)
#[must_use]
pub fn is_critical_var(name: &str) -> bool {
    CRITICAL_VARS.contains(&name)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_valid_env_vars() {
        assert!(is_valid_env_var("MY_APP_CONFIG"));
        assert!(is_valid_env_var("DATABASE_URL"));
        assert!(is_valid_env_var("API_KEY"));
        assert!(is_valid_env_var("DEBUG_MODE"));
        assert!(is_valid_env_var("_PRIVATE_VAR"));
        assert!(is_valid_env_var("VAR_123"));
        assert!(is_valid_env_var("A"));
    }

    #[test]
    fn test_invalid_env_vars() {
        assert!(!is_valid_env_var("")); // Empty
        assert!(!is_valid_env_var("123_VAR")); // Starts with number
        assert!(!is_valid_env_var("-VAR")); // Starts with hyphen
        assert!(!is_valid_env_var("$VAR")); // Starts with dollar
        assert!(!is_valid_env_var("MY-VAR")); // Contains hyphen
        assert!(!is_valid_env_var("MY.VAR")); // Contains period
        assert!(!is_valid_env_var("MY VAR")); // Contains space
    }

    #[test]
    fn test_reserved_vars() {
        assert!(!is_valid_env_var("PATH"));
        assert!(!is_valid_env_var("HOME"));
        assert!(!is_valid_env_var("USER"));
        assert!(!is_valid_env_var("SHELL"));
        assert!(!is_valid_env_var("LD_PRELOAD"));
        assert!(!is_valid_env_var("LD_LIBRARY_PATH"));
    }

    #[test]
    fn test_injection_patterns() {
        assert!(!is_valid_env_var("VAR$(whoami)"));
        assert!(!is_valid_env_var("VAR`ls`"));
        assert!(!is_valid_env_var("VAR${USER}"));
        assert!(!is_valid_env_var("VAR;ls"));
        assert!(!is_valid_env_var("VAR|grep"));
    }

    #[test]
    fn test_length_limits() {
        let at_limit = "A".repeat(MAX_ENV_VAR_LENGTH);
        let over_limit = "A".repeat(MAX_ENV_VAR_LENGTH + 1);

        assert!(is_valid_env_var(&at_limit));
        assert!(!is_valid_env_var(&over_limit));
    }

    #[test]
    fn test_is_reserved_var() {
        assert!(is_reserved_var("PATH"));
        assert!(is_reserved_var("HOME"));
        assert!(is_reserved_var("LD_PRELOAD"));
        assert!(!is_reserved_var("MY_VAR"));
    }

    #[test]
    fn test_is_critical_var() {
        assert!(is_critical_var("LD_PRELOAD"));
        assert!(is_critical_var("LD_LIBRARY_PATH"));
        assert!(is_critical_var("PATH"));
        assert!(is_critical_var("IFS"));
        assert!(!is_critical_var("HOME")); // Reserved but not critical
        assert!(!is_critical_var("MY_VAR"));
    }

    #[test]
    fn test_case_handling() {
        // Mixed case is valid
        assert!(is_valid_env_var("MyVariable"));
        assert!(is_valid_env_var("myVariable"));
        assert!(is_valid_env_var("my_variable"));
    }
}

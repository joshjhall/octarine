//! Environment variable validation functions
//!
//! Result-returning validation functions for environment variable names.
//! These are the "validate_*" functions that return Result<(), Problem>.

use super::MAX_ENV_VAR_LENGTH;
use super::detection;
use crate::primitives::types::Problem;

/// Result type for validation operations
pub type ValidationResult = Result<(), Problem>;

// ============================================================================
// Environment Variable Validation
// ============================================================================

/// Validate an environment variable name
///
/// Returns `Ok(())` if valid, or `Err(Problem)` with details if invalid.
///
/// # Errors
///
/// Returns error if:
/// - Name is empty
/// - Name exceeds MAX_ENV_VAR_LENGTH
/// - Name starts with invalid character
/// - Name contains invalid characters
/// - Name is a reserved system variable
/// - Name contains injection patterns
pub fn validate_env_var(name: &str) -> ValidationResult {
    validate_env_var_with_config(name, MAX_ENV_VAR_LENGTH, true, true)
}

/// Validate an environment variable name with custom configuration
pub fn validate_env_var_with_config(
    name: &str,
    max_length: usize,
    check_reserved: bool,
    check_injection: bool,
) -> ValidationResult {
    if name.is_empty() {
        return Err(Problem::validation(
            "Environment variable name cannot be empty",
        ));
    }

    if name.len() > max_length {
        return Err(Problem::validation(format!(
            "Environment variable name exceeds {} characters",
            max_length
        )));
    }

    if !super::super::common::is_valid_start_char(name) {
        return Err(Problem::validation(
            "Environment variable must start with letter or underscore",
        ));
    }

    if !super::super::common::is_identifier_chars(name, &[]) {
        return Err(Problem::validation(
            "Environment variable contains invalid characters (use alphanumeric and underscore only)",
        ));
    }

    if check_injection && super::super::common::is_injection_pattern_present(name) {
        return Err(Problem::security(
            "Command injection pattern detected in environment variable",
        ));
    }

    if check_reserved {
        if detection::is_critical_var(name) {
            return Err(Problem::security(format!(
                "Cannot override critical system variable '{}'",
                name
            )));
        }
        if detection::is_reserved_var(name) {
            return Err(Problem::validation(format!(
                "'{}' is a reserved environment variable",
                name
            )));
        }
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
    fn test_validate_valid_env_vars() {
        assert!(validate_env_var("MY_APP_CONFIG").is_ok());
        assert!(validate_env_var("DEBUG_MODE").is_ok());
        assert!(validate_env_var("_PRIVATE").is_ok());
    }

    #[test]
    fn test_validate_empty() {
        let result = validate_env_var("");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected error")
                .to_string()
                .contains("empty")
        );
    }

    #[test]
    fn test_validate_too_long() {
        let too_long = "A".repeat(MAX_ENV_VAR_LENGTH + 1);
        let result = validate_env_var(&too_long);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected error")
                .to_string()
                .contains("exceeds")
        );
    }

    #[test]
    fn test_validate_invalid_start() {
        let result = validate_env_var("123VAR");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected error")
                .to_string()
                .contains("start")
        );
    }

    #[test]
    fn test_validate_reserved() {
        let result = validate_env_var("PATH");
        assert!(result.is_err());
        // PATH is critical, so it should be a security error
    }

    #[test]
    fn test_validate_critical() {
        let result = validate_env_var("LD_PRELOAD");
        assert!(result.is_err());
        // Should specifically mention it's critical
    }

    #[test]
    fn test_validate_with_config() {
        // Allow reserved vars
        let result = validate_env_var_with_config("PATH", MAX_ENV_VAR_LENGTH, false, true);
        assert!(result.is_ok());

        // Custom length
        let result = validate_env_var_with_config("SHORT", 10, true, true);
        assert!(result.is_ok());

        let result = validate_env_var_with_config("TOO_LONG_VAR", 10, true, true);
        assert!(result.is_err());
    }
}

//! Generic identifier validation functions
//!
//! Result-returning validation functions for generic identifiers.
//! These are the "validate_*" functions that return Result<(), Problem>.

use super::MAX_IDENTIFIER_LENGTH;
use super::detection;
use crate::primitives::types::Problem;

/// Result type for validation operations
pub type ValidationResult = Result<(), Problem>;

// ============================================================================
// Generic Identifier Validation
// ============================================================================

/// Validate a generic identifier
///
/// Returns `Ok(())` if valid, or `Err(Problem)` with details if invalid.
///
/// # Errors
///
/// Returns error if:
/// - Identifier is empty
/// - Identifier exceeds MAX_IDENTIFIER_LENGTH
/// - Identifier starts with invalid character
/// - Identifier contains invalid characters
/// - Identifier contains injection patterns
pub fn validate_identifier(name: &str) -> ValidationResult {
    validate_identifier_with_config(name, MAX_IDENTIFIER_LENGTH, true)
}

/// Validate a generic identifier with custom configuration
pub fn validate_identifier_with_config(
    name: &str,
    max_length: usize,
    check_injection: bool,
) -> ValidationResult {
    if name.is_empty() {
        return Err(Problem::validation("Identifier cannot be empty"));
    }

    if name.len() > max_length {
        return Err(Problem::validation(format!(
            "Identifier exceeds {} characters",
            max_length
        )));
    }

    if !super::super::common::is_valid_start_char(name) {
        return Err(Problem::validation(
            "Identifier must start with letter or underscore",
        ));
    }

    if !super::super::common::is_identifier_chars(name, &['-']) {
        return Err(Problem::validation(
            "Identifier contains invalid characters (use alphanumeric, underscore, or hyphen)",
        ));
    }

    if check_injection {
        if super::super::common::is_injection_pattern_present(name) {
            return Err(Problem::security(
                "Command injection pattern detected in identifier",
            ));
        }
        if super::super::common::is_sql_injection_pattern_present(name) {
            return Err(Problem::security(
                "SQL injection pattern detected in identifier",
            ));
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
    fn test_validate_valid_identifiers() {
        assert!(validate_identifier("api-key-123").is_ok());
        assert!(validate_identifier("my_identifier").is_ok());
        assert!(validate_identifier("_private").is_ok());
    }

    #[test]
    fn test_validate_empty() {
        let result = validate_identifier("");
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
        let too_long = "a".repeat(MAX_IDENTIFIER_LENGTH + 1);
        let result = validate_identifier(&too_long);
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
        let result = validate_identifier("123identifier");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected error")
                .to_string()
                .contains("start")
        );
    }

    #[test]
    fn test_validate_injection() {
        // Command injection
        assert!(validate_identifier("$(cmd)").is_err());

        // SQL injection
        assert!(validate_identifier("id--comment").is_err());
    }

    #[test]
    fn test_validate_with_config() {
        // Custom length
        let result = validate_identifier_with_config("short", 10, true);
        assert!(result.is_ok());

        let result = validate_identifier_with_config("too-long-id", 10, true);
        assert!(result.is_err());

        // Without injection check
        let result = validate_identifier_with_config("normal-id", 200, false);
        assert!(result.is_ok());
    }
}

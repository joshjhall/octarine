//! Username validation functions
//!
//! Validates usernames according to common web standards.

use crate::primitives::Problem;

// ============================================================================
// Username Validation
// ============================================================================

/// Validate username format (returns Result)
///
/// Validates usernames according to common web standards:
/// - Length: 3-32 characters
/// - Characters: alphanumeric, underscore, hyphen, dot
/// - Cannot start/end with special characters
/// - No consecutive special characters
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::validation;
///
/// assert!(validation::validate_username("john_doe").is_ok());
/// assert!(validation::validate_username("user123").is_ok());
/// assert!(validation::validate_username("ab").is_err()); // Too short
/// assert!(validation::validate_username("_user").is_err()); // Starts with special
/// ```
///
/// # Errors
///
/// Returns `Problem::validation` if:
/// - Username is shorter than 3 or longer than 32 characters
/// - Contains invalid characters
/// - Starts or ends with special characters
/// - Contains consecutive special characters
pub fn validate_username(username: &str) -> Result<(), Problem> {
    let trimmed = username.trim();

    // Length check
    if trimmed.len() < 3 {
        return Err(Problem::Validation(
            "Username must be at least 3 characters".into(),
        ));
    }
    if trimmed.len() > 32 {
        return Err(Problem::Validation(
            "Username must be at most 32 characters".into(),
        ));
    }

    // Character validation
    let chars: Vec<char> = trimmed.chars().collect();
    for c in &chars {
        if !c.is_ascii_alphanumeric() && *c != '_' && *c != '-' && *c != '.' {
            return Err(Problem::Validation(
                "Username can only contain letters, numbers, underscore, hyphen, and dot".into(),
            ));
        }
    }

    // Cannot start or end with special characters
    if let Some(first) = chars.first()
        && !first.is_ascii_alphanumeric()
    {
        return Err(Problem::Validation(
            "Username cannot start with special character".into(),
        ));
    }
    if let Some(last) = chars.last()
        && !last.is_ascii_alphanumeric()
    {
        return Err(Problem::Validation(
            "Username cannot end with special character".into(),
        ));
    }

    // No consecutive special characters
    let mut prev_special = false;
    for c in &chars {
        let is_special = !c.is_ascii_alphanumeric();
        if is_special && prev_special {
            return Err(Problem::Validation(
                "Username cannot have consecutive special characters".into(),
            ));
        }
        prev_special = is_special;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_username_validation() {
        // Valid usernames
        assert!(validate_username("john_doe").is_ok());
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("test.user").is_ok());
        assert!(validate_username("my-username").is_ok());
        assert!(validate_username("abc").is_ok()); // Minimum length

        // Invalid - too short
        assert!(validate_username("ab").is_err());
        assert!(validate_username("a").is_err());

        // Invalid - too long
        assert!(validate_username(&"a".repeat(33)).is_err());

        // Invalid - special characters at start/end
        assert!(validate_username("_user").is_err());
        assert!(validate_username("user_").is_err());
        assert!(validate_username(".user").is_err());
        assert!(validate_username("-user").is_err());

        // Invalid - consecutive special characters
        assert!(validate_username("user__name").is_err());
        assert!(validate_username("user..name").is_err());
        assert!(validate_username("user.-name").is_err());

        // Invalid - disallowed characters
        assert!(validate_username("user@name").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username("user!name").is_err());
    }

    #[test]
    fn test_username_validation_errors() {
        let err = validate_username("ab").expect_err("should fail for short username");
        assert!(err.to_string().contains("at least 3"));

        let err = validate_username("_user").expect_err("should fail for leading special");
        assert!(err.to_string().contains("cannot start"));

        let err = validate_username("user__name").expect_err("should fail for consecutive special");
        assert!(err.to_string().contains("consecutive"));
    }

    #[test]
    fn test_username_edge_cases() {
        // Empty and whitespace
        assert!(validate_username("").is_err());
        assert!(validate_username("   ").is_err());

        // At length boundaries
        assert!(validate_username("abc").is_ok()); // Minimum 3
        assert!(validate_username(&"a".repeat(32)).is_ok()); // Maximum 32
        assert!(validate_username(&"a".repeat(33)).is_err()); // Too long

        // Unicode (not allowed)
        assert!(validate_username("用户名").is_err()); // Chinese
        assert!(validate_username("пользователь").is_err()); // Russian

        // Numbers only
        assert!(validate_username("123").is_ok());
        assert!(validate_username("user123").is_ok());

        // Mixed case
        assert!(validate_username("UserName").is_ok());
        assert!(validate_username("USERNAME").is_ok());
    }
}

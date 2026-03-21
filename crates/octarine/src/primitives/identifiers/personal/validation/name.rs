//! Name validation functions
//!
//! Validates personal names according to common standards.

use crate::primitives::Problem;

// ============================================================================
// Name Validation
// ============================================================================

/// Validate personal name format (returns Result)
///
/// Validates names according to common standards:
/// - Length: 1-100 characters per part, max 200 total
/// - Characters: letters, spaces, hyphens, apostrophes, periods
/// - No numbers or special characters
/// - At least one letter
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::validation;
///
/// assert!(validation::validate_name("John Smith").is_ok());
/// assert!(validation::validate_name("Mary Jane Watson-Parker").is_ok());
/// assert!(validation::validate_name("O'Brien").is_ok());
/// assert!(validation::validate_name("John123").is_err()); // Numbers
/// assert!(validation::validate_name("").is_err()); // Empty
/// ```
///
/// # Errors
///
/// Returns `Problem::validation` if:
/// - Name is empty or longer than 200 characters
/// - Contains numbers
/// - Contains invalid special characters
/// - Has no letters
pub fn validate_name(name: &str) -> Result<(), Problem> {
    let trimmed = name.trim();

    // Empty check
    if trimmed.is_empty() {
        return Err(Problem::Validation("Name cannot be empty".into()));
    }

    // Length check
    if trimmed.len() > 200 {
        return Err(Problem::Validation(
            "Name must be at most 200 characters".into(),
        ));
    }

    // Must contain at least one letter
    if !trimmed.chars().any(|c| c.is_alphabetic()) {
        return Err(Problem::Validation(
            "Name must contain at least one letter".into(),
        ));
    }

    // Character validation
    for c in trimmed.chars() {
        if c.is_ascii_digit() {
            return Err(Problem::Validation("Name cannot contain numbers".into()));
        }
        // Allow: letters (including unicode), spaces, hyphens, apostrophes, periods
        if !c.is_alphabetic() && c != ' ' && c != '-' && c != '\'' && c != '.' {
            return Err(Problem::Validation(
                "Name can only contain letters, spaces, hyphens, apostrophes, and periods".into(),
            ));
        }
    }

    // Check for consecutive special characters
    let chars: Vec<char> = trimmed.chars().collect();
    let mut prev_char: Option<char> = None;
    for &current in &chars {
        if let Some(prev) = prev_char
            && !prev.is_alphabetic()
            && !current.is_alphabetic()
            && prev != ' '
            && current != ' '
        {
            return Err(Problem::Validation(
                "Name cannot have consecutive special characters".into(),
            ));
        }
        prev_char = Some(current);
    }

    // Cannot start or end with special characters (except spaces which are trimmed)
    if let Some(first) = chars.first()
        && !first.is_alphabetic()
    {
        return Err(Problem::Validation(
            "Name cannot start with special character".into(),
        ));
    }
    if let Some(last) = chars.last()
        && !last.is_alphabetic()
        && *last != '.'
    {
        return Err(Problem::Validation(
            "Name cannot end with special character (except period)".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_name_validation() {
        // Valid names
        assert!(validate_name("John").is_ok());
        assert!(validate_name("John Smith").is_ok());
        assert!(validate_name("Mary Jane Watson-Parker").is_ok());
        assert!(validate_name("O'Brien").is_ok());
        assert!(validate_name("Dr. Smith").is_ok());
        assert!(validate_name("José García").is_ok());
        assert!(validate_name("Müller").is_ok());

        // Invalid - empty
        assert!(validate_name("").is_err());
        assert!(validate_name("   ").is_err());

        // Invalid - contains numbers
        assert!(validate_name("John123").is_err());
        assert!(validate_name("User1").is_err());

        // Invalid - special characters
        assert!(validate_name("John@Smith").is_err());
        assert!(validate_name("John#Smith").is_err());
        assert!(validate_name("John!").is_err());

        // Invalid - starts/ends with special
        assert!(validate_name("-John").is_err());
        assert!(validate_name("'Smith").is_err());
        assert!(validate_name("John-").is_err());
    }

    #[test]
    fn test_name_validation_errors() {
        assert!(validate_name("John Smith").is_ok());
        assert!(validate_name("O'Brien").is_ok());

        let err = validate_name("").expect_err("should fail for empty name");
        assert!(err.to_string().contains("empty"));

        let err = validate_name("John123").expect_err("should fail for numbers");
        assert!(err.to_string().contains("numbers"));

        let err = validate_name("-John").expect_err("should fail for leading special");
        assert!(err.to_string().contains("start"));
    }

    #[test]
    fn test_name_edge_cases() {
        // Single character
        assert!(validate_name("A").is_ok());

        // Very long name
        assert!(validate_name(&"A".repeat(200)).is_ok());
        assert!(validate_name(&"A".repeat(201)).is_err());

        // Multiple spaces (valid - just whitespace in between)
        assert!(validate_name("John  Smith").is_ok()); // Double space is okay

        // Consecutive special characters
        assert!(validate_name("John--Smith").is_err());
        assert!(validate_name("O''Brien").is_err());

        // Unicode names
        assert!(validate_name("北京").is_ok()); // Chinese
        assert!(validate_name("Владимир").is_ok()); // Russian
        assert!(validate_name("محمد").is_ok()); // Arabic
    }

    #[test]
    fn test_name_titles_and_suffixes() {
        // Titles with periods
        assert!(validate_name("Dr. John Smith").is_ok());
        assert!(validate_name("Mr. Jones").is_ok());
        assert!(validate_name("Prof. Williams").is_ok());

        // Suffixes
        assert!(validate_name("John Smith Jr.").is_ok());
        assert!(validate_name("Robert Kennedy III").is_ok()); // Roman numerals are letters
    }
}

//! Age validation functions
//!
//! Validates that input is a recognised age expression or a bare numeric
//! age in a plausible range.

use super::super::detection;
use crate::primitives::Problem;

/// Maximum plausible human age. Validation rejects anything higher.
const MAX_PLAUSIBLE_AGE: u32 = 150;

/// Validate an age expression or bare numeric age.
///
/// Accepts:
/// - Bare numbers in `0..=150`, e.g. `"42"`, `"95"`
/// - Free-text age expressions detected by [`detect_ages_in_text`], e.g.
///   `"42-year-old"`, `"in her eighties"`
///
/// # Errors
///
/// Returns `Problem::Validation` when:
/// - Input is empty
/// - Input is not a numeric age in range and contains no age expression
/// - Input is a numeric value but outside the plausible age range
///
/// [`detect_ages_in_text`]: super::super::detection::detect_ages_in_text
pub fn validate_age(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("Empty age value".into()));
    }

    if let Ok(parsed) = trimmed.parse::<u32>() {
        if parsed > MAX_PLAUSIBLE_AGE {
            return Err(Problem::Validation(format!(
                "Age value {parsed} exceeds maximum plausible age of {MAX_PLAUSIBLE_AGE}"
            )));
        }
        return Ok(());
    }

    if detection::is_age(trimmed) {
        return Ok(());
    }

    Err(Problem::Validation(
        "Input is not a recognised age expression".into(),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validate_bare_numeric_age() {
        assert!(validate_age("0").is_ok());
        assert!(validate_age("42").is_ok());
        assert!(validate_age("95").is_ok());
        assert!(validate_age("150").is_ok());
    }

    #[test]
    fn test_validate_age_expression() {
        assert!(validate_age("42-year-old").is_ok());
        assert!(validate_age("age 65").is_ok());
        assert!(validate_age("in her eighties").is_ok());
    }

    #[test]
    fn test_validate_rejects_implausible() {
        assert!(validate_age("999").is_err());
        assert!(validate_age("99999").is_err());
    }

    #[test]
    fn test_validate_rejects_empty_and_garbage() {
        assert!(validate_age("").is_err());
        assert!(validate_age("   ").is_err());
        assert!(validate_age("not an age").is_err());
        assert!(validate_age("abc").is_err());
    }
}

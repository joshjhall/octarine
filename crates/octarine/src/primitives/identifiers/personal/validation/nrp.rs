//! Nationality / Religion / Political Affiliation (NRP) validation
//!
//! Validates that input contains at least one entry from the corresponding
//! NRP lexicon.

use super::super::detection;
use crate::primitives::Problem;

/// Validate that the input contains at least one nationality reference.
///
/// # Errors
///
/// Returns `Problem::Validation` when no nationality is detected.
pub fn validate_nationality(value: &str) -> Result<(), Problem> {
    if value.trim().is_empty() {
        return Err(Problem::Validation("Empty nationality value".into()));
    }
    if detection::is_nationality(value) {
        return Ok(());
    }
    Err(Problem::Validation(
        "Input does not match any known nationality".into(),
    ))
}

/// Validate that the input contains at least one religion reference.
///
/// # Errors
///
/// Returns `Problem::Validation` when no religion is detected.
pub fn validate_religion(value: &str) -> Result<(), Problem> {
    if value.trim().is_empty() {
        return Err(Problem::Validation("Empty religion value".into()));
    }
    if detection::is_religion(value) {
        return Ok(());
    }
    Err(Problem::Validation(
        "Input does not match any known religion".into(),
    ))
}

/// Validate that the input contains at least one political-affiliation
/// reference.
///
/// # Errors
///
/// Returns `Problem::Validation` when no political affiliation is detected.
pub fn validate_political_affiliation(value: &str) -> Result<(), Problem> {
    if value.trim().is_empty() {
        return Err(Problem::Validation(
            "Empty political affiliation value".into(),
        ));
    }
    if detection::is_political_affiliation(value) {
        return Ok(());
    }
    Err(Problem::Validation(
        "Input does not match any known political affiliation".into(),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validate_nationality() {
        assert!(validate_nationality("American").is_ok());
        assert!(validate_nationality("she is Japanese").is_ok());
        assert!(validate_nationality("not a real demonym").is_err());
        assert!(validate_nationality("").is_err());
    }

    #[test]
    fn test_validate_religion() {
        assert!(validate_religion("Catholic").is_ok());
        assert!(validate_religion("she is Buddhist").is_ok());
        assert!(validate_religion("the database query").is_err());
        assert!(validate_religion("").is_err());
    }

    #[test]
    fn test_validate_political_affiliation() {
        assert!(validate_political_affiliation("Democrat").is_ok());
        assert!(validate_political_affiliation("Labour member").is_ok());
        assert!(validate_political_affiliation("apolitical entity").is_err());
        assert!(validate_political_affiliation("").is_err());
    }
}

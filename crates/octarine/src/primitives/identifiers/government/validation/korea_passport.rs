//! South Korea Passport validation
//!
//! Format: `[MRS][A-Z]?[0-9]{7,8}`
//!
//! - First character is one of `M` (multiple), `R` (resident), or `S` (single).
//! - Optional second uppercase letter (newer post-2008 format).
//! - 7 or 8 trailing digits.
//!
//! No public checksum is defined for Korean passports, so validation is
//! format-only.

use crate::primitives::types::Problem;

/// Valid first-character type indicators
const VALID_TYPE_PREFIXES: &[char] = &['M', 'R', 'S'];

/// Minimum passport length (1 letter + 7 digits)
const MIN_LENGTH: usize = 8;

/// Maximum passport length (2 letters + 8 digits)
const MAX_LENGTH: usize = 10;

/// Validate South Korea Passport format
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_korea_passport(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Korea Passport cannot be empty".to_string(),
        ));
    }

    let len = trimmed.chars().count();
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&len) {
        return Err(Problem::Validation(format!(
            "Korea Passport length must be {}-{} chars, got {}",
            MIN_LENGTH, MAX_LENGTH, len
        )));
    }

    let mut chars = trimmed.chars();
    let first = chars.next().unwrap_or(' ');
    if !VALID_TYPE_PREFIXES.contains(&first) {
        return Err(Problem::Validation(format!(
            "Korea Passport must start with M, R, or S, got '{}'",
            first
        )));
    }

    let rest: String = chars.collect();
    let (letter_part, digit_part) = split_letters_digits(&rest);

    if letter_part.len() > 1 {
        return Err(Problem::Validation(format!(
            "Korea Passport may have at most one optional letter after the type indicator, got {}",
            letter_part.len().saturating_add(1)
        )));
    }

    if !(7..=8).contains(&digit_part.len()) {
        return Err(Problem::Validation(format!(
            "Korea Passport must end with 7 or 8 digits, got {}",
            digit_part.len()
        )));
    }

    if !letter_part.chars().all(|c| c.is_ascii_uppercase()) {
        return Err(Problem::Validation(
            "Korea Passport optional letter must be A-Z".to_string(),
        ));
    }

    if !digit_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(Problem::Validation(
            "Korea Passport trailing characters must all be digits".to_string(),
        ));
    }

    Ok(())
}

/// Check if a Korea Passport is a test/dummy pattern
#[must_use]
pub fn is_test_korea_passport(value: &str) -> bool {
    let trimmed = value.trim();

    if validate_korea_passport(trimmed).is_err() {
        return false;
    }

    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.chars().all(|c| c == '0') {
        return true;
    }

    if let Some(first) = digits.chars().next()
        && digits.chars().all(|c| c == first)
    {
        return true;
    }

    if digits == "12345678" || digits == "1234567" {
        return true;
    }

    false
}

// ============================================================================
// Private Helpers
// ============================================================================

fn split_letters_digits(s: &str) -> (String, String) {
    let mut letters = String::new();
    let mut digits = String::new();
    let mut seen_digit = false;

    for c in s.chars() {
        if c.is_ascii_digit() {
            seen_digit = true;
            digits.push(c);
        } else if seen_digit {
            digits.push(c);
        } else {
            letters.push(c);
        }
    }

    (letters, digits)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_korea_passport_single_letter() {
        assert!(validate_korea_passport("M12345678").is_ok());
        assert!(validate_korea_passport("R12345678").is_ok());
        assert!(validate_korea_passport("S12345678").is_ok());
    }

    #[test]
    fn test_validate_korea_passport_seven_digit_variant() {
        assert!(validate_korea_passport("M1234567").is_ok());
    }

    #[test]
    fn test_validate_korea_passport_two_letter_format() {
        assert!(validate_korea_passport("MA12345678").is_ok());
        assert!(validate_korea_passport("SB1234567").is_ok());
    }

    #[test]
    fn test_validate_korea_passport_invalid_prefix() {
        assert!(validate_korea_passport("A12345678").is_err());
        assert!(validate_korea_passport("X12345678").is_err());
    }

    #[test]
    fn test_validate_korea_passport_lowercase_prefix() {
        assert!(validate_korea_passport("m12345678").is_err());
    }

    #[test]
    fn test_validate_korea_passport_too_short() {
        assert!(validate_korea_passport("M123456").is_err());
    }

    #[test]
    fn test_validate_korea_passport_too_long() {
        assert!(validate_korea_passport("MAB12345678").is_err());
        assert!(validate_korea_passport("M123456789").is_err());
    }

    #[test]
    fn test_validate_korea_passport_empty() {
        assert!(validate_korea_passport("").is_err());
    }

    #[test]
    fn test_validate_korea_passport_non_digit_tail() {
        assert!(validate_korea_passport("M1234567A").is_err());
    }

    #[test]
    fn test_is_test_korea_passport() {
        assert!(is_test_korea_passport("M00000000"));
        assert!(is_test_korea_passport("R11111111"));
        assert!(is_test_korea_passport("S12345678"));
        assert!(!is_test_korea_passport("M12397531"));
    }
}

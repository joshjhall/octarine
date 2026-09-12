//! Passport number validation
//!
//! Pure validation functions for passport numbers with no observe dependencies.
//!
//! # Format
//!
//! [`validate_passport`] applies the generic ICAO Doc 9303 shape: 1 alphabetic
//! character (series letter) followed by 6-8 digits, for a total of 7-9
//! characters, with known test patterns rejected.
//!
//! US passports do not all fit that shape — legacy books carry a bare 9-digit
//! number with no series letter. [`validate_us_passport`] accepts both US
//! layouts and does not reject test patterns;
//! [`validate_us_passport_strict`] adds the test-pattern gate back for callers
//! that want it.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.

use crate::primitives::Problem;

// ============================================================================
// Passport Validation
// ============================================================================

/// Validate passport number format
///
/// Validates that a passport number follows ICAO Doc 9303 format:
/// one alphabetic series letter followed by 6-8 digits (7-9 chars total).
///
/// # Returns
///
/// * `Ok(())` - If the passport number format is valid
/// * `Err(Problem)` - If the format is invalid with details
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::validate_passport("C12345678").is_ok());
/// assert!(validation::validate_passport("AB123").is_err());
/// ```
pub fn validate_passport(passport: &str) -> Result<(), Problem> {
    let trimmed = passport.trim();

    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Passport number cannot be empty".into(),
        ));
    }

    // Must be ASCII alphanumeric only
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(Problem::Validation(
            "Passport number must contain only alphanumeric characters".into(),
        ));
    }

    let len = trimmed.len();
    if !(7..=9).contains(&len) {
        return Err(Problem::Validation(format!(
            "Passport number must be 7-9 characters (got {})",
            len
        )));
    }

    let upper = trimmed.to_uppercase();
    let mut chars = upper.chars();

    // First character must be alphabetic (series letter)
    let first = chars
        .next()
        .ok_or_else(|| Problem::Validation("Passport number cannot be empty".into()))?;

    if !first.is_ascii_alphabetic() {
        return Err(Problem::Validation(
            "Passport number must start with an alphabetic series letter".into(),
        ));
    }

    // Remaining characters must be digits
    for (i, c) in chars.enumerate() {
        if !c.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "Passport number must have digits after series letter, found '{}' at position {}",
                c,
                i.saturating_add(1)
            )));
        }
    }

    // Reject test patterns
    if is_test_passport(trimmed) {
        return Err(Problem::Validation(
            "Test passport number patterns not allowed".into(),
        ));
    }

    Ok(())
}

// ============================================================================
// US Passport Validation
// ============================================================================

/// Validate a US passport number (lenient)
///
/// The US has issued two book layouts, both of which are in active
/// circulation and both of which this function accepts:
///
/// | Layout | Shape | Era |
/// |--------|-------|-----|
/// | Legacy | 9 digits (`123456789`) | pre-2021 books, still valid until expiry |
/// | Next Generation | 1 letter + 8 digits (`A12345678`) | current issuance |
///
/// Unlike [`validate_passport`], this does **not** require an alphabetic
/// series letter — the legacy layout has none, and rejecting it drops the
/// majority of US passports still in circulation. It also does **not** reject
/// [`is_test_passport`] patterns: a real number is not invalid merely because
/// its digits happen to run in sequence. Use
/// [`validate_us_passport_strict`] when filtering documentation and sample
/// data is the point.
///
/// # Returns
///
/// * `Ok(())` - If the number matches either US layout
/// * `Err(Problem)` - If the format is invalid, with details
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// // Legacy 9-digit book
/// assert!(validation::validate_us_passport("123456789").is_ok());
/// // Next Generation letter + 8 digits
/// assert!(validation::validate_us_passport("A12345678").is_ok());
/// // Two series letters is neither layout
/// assert!(validation::validate_us_passport("AB1234567").is_err());
/// ```
pub fn validate_us_passport(passport: &str) -> Result<(), Problem> {
    let trimmed = passport.trim();

    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "US passport number cannot be empty".into(),
        ));
    }

    // Must be ASCII alphanumeric only. This also rejects Unicode lookalikes
    // such as Cyrillic А (U+0410).
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(Problem::Validation(
            "US passport number must contain only alphanumeric characters".into(),
        ));
    }

    if trimmed.len() != 9 {
        return Err(Problem::Validation(format!(
            "US passport number must be 9 characters - 9 digits (legacy) or 1 letter + 8 digits (Next Generation), got {}",
            trimmed.len()
        )));
    }

    let upper = trimmed.to_uppercase();

    // Legacy layout: all 9 characters are digits.
    if upper.chars().all(|c| c.is_ascii_digit()) {
        return Ok(());
    }

    // Next Generation layout: one leading letter, then 8 digits.
    let mut chars = upper.chars();
    let first = chars
        .next()
        .ok_or_else(|| Problem::Validation("US passport number cannot be empty".into()))?;

    if !first.is_ascii_alphabetic() {
        return Err(Problem::Validation(
            "US passport number must be 9 digits (legacy) or start with a single series letter (Next Generation)"
                .into(),
        ));
    }

    if !chars.all(|c| c.is_ascii_digit()) {
        return Err(Problem::Validation(
            "US passport number must have 8 digits after the series letter".into(),
        ));
    }

    Ok(())
}

/// Validate a US passport number, rejecting known test patterns (strict)
///
/// Applies [`validate_us_passport`] and then rejects anything
/// [`is_test_passport`] recognises — all-zero, all-same-digit, and sequential
/// runs. Use this where sample and documentation numbers must not be treated
/// as real identifiers; use the lenient
/// [`validate_us_passport`] when the input is real-world data and a
/// sequential-looking number must still be accepted.
///
/// # Returns
///
/// * `Ok(())` - If the number matches a US layout and is not a test pattern
/// * `Err(Problem)` - If the format is invalid, or the number is a test pattern
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// // Lenient accepts an unfortunate-but-real sequential number
/// assert!(validation::validate_us_passport("A12345678").is_ok());
/// // Strict does not
/// assert!(validation::validate_us_passport_strict("A12345678").is_err());
/// ```
pub fn validate_us_passport_strict(passport: &str) -> Result<(), Problem> {
    validate_us_passport(passport)?;

    if is_test_passport(passport) {
        return Err(Problem::Validation(
            "Test US passport number patterns not allowed".into(),
        ));
    }

    Ok(())
}

// ============================================================================
// Test Pattern Detection
// ============================================================================

/// Check if a passport number is a known test/sample pattern
///
/// Test passport numbers are commonly used in documentation, testing, and examples.
/// These should not be treated as real passport identifiers.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::is_test_passport("A00000000"));
/// assert!(validation::is_test_passport("C12345678"));
/// assert!(!validation::is_test_passport("L83726159"));
/// ```
#[must_use]
pub fn is_test_passport(passport: &str) -> bool {
    let upper = passport.trim().to_uppercase();

    // Well-known test passport numbers
    let test_passports = [
        "A00000000",
        "B00000000",
        "C12345678",
        "A12345678",
        "X12345678",
        "Z99999999",
        "A11111111",
        "A99999999",
    ];

    if test_passports.contains(&upper.as_str()) {
        return true;
    }

    // Skip single-char passports
    if upper.len() < 2 {
        return false;
    }

    // All-zero digits after letter
    let digits = &upper[1..];
    if digits.chars().all(|c| c == '0') {
        return true;
    }

    // All-same digit after letter
    if let Some(first_digit) = digits.chars().next()
        && first_digit.is_ascii_digit()
        && digits.chars().all(|c| c == first_digit)
    {
        return true;
    }

    // Sequential ascending digits (e.g., A12345678, A23456789)
    let digit_chars: Vec<u8> = digits.bytes().filter(|b| b.is_ascii_digit()).collect();
    if digit_chars.len() >= 6 {
        let is_ascending = digit_chars.windows(2).all(|w| {
            w.get(1).copied().unwrap_or(0) == w.first().copied().unwrap_or(0).saturating_add(1)
        });
        if is_ascending {
            return true;
        }

        // Sequential descending digits (e.g., A98765432)
        let is_descending = digit_chars.windows(2).all(|w| {
            w.first().copied().unwrap_or(0) == w.get(1).copied().unwrap_or(0).saturating_add(1)
        });
        if is_descending {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ========================================================================
    // validate_passport tests
    // ========================================================================

    #[test]
    fn test_valid_passport_numbers() {
        assert!(validate_passport("L83726159").is_ok());
        assert!(validate_passport("M4928371").is_ok());
        assert!(validate_passport("P392817").is_ok());
        assert!(validate_passport("N5738291").is_ok());
    }

    #[test]
    fn test_valid_passport_case_insensitive() {
        assert!(validate_passport("l83726159").is_ok());
        assert!(validate_passport("m4928371").is_ok());
    }

    #[test]
    fn test_valid_passport_with_whitespace() {
        assert!(validate_passport("  L83726159  ").is_ok());
        assert!(validate_passport("M4928371 ").is_ok());
    }

    #[test]
    fn test_empty_passport() {
        let result = validate_passport("");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("empty")
        );
    }

    #[test]
    fn test_too_short_passport() {
        let result = validate_passport("A12345");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("7-9 characters")
        );
    }

    #[test]
    fn test_too_long_passport() {
        let result = validate_passport("A1234567890");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("7-9 characters")
        );
    }

    #[test]
    fn test_passport_must_start_with_letter() {
        let result = validate_passport("123456789");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("alphabetic series letter")
        );
    }

    #[test]
    fn test_passport_digits_after_letter() {
        let result = validate_passport("AB1234567");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("digits after series letter")
        );
    }

    #[test]
    fn test_passport_special_characters() {
        let result = validate_passport("A12345-78");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("alphanumeric")
        );
    }

    #[test]
    fn test_passport_rejects_test_patterns() {
        let result = validate_passport("A00000000");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("Test passport")
        );

        assert!(validate_passport("C12345678").is_err());
    }

    #[test]
    fn test_passport_unicode_lookalikes() {
        // Cyrillic А looks like Latin A
        assert!(validate_passport("А12345678").is_err()); // Cyrillic А
    }

    // ========================================================================
    // is_test_passport tests
    // ========================================================================

    #[test]
    fn test_known_test_passports() {
        assert!(is_test_passport("A00000000"));
        assert!(is_test_passport("C12345678"));
        assert!(is_test_passport("X12345678"));
        assert!(is_test_passport("Z99999999"));
    }

    #[test]
    fn test_all_same_digit() {
        assert!(is_test_passport("A11111111"));
        assert!(is_test_passport("B22222222"));
        assert!(is_test_passport("C33333333"));
    }

    #[test]
    fn test_sequential_patterns() {
        assert!(is_test_passport("A12345678"));
        assert!(is_test_passport("A98765432"));
    }

    #[test]
    fn test_real_looking_passports_not_flagged() {
        assert!(!is_test_passport("L83726159"));
        assert!(!is_test_passport("M4928371"));
        assert!(!is_test_passport("P392817"));
    }
    // ========================================================================
    // validate_us_passport tests
    // ========================================================================

    #[test]
    fn test_us_passport_accepts_legacy_nine_digits() {
        // The HIGH-4 regression: bare 9-digit legacy books are the majority of
        // US passports in circulation and validate_passport rejects them.
        assert!(validate_us_passport("123456789").is_ok());
        assert!(validate_us_passport("837261590").is_ok());
        // Confirm the generic ICAO validator still rejects it, so this test
        // fails if the two functions are ever collapsed into one.
        assert!(validate_passport("123456789").is_err());
    }

    #[test]
    fn test_us_passport_accepts_next_generation() {
        assert!(validate_us_passport("A83726159").is_ok());
        assert!(validate_us_passport("Z00000001").is_ok());
    }

    #[test]
    fn test_us_passport_case_insensitive_and_trimmed() {
        assert!(validate_us_passport("a83726159").is_ok());
        assert!(validate_us_passport("  A83726159  ").is_ok());
    }

    #[test]
    fn test_us_passport_rejects_wrong_length() {
        // 8 and 10 characters are neither layout.
        let result = validate_us_passport("A1234567");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("9 characters")
        );
        assert!(validate_us_passport("A123456789").is_err());
        assert!(validate_us_passport("12345678").is_err());
        assert!(validate_us_passport("1234567890").is_err());
    }

    #[test]
    fn test_us_passport_rejects_two_series_letters() {
        // "AB1234567" is 9 characters, so only a layout check catches it.
        let result = validate_us_passport("AB1234567");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("8 digits after the series letter")
        );
    }

    #[test]
    fn test_us_passport_rejects_trailing_letter() {
        // Digits must not be interrupted; "12345678A" is 9 chars but neither layout.
        assert!(validate_us_passport("12345678A").is_err());
        assert!(validate_us_passport("A1234567B").is_err());
    }

    #[test]
    fn test_us_passport_rejects_empty_and_punctuation() {
        assert!(validate_us_passport("").is_err());
        assert!(validate_us_passport("   ").is_err());
        assert!(validate_us_passport("A12345-78").is_err());
        assert!(validate_us_passport("123-456-789").is_err());
    }

    #[test]
    fn test_us_passport_rejects_unicode_lookalikes() {
        // Cyrillic А (U+0410) is not an ASCII series letter.
        assert!(validate_us_passport("А12345678").is_err());
    }

    #[test]
    fn test_us_passport_accepts_unfortunate_real_numbers() {
        // Sequential and descending runs are real issuable numbers. The
        // lenient validator must not drop them.
        assert!(validate_us_passport("A12345678").is_ok());
        assert!(validate_us_passport("A98765432").is_ok());
        assert!(validate_us_passport("123456789").is_ok());
    }

    // ========================================================================
    // validate_us_passport_strict tests
    // ========================================================================

    #[test]
    fn test_us_passport_strict_rejects_test_patterns() {
        // The strict/lenient split must be real: same input, opposite verdicts.
        assert!(validate_us_passport("A12345678").is_ok());
        assert!(validate_us_passport_strict("A12345678").is_err());

        assert!(validate_us_passport("A98765432").is_ok());
        assert!(validate_us_passport_strict("A98765432").is_err());

        assert!(validate_us_passport("A00000000").is_ok());
        assert!(validate_us_passport_strict("A00000000").is_err());
    }

    #[test]
    fn test_us_passport_strict_accepts_real_numbers() {
        assert!(validate_us_passport_strict("A83726159").is_ok());
        assert!(validate_us_passport_strict("837261590").is_ok());
    }

    #[test]
    fn test_us_passport_strict_error_mentions_test_pattern() {
        let message = validate_us_passport_strict("A11111111")
            .expect_err("expected error")
            .to_string();
        assert!(message.contains("Test"), "message was: {message}");
    }

    #[test]
    fn test_us_passport_strict_still_rejects_bad_format() {
        // Format errors surface from the lenient validator, not the test gate.
        let message = validate_us_passport_strict("AB1234567")
            .expect_err("expected error")
            .to_string();
        assert!(!message.contains("Test"), "message was: {message}");
    }
}

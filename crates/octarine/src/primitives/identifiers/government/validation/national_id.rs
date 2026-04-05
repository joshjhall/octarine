//! National ID validation
//!
//! Pure validation functions for national identification numbers with no observe dependencies.
//!
//! # Supported Formats
//!
//! - **UK National Insurance Number (NINO)**: 2 letters + 6 digits + 1 suffix letter
//! - **Canadian Social Insurance Number (SIN)**: 9 digits with Luhn checksum
//! - **Generic**: 8-15 alphanumeric characters
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.

use crate::primitives::Problem;

// ============================================================================
// National ID Validation (auto-detect)
// ============================================================================

/// Validate a national ID number, auto-detecting the format
///
/// Attempts to match against known national ID formats (UK NI, Canada SIN)
/// and falls back to generic alphanumeric validation.
///
/// # Returns
///
/// * `Ok(())` - If the national ID format is valid
/// * `Err(Problem)` - If the format is invalid with details
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::validate_national_id("AB123456C").is_ok());   // UK NI
/// assert!(validation::validate_national_id("046-454-286").is_ok()); // Canada SIN
/// ```
pub fn validate_national_id(national_id: &str) -> Result<(), Problem> {
    let trimmed = national_id.trim();

    if trimmed.is_empty() {
        return Err(Problem::Validation("National ID cannot be empty".into()));
    }

    // Try UK NI format: 2 letters + 6 digits + 1 letter
    let upper = trimmed.to_uppercase();
    let clean = upper.replace(['-', ' '], "");

    if is_uk_ni_shape(&clean) {
        return validate_uk_ni(trimmed);
    }

    // Try Canada SIN format: 9 digits (possibly with separators)
    let digits_only: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits_only.len() == 9 && is_canada_sin_shape(trimmed) {
        return validate_canada_sin(trimmed);
    }

    // Generic national ID: 8-15 alphanumeric characters
    validate_generic_national_id(trimmed)
}

/// Check if value has UK NI shape: 2 letters + 6 digits + 1 letter (9 chars)
fn is_uk_ni_shape(clean_upper: &str) -> bool {
    if clean_upper.len() != 9 {
        return false;
    }
    let chars: Vec<char> = clean_upper.chars().collect();
    chars.first().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.get(1).is_some_and(|c| c.is_ascii_alphabetic())
        && chars
            .get(2..8)
            .is_some_and(|s| s.iter().all(|c| c.is_ascii_digit()))
        && chars.get(8).is_some_and(|c| c.is_ascii_alphabetic())
}

/// Check if value has Canada SIN shape: 3-3-3 digit groups or 9 digits
fn is_canada_sin_shape(value: &str) -> bool {
    let trimmed = value.trim();
    // 9 bare digits
    if trimmed.len() == 9 && trimmed.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    // 3-3-3 with separators
    let non_digit_non_sep = trimmed
        .chars()
        .any(|c| !c.is_ascii_digit() && c != '-' && c != ' ');
    !non_digit_non_sep && trimmed.chars().filter(|c| c.is_ascii_digit()).count() == 9
}

// ============================================================================
// UK National Insurance Number
// ============================================================================

/// Invalid UK NI prefixes per HMRC rules
const INVALID_UK_NI_PREFIXES: &[&str] = &["BG", "GB", "NK", "KN", "TN", "NT", "ZZ"];

/// UK NI temporary prefixes (D, F, I, Q, U, V as first letter)
const INVALID_UK_NI_FIRST_LETTERS: &[char] = &['D', 'F', 'I', 'Q', 'U', 'V'];

/// UK NI invalid suffix letters
const INVALID_UK_NI_SUFFIXES: &[char] = &[
    'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z',
];

/// Validate UK National Insurance Number (NINO)
///
/// Format: 2 letters + 6 digits + 1 suffix letter (A, B, C, or D).
/// Rejects invalid prefixes per HMRC rules.
///
/// # Returns
///
/// * `Ok(())` - If the NI number is valid
/// * `Err(Problem)` - If the format is invalid with details
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::validate_uk_ni("AB123456C").is_ok());
/// assert!(validation::validate_uk_ni("BG123456A").is_err()); // Invalid prefix
/// ```
pub fn validate_uk_ni(ni: &str) -> Result<(), Problem> {
    let clean = ni.trim().to_uppercase().replace(['-', ' '], "");

    if clean.len() != 9 {
        return Err(Problem::Validation(format!(
            "UK NI number must be 9 characters (got {})",
            clean.len()
        )));
    }

    let chars: Vec<char> = clean.chars().collect();

    // First two characters must be letters
    let first = chars.first().copied().unwrap_or(' ');
    let second = chars.get(1).copied().unwrap_or(' ');

    if !first.is_ascii_alphabetic() || !second.is_ascii_alphabetic() {
        return Err(Problem::Validation(
            "UK NI number must start with two letters".into(),
        ));
    }

    // Middle 6 characters must be digits
    for (i, c) in chars.iter().enumerate().skip(2).take(6) {
        if !c.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "UK NI number must have digits at positions 3-8, found '{}' at position {}",
                c,
                i.saturating_add(1)
            )));
        }
    }

    // Last character must be a valid suffix letter (A, B, C, or D)
    let suffix = chars.get(8).copied().unwrap_or(' ');
    if INVALID_UK_NI_SUFFIXES.contains(&suffix) || !suffix.is_ascii_alphabetic() {
        return Err(Problem::Validation(format!(
            "UK NI number suffix must be A, B, C, or D (got '{}')",
            suffix
        )));
    }

    // Check invalid first letters
    if INVALID_UK_NI_FIRST_LETTERS.contains(&first) {
        return Err(Problem::Validation(format!(
            "UK NI number cannot start with '{}' (reserved temporary prefix)",
            first
        )));
    }

    // Check invalid prefixes
    let prefix: String = [first, second].iter().collect();
    if INVALID_UK_NI_PREFIXES.contains(&prefix.as_str()) {
        return Err(Problem::Validation(format!(
            "UK NI number prefix '{}' is not valid",
            prefix
        )));
    }

    // Reject test patterns
    if is_test_national_id(ni) {
        return Err(Problem::Validation(
            "Test NI number patterns not allowed".into(),
        ));
    }

    Ok(())
}

// ============================================================================
// Canadian Social Insurance Number
// ============================================================================

/// Validate Canadian Social Insurance Number (SIN) with Luhn checksum
///
/// Format: 9 digits, optionally formatted as `XXX-XXX-XXX` or `XXX XXX XXX`.
/// Uses Luhn algorithm for checksum validation.
///
/// # Returns
///
/// * `Ok(())` - If the SIN is valid
/// * `Err(Problem)` - If the format is invalid or checksum fails
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::validate_canada_sin("046-454-286").is_ok());
/// assert!(validation::validate_canada_sin("123-456-789").is_err()); // Bad checksum
/// ```
pub fn validate_canada_sin(sin: &str) -> Result<(), Problem> {
    let trimmed = sin.trim();

    // Extract digits only
    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.len() != 9 {
        return Err(Problem::Validation(format!(
            "Canadian SIN must be 9 digits (got {})",
            digits.len()
        )));
    }

    // Ensure only digits and valid separators
    if trimmed
        .chars()
        .any(|c| !c.is_ascii_digit() && c != '-' && c != ' ')
    {
        return Err(Problem::Validation(
            "Canadian SIN must contain only digits and optional separators (- or space)".into(),
        ));
    }

    // Luhn checksum validation
    if !luhn_check(&digits) {
        return Err(Problem::Validation(
            "Canadian SIN checksum (Luhn) validation failed".into(),
        ));
    }

    // Reject test patterns
    if is_test_national_id(sin) {
        return Err(Problem::Validation("Test SIN patterns not allowed".into()));
    }

    Ok(())
}

/// Luhn algorithm checksum validation
fn luhn_check(digits: &str) -> bool {
    let mut sum: u32 = 0;
    let mut double = false;

    for c in digits.chars().rev() {
        let Some(mut digit) = c.to_digit(10) else {
            return false;
        };

        if double {
            digit = digit.saturating_mul(2);
            if digit > 9 {
                digit = digit.saturating_sub(9);
            }
        }

        sum = sum.saturating_add(digit);
        double = !double;
    }

    sum.is_multiple_of(10)
}

// ============================================================================
// Generic National ID
// ============================================================================

/// Validate generic national ID format
///
/// Accepts 8-15 alphanumeric characters. Used as fallback when the format
/// doesn't match a known country-specific pattern.
fn validate_generic_national_id(national_id: &str) -> Result<(), Problem> {
    let clean = national_id
        .trim()
        .to_uppercase()
        .replace(['-', ' ', '.'], "");

    if !clean.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(Problem::Validation(
            "National ID must contain only alphanumeric characters".into(),
        ));
    }

    let len = clean.len();
    if !(8..=15).contains(&len) {
        return Err(Problem::Validation(format!(
            "National ID must be 8-15 characters (got {})",
            len
        )));
    }

    Ok(())
}

// ============================================================================
// Test Pattern Detection
// ============================================================================

/// Check if a national ID is a known test/sample pattern
///
/// Detects common test patterns across all national ID formats.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::is_test_national_id("AA000000A"));
/// assert!(validation::is_test_national_id("000-000-000"));
/// assert!(!validation::is_test_national_id("AB123456C"));
/// ```
#[must_use]
pub fn is_test_national_id(national_id: &str) -> bool {
    let upper = national_id.trim().to_uppercase();
    let clean = upper.replace(['-', ' ', '.'], "");

    // Well-known test NI numbers
    let test_patterns = ["AA000000A", "AB000000A", "ZZ999999D"];

    if test_patterns.contains(&clean.as_str()) {
        return true;
    }

    // All-zero digits
    let digits: String = clean.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 6 && digits.chars().all(|c| c == '0') {
        return true;
    }

    // All-same digits (9+ digits all the same)
    if digits.len() >= 9
        && let Some(first) = digits.chars().next()
        && digits.chars().all(|c| c == first)
    {
        return true;
    }

    // Sequential ascending 9-digit pattern
    if digits.len() == 9 && digits == "123456789" {
        return true;
    }

    // Sequential descending 9-digit pattern
    if digits.len() == 9 && digits == "987654321" {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ========================================================================
    // validate_uk_ni tests
    // ========================================================================

    #[test]
    fn test_valid_uk_ni() {
        assert!(validate_uk_ni("AB123456C").is_ok());
        assert!(validate_uk_ni("CE123456A").is_ok());
        assert!(validate_uk_ni("HJ987654B").is_ok());
        assert!(validate_uk_ni("LA456789D").is_ok());
    }

    #[test]
    fn test_uk_ni_case_insensitive() {
        assert!(validate_uk_ni("ab123456c").is_ok());
        assert!(validate_uk_ni("Ab123456C").is_ok());
    }

    #[test]
    fn test_uk_ni_with_spaces() {
        assert!(validate_uk_ni("AB 12 34 56 C").is_ok());
        assert!(validate_uk_ni(" AB123456C ").is_ok());
    }

    #[test]
    fn test_uk_ni_invalid_prefix_bg() {
        let result = validate_uk_ni("BG123456A");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("not valid")
        );
    }

    #[test]
    fn test_uk_ni_invalid_prefix_gb() {
        let result = validate_uk_ni("GB123456A");
        assert!(result.is_err());
    }

    #[test]
    fn test_uk_ni_invalid_first_letter_d() {
        let result = validate_uk_ni("DA123456A");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("reserved temporary prefix")
        );
    }

    #[test]
    fn test_uk_ni_invalid_first_letter_f() {
        assert!(validate_uk_ni("FA123456A").is_err());
    }

    #[test]
    fn test_uk_ni_invalid_suffix() {
        let result = validate_uk_ni("AB123456E");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("suffix must be A, B, C, or D")
        );
    }

    #[test]
    fn test_uk_ni_wrong_length() {
        let result = validate_uk_ni("AB12345C");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("9 characters")
        );
    }

    #[test]
    fn test_uk_ni_non_digit_middle() {
        let result = validate_uk_ni("AB12X456C");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("digits")
        );
    }

    #[test]
    fn test_uk_ni_empty() {
        assert!(validate_uk_ni("").is_err());
    }

    // ========================================================================
    // validate_canada_sin tests
    // ========================================================================

    #[test]
    fn test_valid_canada_sin() {
        // 046-454-286 has valid Luhn checksum
        assert!(validate_canada_sin("046454286").is_ok());
        assert!(validate_canada_sin("046-454-286").is_ok());
        assert!(validate_canada_sin("046 454 286").is_ok());
    }

    #[test]
    fn test_canada_sin_invalid_checksum() {
        let result = validate_canada_sin("123-456-789");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("Luhn")
        );
    }

    #[test]
    fn test_canada_sin_wrong_length() {
        let result = validate_canada_sin("12345678");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("9 digits")
        );
    }

    #[test]
    fn test_canada_sin_invalid_characters() {
        let result = validate_canada_sin("046X454286");
        assert!(result.is_err());
    }

    #[test]
    fn test_canada_sin_empty() {
        assert!(validate_canada_sin("").is_err());
    }

    // ========================================================================
    // validate_national_id auto-detect tests
    // ========================================================================

    #[test]
    fn test_auto_detect_uk_ni() {
        assert!(validate_national_id("AB123456C").is_ok());
    }

    #[test]
    fn test_auto_detect_canada_sin() {
        assert!(validate_national_id("046-454-286").is_ok());
    }

    #[test]
    fn test_auto_detect_generic() {
        assert!(validate_national_id("ABCD12345678").is_ok());
    }

    #[test]
    fn test_auto_detect_empty() {
        assert!(validate_national_id("").is_err());
    }

    #[test]
    fn test_generic_too_short() {
        let result = validate_national_id("AB1234");
        assert!(result.is_err());
    }

    #[test]
    fn test_generic_too_long() {
        let result = validate_national_id("ABCDEFGHIJ1234567890");
        assert!(result.is_err());
    }

    // ========================================================================
    // Luhn checksum tests
    // ========================================================================

    #[test]
    fn test_luhn_valid() {
        assert!(luhn_check("046454286"));
        assert!(luhn_check("79927398713")); // Well-known Luhn test number
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!luhn_check("123456789"));
        assert!(!luhn_check("000000001"));
    }

    // ========================================================================
    // is_test_national_id tests
    // ========================================================================

    #[test]
    fn test_known_test_patterns() {
        assert!(is_test_national_id("AA000000A"));
        assert!(is_test_national_id("ZZ999999D"));
    }

    #[test]
    fn test_all_zero_digits() {
        assert!(is_test_national_id("AB000000C"));
    }

    #[test]
    fn test_all_same_digits() {
        assert!(is_test_national_id("111111111"));
        assert!(is_test_national_id("999999999"));
    }

    #[test]
    fn test_sequential_digits() {
        assert!(is_test_national_id("123456789"));
        assert!(is_test_national_id("987654321"));
    }

    #[test]
    fn test_real_ids_not_flagged() {
        assert!(!is_test_national_id("AB123456C"));
        assert!(!is_test_national_id("046454286"));
    }

    // ========================================================================
    // Unicode edge cases
    // ========================================================================

    #[test]
    fn test_uk_ni_unicode_lookalikes() {
        // Cyrillic letters that look like Latin
        assert!(validate_uk_ni("АВ123456C").is_err()); // Cyrillic АВ
    }

    #[test]
    fn test_canada_sin_fullwidth_digits() {
        // Full-width digits
        assert!(validate_canada_sin("０４６454286").is_err());
    }
}

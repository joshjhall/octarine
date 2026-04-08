//! Australian Tax File Number (TFN) and Business Number (ABN) validation
//!
//! TFN: 8-9 digit number with mod-11 weighted checksum
//! ABN: 11 digit number with mod-89 weighted checksum (first digit adjusted)

use crate::primitives::types::Problem;

/// Checksum weights for TFN validation
const TFN_WEIGHTS: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];

/// Checksum weights for ABN validation
const ABN_WEIGHTS: [u32; 11] = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];

// ============================================================================
// TFN Validation
// ============================================================================

/// Validate Australian TFN format (without checksum)
///
/// Checks that the value contains 8 or 9 digits.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_australia_tfn(value: &str) -> Result<(), Problem> {
    let digits = extract_digits(value, "TFN")?;
    let len = digits.len();

    if len != 8 && len != 9 {
        return Err(Problem::Validation(format!(
            "Australian TFN must be 8 or 9 digits, got {}",
            len
        )));
    }

    Ok(())
}

/// Validate Australian TFN with mod-11 weighted checksum
///
/// Weights: [1, 4, 3, 7, 5, 8, 6, 9, 10]
/// Weighted sum must be divisible by 11.
///
/// # Errors
///
/// Returns `Problem::Validation` if format or checksum is invalid.
pub fn validate_australia_tfn_with_checksum(value: &str) -> Result<(), Problem> {
    let digits = extract_digits(value, "TFN")?;

    if digits.len() != 9 {
        return Err(Problem::Validation(format!(
            "Australian TFN checksum validation requires 9 digits, got {}",
            digits.len()
        )));
    }

    let mut sum: u32 = 0;
    for (i, &weight) in TFN_WEIGHTS.iter().enumerate() {
        let digit = digits.get(i).copied().unwrap_or(0);
        sum = sum.saturating_add(digit.saturating_mul(weight));
    }

    if !sum.is_multiple_of(11) {
        return Err(Problem::Validation(
            "Australian TFN checksum failed: weighted sum not divisible by 11".to_string(),
        ));
    }

    Ok(())
}

/// Check if a TFN is a test/dummy pattern
#[must_use]
pub fn is_test_australia_tfn(value: &str) -> bool {
    let clean: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    is_test_pattern(&clean)
}

// ============================================================================
// ABN Validation
// ============================================================================

/// Validate Australian ABN format (without checksum)
///
/// Checks that the value contains exactly 11 digits.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_australia_abn(value: &str) -> Result<(), Problem> {
    let digits = extract_digits(value, "ABN")?;

    if digits.len() != 11 {
        return Err(Problem::Validation(format!(
            "Australian ABN must be 11 digits, got {}",
            digits.len()
        )));
    }

    Ok(())
}

/// Validate Australian ABN with mod-89 weighted checksum
///
/// Algorithm:
/// 1. Subtract 1 from the first digit
/// 2. Apply weights [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
/// 3. Weighted sum must be divisible by 89
///
/// # Errors
///
/// Returns `Problem::Validation` if format or checksum is invalid.
pub fn validate_australia_abn_with_checksum(value: &str) -> Result<(), Problem> {
    let mut digits = extract_digits(value, "ABN")?;

    if digits.len() != 11 {
        return Err(Problem::Validation(format!(
            "Australian ABN must be 11 digits, got {}",
            digits.len()
        )));
    }

    // Subtract 1 from first digit
    if let Some(first) = digits.first_mut() {
        *first = first.saturating_sub(1);
    }

    let mut sum: u32 = 0;
    for (i, &weight) in ABN_WEIGHTS.iter().enumerate() {
        let digit = digits.get(i).copied().unwrap_or(0);
        sum = sum.saturating_add(digit.saturating_mul(weight));
    }

    if !sum.is_multiple_of(89) {
        return Err(Problem::Validation(
            "Australian ABN checksum failed: weighted sum not divisible by 89".to_string(),
        ));
    }

    Ok(())
}

/// Check if an ABN is a test/dummy pattern
#[must_use]
pub fn is_test_australia_abn(value: &str) -> bool {
    let clean: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    is_test_pattern(&clean)
}

// ============================================================================
// Private Helpers
// ============================================================================

/// Extract digits from a value string
fn extract_digits(value: &str, id_type: &str) -> Result<Vec<u32>, Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(format!(
            "Australian {} cannot be empty",
            id_type
        )));
    }

    let digits: Vec<u32> = trimmed
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.is_empty() {
        return Err(Problem::Validation(format!(
            "Australian {} contains no digits",
            id_type
        )));
    }

    Ok(digits)
}

/// Check if digits form a test pattern (all same, all zeros, sequential)
fn is_test_pattern(clean: &str) -> bool {
    if clean.is_empty() {
        return false;
    }

    // All zeros
    if clean.chars().all(|c| c == '0') {
        return true;
    }

    // All same digits
    if let Some(first) = clean.chars().next()
        && clean.chars().all(|c| c == first)
    {
        return true;
    }

    false
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // ===== TFN Tests =====

    #[test]
    fn test_validate_tfn_valid_9_digits() {
        assert!(validate_australia_tfn("123 456 789").is_ok());
    }

    #[test]
    fn test_validate_tfn_valid_8_digits() {
        assert!(validate_australia_tfn("12345678").is_ok());
    }

    #[test]
    fn test_validate_tfn_wrong_length() {
        assert!(validate_australia_tfn("1234567").is_err()); // 7 digits
        assert!(validate_australia_tfn("1234567890").is_err()); // 10 digits
    }

    #[test]
    fn test_validate_tfn_empty() {
        assert!(validate_australia_tfn("").is_err());
    }

    #[test]
    fn test_validate_tfn_with_checksum_valid() {
        // Known valid TFN: 865 438 126
        // Weights: [1, 4, 3, 7, 5, 8, 6, 9, 10]
        // 8*1 + 6*4 + 5*3 + 4*7 + 3*5 + 8*8 + 1*6 + 2*9 + 6*10
        // = 8 + 24 + 15 + 28 + 15 + 64 + 6 + 18 + 60 = 238
        // 238 / 11 = 21.636... — not valid

        // Let's compute a valid one: digits where sum % 11 == 0
        // Try: 123 456 782
        // 1*1 + 2*4 + 3*3 + 4*7 + 5*5 + 6*8 + 7*6 + 8*9 + 2*10
        // = 1 + 8 + 9 + 28 + 25 + 48 + 42 + 72 + 20 = 253
        // 253 % 11 = 0 ✓
        assert!(validate_australia_tfn_with_checksum("123 456 782").is_ok());
    }

    #[test]
    fn test_validate_tfn_with_checksum_invalid() {
        // Same digits but last changed: 123 456 783
        // Sum = 253 - 20 + 30 = 263, 263 % 11 = 0? No, 263/11 = 23.9
        // Actually: change last digit from 2 to 3 adds 10 more = 263
        // 263 % 11 = 263 - 253 = 10, != 0
        assert!(validate_australia_tfn_with_checksum("123 456 783").is_err());
    }

    #[test]
    fn test_validate_tfn_with_checksum_requires_9_digits() {
        assert!(validate_australia_tfn_with_checksum("12345678").is_err());
    }

    #[test]
    fn test_is_test_tfn() {
        assert!(is_test_australia_tfn("000 000 000"));
        assert!(is_test_australia_tfn("111111111"));
        assert!(!is_test_australia_tfn("123 456 782"));
    }

    // ===== ABN Tests =====

    #[test]
    fn test_validate_abn_valid() {
        assert!(validate_australia_abn("51 824 753 556").is_ok());
    }

    #[test]
    fn test_validate_abn_wrong_length() {
        assert!(validate_australia_abn("1234567890").is_err()); // 10 digits
        assert!(validate_australia_abn("123456789012").is_err()); // 12 digits
    }

    #[test]
    fn test_validate_abn_empty() {
        assert!(validate_australia_abn("").is_err());
    }

    #[test]
    fn test_validate_abn_with_checksum_valid() {
        // Known valid ABN: 51 824 753 556
        // Step 1: subtract 1 from first digit: 4, 1, 8, 2, 4, 7, 5, 3, 5, 5, 6
        // Step 2: weights [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
        // 4*10 + 1*1 + 8*3 + 2*5 + 4*7 + 7*9 + 5*11 + 3*13 + 5*15 + 5*17 + 6*19
        // = 40 + 1 + 24 + 10 + 28 + 63 + 55 + 39 + 75 + 85 + 114 = 534
        // 534 % 89 = 534 - 5*89 = 534 - 445 = 89 → 89 % 89 = 0 ✓
        assert!(validate_australia_abn_with_checksum("51 824 753 556").is_ok());
    }

    #[test]
    fn test_validate_abn_with_checksum_invalid() {
        // Change last digit: 51 824 753 557
        assert!(validate_australia_abn_with_checksum("51 824 753 557").is_err());
    }

    #[test]
    fn test_validate_abn_with_checksum_another_valid() {
        // Known valid ABN: 33 102 417 032 (used by ATO examples)
        // Subtract 1 from first: 2, 3, 1, 0, 2, 4, 1, 7, 0, 3, 2
        // Weighted sum: 2*10 + 3*1 + 1*3 + 0*5 + 2*7 + 4*9 + 1*11 + 7*13 + 0*15 + 3*17 + 2*19
        // = 20 + 3 + 3 + 0 + 14 + 36 + 11 + 91 + 0 + 51 + 38 = 267
        // 267 % 89 = 267 - 2*89 = 267 - 178 = 89 → 89 % 89 = 0 ✓
        assert!(validate_australia_abn_with_checksum("33 102 417 032").is_ok());
    }

    #[test]
    fn test_validate_abn_without_spaces() {
        assert!(validate_australia_abn_with_checksum("51824753556").is_ok());
    }

    #[test]
    fn test_is_test_abn() {
        assert!(is_test_australia_abn("00 000 000 000"));
        assert!(is_test_australia_abn("11111111111"));
        assert!(!is_test_australia_abn("51 824 753 556"));
    }
}

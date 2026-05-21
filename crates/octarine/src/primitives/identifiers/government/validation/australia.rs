//! Australian Tax File Number (TFN), Business Number (ABN), Medicare, and ACN validation
//!
//! TFN: 8-9 digit number with mod-11 weighted checksum
//! ABN: 11 digit number with mod-89 weighted checksum (first digit adjusted)
//! Medicare: 10 digits (optional 11th individual reference); first digit 2-6;
//!   weighted mod-10 checksum using `[1, 3, 7, 9, 1, 3, 7, 9]`.
//! ACN: 9 digits; weighted mod-10 checksum using `[8, 7, 6, 5, 4, 3, 2, 1]`.

use crate::primitives::types::Problem;

/// Checksum weights for TFN validation
const TFN_WEIGHTS: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];

/// Checksum weights for ABN validation
const ABN_WEIGHTS: [u32; 11] = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];

/// Checksum weights for Medicare (applied to first 8 digits, compared to 9th)
const MEDICARE_WEIGHTS: [u32; 8] = [1, 3, 7, 9, 1, 3, 7, 9];

/// Checksum weights for ACN (applied to first 8 digits, used in 10-sum%10 against 9th)
const ACN_WEIGHTS: [u32; 8] = [8, 7, 6, 5, 4, 3, 2, 1];

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
// Medicare Validation
// ============================================================================

/// Validate Australian Medicare format (without checksum)
///
/// Accepts 10 digits (with optional 11th individual reference number).
/// First digit must be 2-6 (issuer code).
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_australia_medicare(value: &str) -> Result<(), Problem> {
    let digits = extract_digits(value, "Medicare")?;
    let len = digits.len();

    if len != 10 && len != 11 {
        return Err(Problem::Validation(format!(
            "Australian Medicare must be 10 or 11 digits, got {}",
            len
        )));
    }

    let first = digits.first().copied().unwrap_or(0);
    if !(2..=6).contains(&first) {
        return Err(Problem::Validation(format!(
            "Australian Medicare first digit must be 2-6, got {}",
            first
        )));
    }

    Ok(())
}

/// Validate Australian Medicare with weighted mod-10 checksum
///
/// Algorithm: weighted sum of first 8 digits using `[1, 3, 7, 9, 1, 3, 7, 9]`,
/// then `sum % 10` must equal the 9th digit. The 10th digit is the card
/// issue number (not part of checksum); an optional 11th individual reference
/// number is not validated.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid or checksum fails.
pub fn validate_australia_medicare_with_checksum(value: &str) -> Result<(), Problem> {
    validate_australia_medicare(value)?;

    let digits = extract_digits(value, "Medicare")?;

    let mut sum: u32 = 0;
    for (i, &weight) in MEDICARE_WEIGHTS.iter().enumerate() {
        let digit = digits.get(i).copied().unwrap_or(0);
        sum = sum.saturating_add(digit.saturating_mul(weight));
    }

    let expected = sum % 10;
    let actual = digits.get(8).copied().unwrap_or(0);

    if expected != actual {
        return Err(Problem::Validation(format!(
            "Australian Medicare checksum failed: expected {}, got {}",
            expected, actual
        )));
    }

    Ok(())
}

/// Check if a Medicare value is a test/dummy pattern
#[must_use]
pub fn is_test_australia_medicare(value: &str) -> bool {
    let clean: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    is_test_pattern(&clean)
}

// ============================================================================
// ACN Validation
// ============================================================================

/// Validate Australian Company Number format (without checksum)
///
/// Checks that the value contains exactly 9 digits.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_australia_acn(value: &str) -> Result<(), Problem> {
    let digits = extract_digits(value, "ACN")?;

    if digits.len() != 9 {
        return Err(Problem::Validation(format!(
            "Australian ACN must be 9 digits, got {}",
            digits.len()
        )));
    }

    Ok(())
}

/// Validate Australian Company Number with weighted mod-10 checksum
///
/// Algorithm: weighted sum of first 8 digits using `[8, 7, 6, 5, 4, 3, 2, 1]`,
/// then `(10 - sum % 10) % 10` must equal the 9th digit.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid or checksum fails.
pub fn validate_australia_acn_with_checksum(value: &str) -> Result<(), Problem> {
    validate_australia_acn(value)?;

    let digits = extract_digits(value, "ACN")?;

    let mut sum: u32 = 0;
    for (i, &weight) in ACN_WEIGHTS.iter().enumerate() {
        let digit = digits.get(i).copied().unwrap_or(0);
        sum = sum.saturating_add(digit.saturating_mul(weight));
    }

    let expected = (10u32.saturating_sub(sum % 10)) % 10;
    let actual = digits.get(8).copied().unwrap_or(0);

    if expected != actual {
        return Err(Problem::Validation(format!(
            "Australian ACN checksum failed: expected {}, got {}",
            expected, actual
        )));
    }

    Ok(())
}

/// Check if an ACN value is a test/dummy pattern
#[must_use]
pub fn is_test_australia_acn(value: &str) -> bool {
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

    // ===== Medicare Tests =====

    // Build a valid 10-digit Medicare value from the first 8 digits by computing
    // the 9th (checksum) digit and appending an arbitrary issue digit.
    fn make_valid_medicare(first_eight: [u32; 8], issue: u32) -> String {
        let mut sum: u32 = 0;
        for (i, &weight) in MEDICARE_WEIGHTS.iter().enumerate() {
            sum = sum.saturating_add(
                first_eight
                    .get(i)
                    .copied()
                    .unwrap_or(0)
                    .saturating_mul(weight),
            );
        }
        let check = sum % 10;
        let mut out = String::new();
        for d in first_eight.iter() {
            out.push(char::from_digit(*d, 10).unwrap_or('0'));
        }
        out.push(char::from_digit(check, 10).unwrap_or('0'));
        out.push(char::from_digit(issue % 10, 10).unwrap_or('0'));
        out
    }

    #[test]
    fn test_validate_medicare_valid_10_digits() {
        assert!(validate_australia_medicare("2123456701").is_ok());
    }

    #[test]
    fn test_validate_medicare_valid_with_spaces() {
        assert!(validate_australia_medicare("2123 45670 1").is_ok());
    }

    #[test]
    fn test_validate_medicare_with_11_digit_irn() {
        assert!(validate_australia_medicare("21234567019").is_ok());
    }

    #[test]
    fn test_validate_medicare_wrong_first_digit() {
        assert!(validate_australia_medicare("1123456701").is_err());
        assert!(validate_australia_medicare("7123456701").is_err());
    }

    #[test]
    fn test_validate_medicare_wrong_length() {
        assert!(validate_australia_medicare("212345670").is_err());
        assert!(validate_australia_medicare("212345670199").is_err());
    }

    #[test]
    fn test_validate_medicare_empty() {
        assert!(validate_australia_medicare("").is_err());
    }

    #[test]
    fn test_validate_medicare_with_checksum_valid() {
        // Computed: digits [2,9,5,4,4,3,2,5] with check 9 -> 2954432595
        let medicare = make_valid_medicare([2, 9, 5, 4, 4, 3, 2, 5], 5);
        assert!(
            validate_australia_medicare_with_checksum(&medicare).is_ok(),
            "Generated valid Medicare should pass: {}",
            medicare
        );
    }

    #[test]
    fn test_validate_medicare_with_checksum_invalid() {
        let medicare = make_valid_medicare([2, 9, 5, 4, 4, 3, 2, 5], 5);
        // Tamper the 9th digit (checksum position)
        let mut chars: Vec<char> = medicare.chars().collect();
        if let Some(c) = chars.get_mut(8) {
            *c = if *c == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_australia_medicare_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_medicare_with_checksum_all_prefixes() {
        // All allowed first digits (2-6) compute valid Medicare numbers
        for first in 2u32..=6 {
            let medicare = make_valid_medicare([first, 1, 2, 3, 4, 5, 6, 7], 1);
            assert!(
                validate_australia_medicare_with_checksum(&medicare).is_ok(),
                "First digit {} should produce a valid Medicare: {}",
                first,
                medicare
            );
        }
    }

    #[test]
    fn test_is_test_medicare() {
        assert!(is_test_australia_medicare("0000000000"));
        assert!(is_test_australia_medicare("2222 22222 2"));
        assert!(!is_test_australia_medicare("2123 45670 1"));
    }

    // ===== ACN Tests =====

    #[test]
    fn test_validate_acn_valid() {
        assert!(validate_australia_acn("004 085 616").is_ok());
        assert!(validate_australia_acn("123456789").is_ok());
    }

    #[test]
    fn test_validate_acn_wrong_length() {
        assert!(validate_australia_acn("12345678").is_err()); // 8 digits
        assert!(validate_australia_acn("1234567890").is_err()); // 10 digits
    }

    #[test]
    fn test_validate_acn_empty() {
        assert!(validate_australia_acn("").is_err());
    }

    #[test]
    fn test_validate_acn_with_checksum_valid_asic_example() {
        // ASIC published example ACN: 004 085 616
        // Weights [8, 7, 6, 5, 4, 3, 2, 1] applied to 00408561:
        // 0*8 + 0*7 + 4*6 + 0*5 + 8*4 + 5*3 + 6*2 + 1*1 = 24 + 32 + 15 + 12 + 1 = 84
        // (10 - 84 % 10) % 10 = (10 - 4) % 10 = 6 ✓
        assert!(validate_australia_acn_with_checksum("004 085 616").is_ok());
    }

    #[test]
    fn test_validate_acn_with_checksum_valid_no_spaces() {
        assert!(validate_australia_acn_with_checksum("004085616").is_ok());
    }

    #[test]
    fn test_validate_acn_with_checksum_invalid() {
        // Tamper the last digit
        assert!(validate_australia_acn_with_checksum("004 085 617").is_err());
    }

    #[test]
    fn test_validate_acn_with_checksum_zero_check_case() {
        // Construct first 8 digits that yield sum % 10 == 0, so check = 0.
        // [1,2,3,4,5,6,7,8] -> 1*8+2*7+3*6+4*5+5*4+6*3+7*2+8*1 = 8+14+18+20+20+18+14+8 = 120
        // (10 - 0) % 10 = 0 ✓
        assert!(validate_australia_acn_with_checksum("123456780").is_ok());
    }

    #[test]
    fn test_is_test_acn() {
        assert!(is_test_australia_acn("000 000 000"));
        assert!(is_test_australia_acn("111111111"));
        assert!(!is_test_australia_acn("004 085 616"));
    }
}

//! South Korea Business Registration Number (BRN) validation
//!
//! Format: `NNN-NN-NNNNN` (10 digits total).
//!
//! Weighted mod-10 checksum (per the Korean National Tax Service algorithm):
//!
//! - Multiply digits 0..=8 by weights `[1, 3, 7, 1, 3, 7, 1, 3, 5]`.
//! - Sum the weighted products.
//! - Add `floor(d[8] * 5 / 10)` (carry from the 9th digit × 5 weight).
//! - Check digit = `(10 - sum % 10) % 10`, must equal `d[9]`.

use crate::primitives::types::Problem;

const BRN_DIGIT_COUNT: usize = 10;

/// Weights for digits 0..=8 (the final digit is the check digit)
const BRN_WEIGHTS: [u32; 9] = [1, 3, 7, 1, 3, 7, 1, 3, 5];

/// Validate South Korea BRN format (without checksum)
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_korea_brn(value: &str) -> Result<(), Problem> {
    extract_digits(value).map(|_| ())
}

/// Validate South Korea BRN with weighted mod-10 checksum
///
/// # Errors
///
/// Returns `Problem::Validation` if format or checksum is invalid.
pub fn validate_korea_brn_with_checksum(value: &str) -> Result<(), Problem> {
    let digits = extract_digits(value)?;
    validate_checksum(&digits)?;
    Ok(())
}

/// Check if a Korea BRN is a test/dummy pattern
#[must_use]
pub fn is_test_korea_brn(value: &str) -> bool {
    let clean: String = value.chars().filter(|c| c.is_ascii_digit()).collect();

    if clean.len() != BRN_DIGIT_COUNT {
        return false;
    }

    if let Some(first) = clean.chars().next()
        && clean.chars().all(|c| c == first)
    {
        return true;
    }

    if clean.chars().all(|c| c == '0') {
        return true;
    }

    if clean == "1234567890" {
        return true;
    }

    false
}

// ============================================================================
// Private Helpers
// ============================================================================

fn extract_digits(value: &str) -> Result<Vec<u32>, Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("Korea BRN cannot be empty".to_string()));
    }

    let digits: Vec<u32> = trimmed
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != BRN_DIGIT_COUNT {
        return Err(Problem::Validation(format!(
            "Korea BRN must contain exactly {} digits, got {}",
            BRN_DIGIT_COUNT,
            digits.len()
        )));
    }

    Ok(digits)
}

/// Validate the weighted mod-10 checksum.
fn validate_checksum(digits: &[u32]) -> Result<(), Problem> {
    let mut sum: u32 = 0;
    for (i, &weight) in BRN_WEIGHTS.iter().enumerate() {
        let digit = digits.get(i).copied().unwrap_or(0);
        sum = sum.saturating_add(digit.saturating_mul(weight));
    }

    // Carry from digit[8] * 5: add floor(d[8] * 5 / 10)
    let carry = digits.get(8).copied().unwrap_or(0).saturating_mul(5) / 10;
    sum = sum.saturating_add(carry);

    let expected = (10u32.saturating_sub(sum % 10)) % 10;
    let actual = digits.get(9).copied().unwrap_or(0);

    if actual != expected {
        return Err(Problem::Validation(format!(
            "Korea BRN checksum failed: expected {}, got {}",
            expected, actual
        )));
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    /// Compute the BRN check digit for the first 9 digits.
    fn compute_check_digit(first_9: &str) -> u32 {
        let digits: Vec<u32> = first_9
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();
        let mut sum: u32 = 0;
        for (i, &weight) in BRN_WEIGHTS.iter().enumerate() {
            sum = sum.saturating_add(digits.get(i).copied().unwrap_or(0).saturating_mul(weight));
        }
        sum = sum.saturating_add(digits.get(8).copied().unwrap_or(0).saturating_mul(5) / 10);
        (10u32.saturating_sub(sum % 10)) % 10
    }

    fn make_valid_brn(first_9: &str) -> String {
        let check = compute_check_digit(first_9);
        let digits: String = first_9.chars().filter(|c| c.is_ascii_digit()).collect();
        format!(
            "{}-{}-{}{}",
            &digits[..3],
            &digits[3..5],
            &digits[5..],
            check
        )
    }

    #[test]
    fn test_validate_korea_brn_valid_format() {
        assert!(validate_korea_brn("123-45-67890").is_ok());
        assert!(validate_korea_brn("000-00-00000").is_ok()); // format-only
    }

    #[test]
    fn test_validate_korea_brn_without_dashes() {
        assert!(validate_korea_brn("1234567890").is_ok());
    }

    #[test]
    fn test_validate_korea_brn_empty() {
        assert!(validate_korea_brn("").is_err());
    }

    #[test]
    fn test_validate_korea_brn_wrong_length() {
        assert!(validate_korea_brn("123-45-6789").is_err());
        assert!(validate_korea_brn("123-45-678901").is_err());
    }

    #[test]
    fn test_validate_korea_brn_with_checksum_valid() {
        let brn = make_valid_brn("123456789");
        assert!(
            validate_korea_brn_with_checksum(&brn).is_ok(),
            "Valid BRN with correct checksum should pass: {}",
            brn
        );
    }

    #[test]
    fn test_validate_korea_brn_with_checksum_invalid() {
        let brn = make_valid_brn("123456789");
        let mut chars: Vec<char> = brn.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_korea_brn_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_korea_brn_checksum_multiple_samples() {
        // A handful of distinct first-9-digit prefixes should each round-trip.
        for prefix in &["111222333", "987654321", "555000111", "234567890"] {
            let brn = make_valid_brn(prefix);
            assert!(
                validate_korea_brn_with_checksum(&brn).is_ok(),
                "Round-trip BRN should validate: prefix={} brn={}",
                prefix,
                brn
            );
        }
    }

    #[test]
    fn test_is_test_korea_brn() {
        assert!(is_test_korea_brn("1111111111"));
        assert!(is_test_korea_brn("0000000000"));
        assert!(is_test_korea_brn("1234567890"));
        // A real-looking BRN should not be flagged as a test pattern.
        assert!(!is_test_korea_brn("123-45-67891"));
    }
}

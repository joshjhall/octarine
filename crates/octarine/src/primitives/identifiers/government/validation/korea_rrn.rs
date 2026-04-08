//! South Korea Resident Registration Number (RRN) validation
//!
//! Validates Korean RRN format: YYMMDD-GNNNNNN
//! - First 6 digits: birth date (YYMMDD)
//! - 7th digit (G): gender/century code (1-8)
//! - Last 6 digits: registration sequence + check digit
//! - Weighted checksum: weights [2,3,4,5,6,7,8,9,2,3,4,5], check = (11 - sum%11) % 10

use crate::primitives::types::Problem;

/// Minimum valid RRN length (13 digits without dash)
const RRN_DIGIT_COUNT: usize = 13;

/// Checksum weights for RRN validation
const CHECKSUM_WEIGHTS: [u32; 12] = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];

/// Validate South Korea RRN format (without checksum)
///
/// Checks:
/// - Correct length and format (YYMMDD-GNNNNNN or YYMMDDGNNNNNN)
/// - Valid birth date (month 01-12, day 01-31)
/// - Valid gender/century digit (1-8)
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_korea_rrn(value: &str) -> Result<(), Problem> {
    let digits = extract_digits(value)?;

    validate_birth_date(&digits)?;
    validate_gender_digit(&digits)?;

    Ok(())
}

/// Validate South Korea RRN with weighted checksum
///
/// Performs all format checks plus checksum verification:
/// weights [2,3,4,5,6,7,8,9,2,3,4,5], check = (11 - sum%11) % 10
///
/// # Errors
///
/// Returns `Problem::Validation` if format or checksum is invalid.
pub fn validate_korea_rrn_with_checksum(value: &str) -> Result<(), Problem> {
    let digits = extract_digits(value)?;

    validate_birth_date(&digits)?;
    validate_gender_digit(&digits)?;
    validate_checksum(&digits)?;

    Ok(())
}

/// Check if a Korea RRN is a test/dummy pattern
///
/// Returns true for patterns like all-zeros, all-same, or sequential digits.
#[must_use]
pub fn is_test_korea_rrn(value: &str) -> bool {
    let clean: String = value.chars().filter(|c| c.is_ascii_digit()).collect();

    if clean.len() != RRN_DIGIT_COUNT {
        return false;
    }

    // All same digits
    if let Some(first) = clean.chars().next()
        && clean.chars().all(|c| c == first)
    {
        return true;
    }

    // All zeros
    if clean.chars().all(|c| c == '0') {
        return true;
    }

    // Sequential patterns
    if clean == "1234567890123" {
        return true;
    }

    false
}

// ============================================================================
// Private Helpers
// ============================================================================

/// Extract exactly 13 digits from an RRN string, stripping optional dash
fn extract_digits(value: &str) -> Result<Vec<u32>, Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("Korea RRN cannot be empty".to_string()));
    }

    let digits: Vec<u32> = trimmed
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != RRN_DIGIT_COUNT {
        return Err(Problem::Validation(format!(
            "Korea RRN must contain exactly {} digits, got {}",
            RRN_DIGIT_COUNT,
            digits.len()
        )));
    }

    Ok(digits)
}

/// Validate birth date portion (first 6 digits: YYMMDD)
fn validate_birth_date(digits: &[u32]) -> Result<(), Problem> {
    let month = digits
        .get(2)
        .copied()
        .unwrap_or(0)
        .saturating_mul(10)
        .saturating_add(digits.get(3).copied().unwrap_or(0));
    let day = digits
        .get(4)
        .copied()
        .unwrap_or(0)
        .saturating_mul(10)
        .saturating_add(digits.get(5).copied().unwrap_or(0));

    if !(1..=12).contains(&month) {
        return Err(Problem::Validation(format!(
            "Korea RRN birth month must be 01-12, got {:02}",
            month
        )));
    }

    if !(1..=31).contains(&day) {
        return Err(Problem::Validation(format!(
            "Korea RRN birth day must be 01-31, got {:02}",
            day
        )));
    }

    Ok(())
}

/// Validate gender/century digit (7th digit, index 6)
fn validate_gender_digit(digits: &[u32]) -> Result<(), Problem> {
    let gender = digits.get(6).copied().unwrap_or(0);

    if !(1..=8).contains(&gender) {
        return Err(Problem::Validation(format!(
            "Korea RRN gender/century digit must be 1-8, got {}",
            gender
        )));
    }

    Ok(())
}

/// Validate weighted checksum
///
/// Sum = Σ(digit[i] * weight[i]) for i = 0..11
/// Check digit = (11 - sum % 11) % 10
/// Must equal digit[12]
fn validate_checksum(digits: &[u32]) -> Result<(), Problem> {
    let mut sum: u32 = 0;
    for (i, &weight) in CHECKSUM_WEIGHTS.iter().enumerate() {
        let digit = digits.get(i).copied().unwrap_or(0);
        sum = sum.saturating_add(digit.saturating_mul(weight));
    }

    let expected = (11u32.saturating_sub(sum % 11)) % 10;
    let actual = digits.get(12).copied().unwrap_or(0);

    if actual != expected {
        return Err(Problem::Validation(format!(
            "Korea RRN checksum failed: expected {}, got {}",
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

    // Helper to generate a valid RRN with correct checksum
    fn compute_check_digit(first_12: &str) -> u32 {
        let digits: Vec<u32> = first_12
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();
        let mut sum: u32 = 0;
        for (i, &weight) in CHECKSUM_WEIGHTS.iter().enumerate() {
            sum = sum.saturating_add(digits.get(i).copied().unwrap_or(0).saturating_mul(weight));
        }
        (11u32.saturating_sub(sum % 11)) % 10
    }

    fn make_valid_rrn(first_12: &str) -> String {
        let check = compute_check_digit(first_12);
        let digits: String = first_12.chars().filter(|c| c.is_ascii_digit()).collect();
        format!("{}-{}{}", &digits[..6], &digits[6..], check)
    }

    #[test]
    fn test_validate_korea_rrn_valid_format() {
        // Male born 1990-01-15, gender digit 1 (1900s male)
        assert!(validate_korea_rrn("900115-1234567").is_ok());
    }

    #[test]
    fn test_validate_korea_rrn_all_gender_codes() {
        // Gender/century codes 1-8
        for code in 1..=8 {
            let rrn = format!("900115-{}234567", code);
            assert!(
                validate_korea_rrn(&rrn).is_ok(),
                "Gender code {} should be valid",
                code
            );
        }
    }

    #[test]
    fn test_validate_korea_rrn_invalid_gender_code() {
        assert!(validate_korea_rrn("900115-0234567").is_err());
        assert!(validate_korea_rrn("900115-9234567").is_err());
    }

    #[test]
    fn test_validate_korea_rrn_invalid_month() {
        assert!(validate_korea_rrn("901315-1234567").is_err()); // Month 13
        assert!(validate_korea_rrn("900015-1234567").is_err()); // Month 00
    }

    #[test]
    fn test_validate_korea_rrn_invalid_day() {
        assert!(validate_korea_rrn("900132-1234567").is_err()); // Day 32
        assert!(validate_korea_rrn("900100-1234567").is_err()); // Day 00
    }

    #[test]
    fn test_validate_korea_rrn_without_dash() {
        assert!(validate_korea_rrn("9001151234567").is_ok());
    }

    #[test]
    fn test_validate_korea_rrn_empty() {
        assert!(validate_korea_rrn("").is_err());
    }

    #[test]
    fn test_validate_korea_rrn_wrong_length() {
        assert!(validate_korea_rrn("900115-123456").is_err()); // Too short
        assert!(validate_korea_rrn("900115-12345678").is_err()); // Too long
    }

    #[test]
    fn test_validate_korea_rrn_with_checksum_valid() {
        // Generate a valid RRN with correct checksum
        let rrn = make_valid_rrn("900115-123456");
        assert!(
            validate_korea_rrn_with_checksum(&rrn).is_ok(),
            "Valid RRN with correct checksum should pass: {}",
            rrn
        );
    }

    #[test]
    fn test_validate_korea_rrn_with_checksum_invalid() {
        // Use a known RRN but tamper with the check digit
        let rrn = make_valid_rrn("900115-123456");
        // Change the last digit to something different
        let mut chars: Vec<char> = rrn.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_korea_rrn_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_korea_rrn_with_checksum_2000s_male() {
        // Male born 2000-03-20, gender digit 3
        let rrn = make_valid_rrn("000320-312345");
        assert!(validate_korea_rrn_with_checksum(&rrn).is_ok());
    }

    #[test]
    fn test_validate_korea_rrn_with_checksum_2000s_female() {
        // Female born 2005-11-28, gender digit 4
        let rrn = make_valid_rrn("051128-456789");
        assert!(validate_korea_rrn_with_checksum(&rrn).is_ok());
    }

    #[test]
    fn test_validate_korea_rrn_with_checksum_foreign() {
        // Foreign 1900s male, gender digit 5
        let rrn = make_valid_rrn("850715-567890");
        assert!(validate_korea_rrn_with_checksum(&rrn).is_ok());
    }

    #[test]
    fn test_is_test_korea_rrn() {
        assert!(is_test_korea_rrn("1111111111111"));
        assert!(is_test_korea_rrn("0000000000000"));
        assert!(is_test_korea_rrn("1234567890123"));
        assert!(!is_test_korea_rrn("900115-1234567"));
    }

    #[test]
    fn test_is_test_korea_rrn_wrong_length() {
        assert!(!is_test_korea_rrn("12345"));
        assert!(!is_test_korea_rrn(""));
    }
}

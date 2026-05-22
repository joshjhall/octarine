//! South Korea Foreign Registration Number (FRN) validation
//!
//! Same format as RRN (`YYMMDD-GNNNNNN`) but for foreigners — gender/century
//! digit is 5-8. Reuses the RRN weighted checksum verbatim:
//! weights `[2,3,4,5,6,7,8,9,2,3,4,5]`, check digit `(11 - sum%11) % 10`.

use crate::primitives::types::Problem;

/// Minimum valid FRN length (13 digits without dash)
const FRN_DIGIT_COUNT: usize = 13;

/// Checksum weights for FRN validation (identical to RRN — see korea_rrn.rs)
const CHECKSUM_WEIGHTS: [u32; 12] = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];

/// Validate South Korea FRN format (without checksum)
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_korea_frn(value: &str) -> Result<(), Problem> {
    let digits = extract_digits(value)?;

    validate_birth_date(&digits)?;
    validate_gender_digit(&digits)?;

    Ok(())
}

/// Validate South Korea FRN with weighted checksum
///
/// # Errors
///
/// Returns `Problem::Validation` if format or checksum is invalid.
pub fn validate_korea_frn_with_checksum(value: &str) -> Result<(), Problem> {
    let digits = extract_digits(value)?;

    validate_birth_date(&digits)?;
    validate_gender_digit(&digits)?;
    validate_checksum(&digits)?;

    Ok(())
}

/// Check if a Korea FRN is a test/dummy pattern
#[must_use]
pub fn is_test_korea_frn(value: &str) -> bool {
    let clean: String = value.chars().filter(|c| c.is_ascii_digit()).collect();

    if clean.len() != FRN_DIGIT_COUNT {
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

    if clean == "1234567890123" {
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
        return Err(Problem::Validation("Korea FRN cannot be empty".to_string()));
    }

    let digits: Vec<u32> = trimmed
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != FRN_DIGIT_COUNT {
        return Err(Problem::Validation(format!(
            "Korea FRN must contain exactly {} digits, got {}",
            FRN_DIGIT_COUNT,
            digits.len()
        )));
    }

    Ok(digits)
}

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
            "Korea FRN birth month must be 01-12, got {:02}",
            month
        )));
    }

    if !(1..=31).contains(&day) {
        return Err(Problem::Validation(format!(
            "Korea FRN birth day must be 01-31, got {:02}",
            day
        )));
    }

    Ok(())
}

/// Validate gender/century digit (7th digit, index 6) — must be 5-8 for FRN
fn validate_gender_digit(digits: &[u32]) -> Result<(), Problem> {
    let gender = digits.get(6).copied().unwrap_or(0);

    if !(5..=8).contains(&gender) {
        return Err(Problem::Validation(format!(
            "Korea FRN gender/century digit must be 5-8 (use korea_rrn for 1-4), got {}",
            gender
        )));
    }

    Ok(())
}

/// Validate weighted checksum (identical algorithm to RRN)
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
            "Korea FRN checksum failed: expected {}, got {}",
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

    fn make_valid_frn(first_12: &str) -> String {
        let check = compute_check_digit(first_12);
        let digits: String = first_12.chars().filter(|c| c.is_ascii_digit()).collect();
        format!("{}-{}{}", &digits[..6], &digits[6..], check)
    }

    #[test]
    fn test_validate_korea_frn_valid_format() {
        // Foreign male born 1990-01-15, gender digit 5
        assert!(validate_korea_frn("900115-5234567").is_ok());
    }

    #[test]
    fn test_validate_korea_frn_all_gender_codes() {
        for code in 5..=8 {
            let frn = format!("900115-{}234567", code);
            assert!(
                validate_korea_frn(&frn).is_ok(),
                "Gender code {} should be valid",
                code
            );
        }
    }

    #[test]
    fn test_validate_korea_frn_rejects_rrn_gender_codes() {
        // Citizen codes 1-4 belong to RRN, not FRN
        for code in 1..=4 {
            let frn = format!("900115-{}234567", code);
            assert!(
                validate_korea_frn(&frn).is_err(),
                "Gender code {} is RRN and must be rejected by FRN validator",
                code
            );
        }
    }

    #[test]
    fn test_validate_korea_frn_invalid_gender_code() {
        assert!(validate_korea_frn("900115-0234567").is_err());
        assert!(validate_korea_frn("900115-9234567").is_err());
    }

    #[test]
    fn test_validate_korea_frn_invalid_month() {
        assert!(validate_korea_frn("901315-5234567").is_err());
        assert!(validate_korea_frn("900015-5234567").is_err());
    }

    #[test]
    fn test_validate_korea_frn_invalid_day() {
        assert!(validate_korea_frn("900132-5234567").is_err());
        assert!(validate_korea_frn("900100-5234567").is_err());
    }

    #[test]
    fn test_validate_korea_frn_without_dash() {
        assert!(validate_korea_frn("9001155234567").is_ok());
    }

    #[test]
    fn test_validate_korea_frn_empty() {
        assert!(validate_korea_frn("").is_err());
    }

    #[test]
    fn test_validate_korea_frn_wrong_length() {
        assert!(validate_korea_frn("900115-523456").is_err());
        assert!(validate_korea_frn("900115-52345678").is_err());
    }

    #[test]
    fn test_validate_korea_frn_with_checksum_valid() {
        let frn = make_valid_frn("900115-523456");
        assert!(
            validate_korea_frn_with_checksum(&frn).is_ok(),
            "Valid FRN with correct checksum should pass: {}",
            frn
        );
    }

    #[test]
    fn test_validate_korea_frn_with_checksum_invalid() {
        let frn = make_valid_frn("900115-523456");
        let mut chars: Vec<char> = frn.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_korea_frn_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_korea_frn_with_checksum_2000s_foreigner() {
        // Foreign 2000s male, gender digit 7
        let frn = make_valid_frn("000320-712345");
        assert!(validate_korea_frn_with_checksum(&frn).is_ok());
    }

    #[test]
    fn test_is_test_korea_frn() {
        assert!(is_test_korea_frn("5555555555555"));
        assert!(is_test_korea_frn("0000000000000"));
        assert!(is_test_korea_frn("1234567890123"));
        assert!(!is_test_korea_frn("900115-5234567"));
    }

    #[test]
    fn test_is_test_korea_frn_wrong_length() {
        assert!(!is_test_korea_frn("12345"));
        assert!(!is_test_korea_frn(""));
    }
}

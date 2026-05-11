//! Thailand TNIN (National Identification Number) validation
//!
//! Format: 13 digits. Display form `N-NNNN-NNNNN-NN-N`.
//!
//! Check digit algorithm: sum `d[i] * (13 - i)` for `i` in 0..12 (weights
//! 13, 12, …, 2), then `check = (11 - sum % 11) % 10`.

use crate::primitives::types::Problem;

/// Validate Thailand TNIN format (without checksum)
///
/// Checks: 13 digits, not all the same digit.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_thailand_tnin(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("TNIN cannot be empty".to_string()));
    }

    for ch in trimmed.chars() {
        if !ch.is_ascii_digit() && !matches!(ch, '-' | ' ' | '\t') {
            return Err(Problem::Validation(format!(
                "invalid character '{ch}' in TNIN"
            )));
        }
    }

    let digits: Vec<u8> = trimmed
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();

    if digits.len() != 13 {
        return Err(Problem::Validation(format!(
            "TNIN must be 13 digits, got {}",
            digits.len()
        )));
    }

    if all_same_digit(&digits) {
        return Err(Problem::Validation(
            "TNIN cannot have all identical digits".to_string(),
        ));
    }

    Ok(())
}

/// Validate Thailand TNIN with mod-11 weighted-sum check digit
///
/// # Errors
///
/// Returns `Problem::Validation` if the format or checksum is invalid.
pub fn validate_thailand_tnin_with_checksum(value: &str) -> Result<(), Problem> {
    validate_thailand_tnin(value)?;

    let digits: Vec<u8> = value
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();

    let computed = compute_tnin_check_digit(digits.get(..12).unwrap_or(&[]));
    let actual = digits.get(12).copied().unwrap_or(99);

    if computed != actual {
        return Err(Problem::Validation(format!(
            "TNIN check digit mismatch: expected {computed}, got {actual}"
        )));
    }

    Ok(())
}

/// Check if a TNIN is a test/dummy pattern (all-same-digit)
#[must_use]
pub fn is_test_thailand_tnin(value: &str) -> bool {
    let digits: Vec<u8> = value
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    digits.len() == 13 && all_same_digit(&digits)
}

// ============================================================================
// Helpers
// ============================================================================

fn all_same_digit(digits: &[u8]) -> bool {
    digits
        .first()
        .is_some_and(|&first| digits.iter().all(|&d| d == first))
}

/// Compute the TNIN check digit from the first 12 digits.
fn compute_tnin_check_digit(first_12: &[u8]) -> u8 {
    let mut sum: u32 = 0;
    for (i, &d) in first_12.iter().enumerate() {
        let weight = 13_u32.saturating_sub(i as u32);
        sum = sum.saturating_add(u32::from(d).saturating_mul(weight));
    }
    let r = sum.checked_rem(11).unwrap_or(0);
    let check = 11_u32.saturating_sub(r).checked_rem(10).unwrap_or(0);
    u8::try_from(check).unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_valid_tnin(first_12: &str) -> String {
        let digits: Vec<u8> = first_12
            .chars()
            .filter_map(|c| c.to_digit(10).map(|d| d as u8))
            .collect();
        assert_eq!(digits.len(), 12, "make_valid_tnin needs 12 digits");
        let check = compute_tnin_check_digit(&digits);
        let mut all = digits.clone();
        all.push(check);
        all.iter()
            .map(|d| char::from_digit(u32::from(*d), 10).unwrap_or('0'))
            .collect()
    }

    // ===== Format Tests =====

    #[test]
    fn test_validate_tnin_valid_unformatted() {
        let tnin = make_valid_tnin("123456789012");
        assert!(validate_thailand_tnin(&tnin).is_ok());
    }

    #[test]
    fn test_validate_tnin_valid_with_dashes() {
        let tnin = make_valid_tnin("123456789012");
        // Insert dashes in display form: N-NNNN-NNNNN-NN-N
        let formatted = format!(
            "{}-{}-{}-{}-{}",
            &tnin[..1],
            &tnin[1..5],
            &tnin[5..10],
            &tnin[10..12],
            &tnin[12..]
        );
        assert!(validate_thailand_tnin(&formatted).is_ok());
    }

    #[test]
    fn test_validate_tnin_rejects_wrong_length() {
        assert!(validate_thailand_tnin("1234567890").is_err());
        assert!(validate_thailand_tnin("12345678901234").is_err());
    }

    #[test]
    fn test_validate_tnin_rejects_empty() {
        assert!(validate_thailand_tnin("").is_err());
    }

    #[test]
    fn test_validate_tnin_rejects_letters() {
        assert!(validate_thailand_tnin("123456789abcd").is_err());
    }

    #[test]
    fn test_validate_tnin_rejects_all_same() {
        assert!(validate_thailand_tnin("1111111111111").is_err());
    }

    // ===== Checksum Tests =====

    #[test]
    fn test_validate_tnin_with_checksum_generated() {
        let tnin = make_valid_tnin("123456789012");
        assert!(
            validate_thailand_tnin_with_checksum(&tnin).is_ok(),
            "Generated TNIN {tnin} should validate"
        );
    }

    #[test]
    fn test_validate_tnin_with_checksum_tampered() {
        let tnin = make_valid_tnin("123456789012");
        let mut chars: Vec<char> = tnin.chars().collect();
        if let Some(c) = chars.last_mut() {
            *c = if *c == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_thailand_tnin_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_tnin_with_checksum_multiple_seeds() {
        for seed in &["123456789012", "987654321098", "111222333444"] {
            let tnin = make_valid_tnin(seed);
            assert!(
                validate_thailand_tnin_with_checksum(&tnin).is_ok(),
                "Generated TNIN {tnin} from seed {seed} should validate"
            );
        }
    }

    // ===== Test Pattern Tests =====

    #[test]
    fn test_is_test_thailand_tnin_all_same() {
        assert!(is_test_thailand_tnin("1111111111111"));
        assert!(is_test_thailand_tnin("0000000000000"));
    }

    #[test]
    fn test_is_test_thailand_tnin_rejects_real() {
        let tnin = make_valid_tnin("123456789012");
        assert!(!is_test_thailand_tnin(&tnin));
    }

    #[test]
    fn test_is_test_thailand_tnin_rejects_wrong_length() {
        assert!(!is_test_thailand_tnin("111"));
    }
}

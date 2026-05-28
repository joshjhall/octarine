//! Turkey identifier validation — TCKN (T.C. Kimlik Numarası) and license plate.
//!
//! # TCKN — Turkish National ID
//!
//! Format: 11 digits. First digit must not be `0`.
//!
//! NVI mod-10 dual-check-digit algorithm:
//! - Digit 10 = `(((d1+d3+d5+d7+d9) * 7) - (d2+d4+d6+d8)) mod 10`
//! - Digit 11 = `(d1 + d2 + … + d10) mod 10`
//!
//! # License plate
//!
//! Format: `<province 01-81><1-3 letters from A-PR-VY-Z><2-4 digits>`, with
//! optional spaces or hyphens between groups. Letters `Q`, `W`, `X` are
//! reserved and not assigned. Example: `34 ABC 123` (Istanbul = 34).

use crate::primitives::types::Problem;

/// Validate Turkey TCKN format (without checksum)
///
/// Checks: 11 digits, leading digit non-zero, not all identical digits.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_turkey_tckn(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("TCKN cannot be empty".to_string()));
    }

    for ch in trimmed.chars() {
        if !ch.is_ascii_digit() && !matches!(ch, '-' | ' ' | '\t') {
            return Err(Problem::Validation(format!(
                "invalid character '{ch}' in TCKN"
            )));
        }
    }

    let digits: Vec<u8> = trimmed
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();

    if digits.len() != 11 {
        return Err(Problem::Validation(format!(
            "TCKN must be 11 digits, got {}",
            digits.len()
        )));
    }

    if digits.first().copied() == Some(0) {
        return Err(Problem::Validation(
            "TCKN first digit cannot be 0".to_string(),
        ));
    }

    if all_same_digit(&digits) {
        return Err(Problem::Validation(
            "TCKN cannot have all identical digits".to_string(),
        ));
    }

    Ok(())
}

/// Validate Turkey TCKN with NVI mod-10 dual-check-digit verification
///
/// # Errors
///
/// Returns `Problem::Validation` if the format or either check digit fails.
pub fn validate_turkey_tckn_with_checksum(value: &str) -> Result<(), Problem> {
    validate_turkey_tckn(value)?;

    let digits: Vec<u8> = value
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();

    let (computed_10, computed_11) = compute_tckn_check_digits(digits.get(..9).unwrap_or(&[]));
    let actual_10 = digits.get(9).copied().unwrap_or(99);
    let actual_11 = digits.get(10).copied().unwrap_or(99);

    if computed_10 != actual_10 {
        return Err(Problem::Validation(format!(
            "TCKN 10th check digit mismatch: expected {computed_10}, got {actual_10}"
        )));
    }

    if computed_11 != actual_11 {
        return Err(Problem::Validation(format!(
            "TCKN 11th check digit mismatch: expected {computed_11}, got {actual_11}"
        )));
    }

    Ok(())
}

/// Check if a TCKN is a test/dummy pattern (all-same-digit). Used to skip
/// generated placeholders in fixtures and audit logs.
#[must_use]
pub fn is_test_turkey_tckn(value: &str) -> bool {
    let digits: Vec<u8> = value
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    digits.len() == 11 && all_same_digit(&digits)
}

/// Validate Turkey license plate format
///
/// Format: `<province 01-81>[\s\-]?<1-3 letters from A-PR-VY-Z>[\s\-]?<2-4 digits>`.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_turkey_license_plate(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "license plate cannot be empty".to_string(),
        ));
    }

    let upper = trimmed.to_ascii_uppercase();
    let compact: String = upper
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '-'))
        .collect();

    let bytes = compact.as_bytes();
    if bytes.len() < 5 || bytes.len() > 10 {
        return Err(Problem::Validation(format!(
            "license plate must be 5-10 chars (excluding separators), got {}",
            bytes.len()
        )));
    }

    // First two chars: province digits.
    let province_digits = compact.get(..2).unwrap_or("");
    let province: u32 = province_digits
        .parse()
        .map_err(|_| Problem::Validation("license plate must start with 2 digits".to_string()))?;
    if !(1..=81).contains(&province) {
        return Err(Problem::Validation(format!(
            "license plate province must be 01-81, got {province:02}"
        )));
    }

    // Middle: 1-3 letters from valid class. Then 2-4 trailing digits.
    let rest = compact.get(2..).unwrap_or("");
    let letter_count = rest.chars().take_while(|c| c.is_ascii_alphabetic()).count();
    if !(1..=3).contains(&letter_count) {
        return Err(Problem::Validation(format!(
            "license plate must have 1-3 letters after province, got {letter_count}"
        )));
    }

    let letters = rest.get(..letter_count).unwrap_or("");
    for ch in letters.chars() {
        if matches!(ch, 'Q' | 'W' | 'X') {
            return Err(Problem::Validation(format!(
                "license plate letter '{ch}' is reserved (Q/W/X not assigned)"
            )));
        }
        if !ch.is_ascii_uppercase() {
            return Err(Problem::Validation(format!(
                "license plate letter '{ch}' must be A-Z"
            )));
        }
    }

    let trailing = rest.get(letter_count..).unwrap_or("");
    if !(2..=4).contains(&trailing.len()) {
        return Err(Problem::Validation(format!(
            "license plate must end with 2-4 digits, got {}",
            trailing.len()
        )));
    }
    if !trailing.chars().all(|c| c.is_ascii_digit()) {
        return Err(Problem::Validation(
            "license plate trailing group must be digits".to_string(),
        ));
    }

    Ok(())
}

// ============================================================================
// Helpers
// ============================================================================

fn all_same_digit(digits: &[u8]) -> bool {
    digits
        .first()
        .is_some_and(|&first| digits.iter().all(|&d| d == first))
}

/// Compute the TCKN 10th and 11th check digits from the first 9 digits.
///
/// Algorithm (NVI):
/// - `d10 = (((d1+d3+d5+d7+d9) * 7) - (d2+d4+d6+d8)) mod 10`
/// - `d11 = (d1 + d2 + … + d10) mod 10`
fn compute_tckn_check_digits(first_9: &[u8]) -> (u8, u8) {
    if first_9.len() != 9 {
        return (99, 99);
    }

    let mut odd_sum: u32 = 0; // d1, d3, d5, d7, d9 (1-indexed odd)
    let mut even_sum: u32 = 0; // d2, d4, d6, d8 (1-indexed even)
    for (i, &d) in first_9.iter().enumerate() {
        // 0-indexed: i=0 is d1 (odd), i=1 is d2 (even)
        if i.checked_rem(2).unwrap_or(0) == 0 {
            odd_sum = odd_sum.saturating_add(u32::from(d));
        } else {
            even_sum = even_sum.saturating_add(u32::from(d));
        }
    }

    let weighted = odd_sum.saturating_mul(7);
    // Use modular arithmetic to avoid underflow: (weighted - even_sum) mod 10.
    // Add 10 * even_sum to keep the dividend non-negative (10 is the modulus).
    let dividend = weighted.saturating_add(even_sum.saturating_mul(9));
    let d10 = u8::try_from(dividend.checked_rem(10).unwrap_or(0)).unwrap_or(0);

    // d11 = (d1 + d2 + … + d10) mod 10
    let first_9_sum: u32 = first_9.iter().map(|&d| u32::from(d)).sum();
    let total = first_9_sum.saturating_add(u32::from(d10));
    let d11 = u8::try_from(total.checked_rem(10).unwrap_or(0)).unwrap_or(0);

    (d10, d11)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_valid_tckn(first_9: &str) -> String {
        let digits: Vec<u8> = first_9
            .chars()
            .filter_map(|c| c.to_digit(10).map(|d| d as u8))
            .collect();
        assert_eq!(digits.len(), 9, "make_valid_tckn needs 9 digits");
        assert!(digits.first().copied() != Some(0), "first digit non-zero");
        let (d10, d11) = compute_tckn_check_digits(&digits);
        let mut all = digits.clone();
        all.push(d10);
        all.push(d11);
        all.iter()
            .map(|d| char::from_digit(u32::from(*d), 10).unwrap_or('0'))
            .collect()
    }

    // ===== TCKN format tests =====

    #[test]
    fn test_validate_tckn_valid_unformatted() {
        let tckn = make_valid_tckn("123456789");
        assert!(validate_turkey_tckn(&tckn).is_ok());
    }

    #[test]
    fn test_validate_tckn_rejects_wrong_length() {
        assert!(validate_turkey_tckn("1234567890").is_err()); // 10
        assert!(validate_turkey_tckn("123456789012").is_err()); // 12
    }

    #[test]
    fn test_validate_tckn_rejects_empty() {
        assert!(validate_turkey_tckn("").is_err());
    }

    #[test]
    fn test_validate_tckn_rejects_letters() {
        assert!(validate_turkey_tckn("1234567890a").is_err());
    }

    #[test]
    fn test_validate_tckn_rejects_leading_zero() {
        // 11 digits starting with 0 — must reject regardless of checksum
        assert!(validate_turkey_tckn("01234567890").is_err());
    }

    #[test]
    fn test_validate_tckn_rejects_all_same() {
        assert!(validate_turkey_tckn("11111111111").is_err());
    }

    // ===== TCKN checksum tests =====

    #[test]
    fn test_validate_tckn_with_checksum_generated() {
        let tckn = make_valid_tckn("123456789");
        assert!(
            validate_turkey_tckn_with_checksum(&tckn).is_ok(),
            "Generated TCKN {tckn} should validate"
        );
    }

    #[test]
    fn test_validate_tckn_with_checksum_tampered_last() {
        let tckn = make_valid_tckn("123456789");
        let mut chars: Vec<char> = tckn.chars().collect();
        if let Some(c) = chars.last_mut() {
            *c = if *c == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_turkey_tckn_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_tckn_with_checksum_tampered_tenth() {
        let tckn = make_valid_tckn("123456789");
        let mut chars: Vec<char> = tckn.chars().collect();
        if let Some(c) = chars.get_mut(9) {
            *c = if *c == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_turkey_tckn_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_tckn_with_checksum_multiple_seeds() {
        for seed in &["123456789", "987654321", "111222333"] {
            let tckn = make_valid_tckn(seed);
            assert!(
                validate_turkey_tckn_with_checksum(&tckn).is_ok(),
                "Generated TCKN {tckn} from seed {seed} should validate"
            );
        }
    }

    // ===== Test-pattern tests =====

    #[test]
    fn test_is_test_turkey_tckn_all_same() {
        assert!(is_test_turkey_tckn("11111111111"));
        assert!(is_test_turkey_tckn("00000000000"));
    }

    #[test]
    fn test_is_test_turkey_tckn_rejects_real() {
        let tckn = make_valid_tckn("123456789");
        assert!(!is_test_turkey_tckn(&tckn));
    }

    #[test]
    fn test_is_test_turkey_tckn_rejects_wrong_length() {
        assert!(!is_test_turkey_tckn("111"));
    }

    // ===== License plate tests =====

    #[test]
    fn test_validate_plate_valid_spaced() {
        assert!(validate_turkey_license_plate("34 ABC 123").is_ok());
    }

    #[test]
    fn test_validate_plate_valid_compact() {
        assert!(validate_turkey_license_plate("34ABC123").is_ok());
    }

    #[test]
    fn test_validate_plate_valid_short_letters() {
        assert!(validate_turkey_license_plate("06 A 12").is_ok());
        assert!(validate_turkey_license_plate("81 ZZ 99").is_ok());
    }

    #[test]
    fn test_validate_plate_valid_long_digits() {
        assert!(validate_turkey_license_plate("34 ABC 1234").is_ok());
    }

    #[test]
    fn test_validate_plate_rejects_province_zero() {
        assert!(validate_turkey_license_plate("00 ABC 123").is_err());
    }

    #[test]
    fn test_validate_plate_rejects_province_too_high() {
        assert!(validate_turkey_license_plate("82 ABC 123").is_err());
        assert!(validate_turkey_license_plate("99 ABC 123").is_err());
    }

    #[test]
    fn test_validate_plate_rejects_reserved_letters() {
        assert!(validate_turkey_license_plate("34 QBC 123").is_err());
        assert!(validate_turkey_license_plate("34 WBC 123").is_err());
        assert!(validate_turkey_license_plate("34 XBC 123").is_err());
    }

    #[test]
    fn test_validate_plate_rejects_too_few_digits() {
        assert!(validate_turkey_license_plate("34 ABC 1").is_err());
    }

    #[test]
    fn test_validate_plate_rejects_too_many_digits() {
        assert!(validate_turkey_license_plate("34 ABC 12345").is_err());
    }

    #[test]
    fn test_validate_plate_rejects_too_many_letters() {
        assert!(validate_turkey_license_plate("34 ABCD 123").is_err());
    }

    #[test]
    fn test_validate_plate_rejects_empty() {
        assert!(validate_turkey_license_plate("").is_err());
    }
}

//! Poland PESEL (Powszechny Elektroniczny System Ewidencji Ludności) validation
//!
//! Format: YYMMDDNNNCC (11 digits)
//! - YY: year (00-99)
//! - MM: month with century encoding (01-12 for 1900s, 21-32 for 2000s,
//!   41-52 for 2100s, 61-72 for 2200s, 81-92 for 1800s)
//! - DD: day (01-31)
//! - NNN: serial number (odd=male, even=female)
//! - C: checksum digit
//! - Weights: [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
//! - Check digit: (10 - (weighted_sum % 10)) % 10

use crate::primitives::types::Problem;

/// Weights for PESEL checksum calculation
const WEIGHTS: [u32; 10] = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];

// ============================================================================
// Validation
// ============================================================================

/// Validate Poland PESEL format (without checksum)
///
/// Checks: correct length, all digits, valid birth date with century encoding.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_poland_pesel(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Poland PESEL cannot be empty".to_string(),
        ));
    }

    if trimmed.len() != 11 {
        return Err(Problem::Validation(format!(
            "Poland PESEL must be 11 digits, got {} characters",
            trimmed.len()
        )));
    }

    let chars: Vec<char> = trimmed.chars().collect();

    // All characters must be digits
    for (i, &ch) in chars.iter().enumerate() {
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "Poland PESEL position {} must be a digit, got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    // Validate birth date with century encoding
    let month_raw = parse_two_digits(&chars, 2)?;
    let day = parse_two_digits(&chars, 4)?;

    // Decode century-encoded month
    let month = decode_month(month_raw)?;

    if !(1..=12).contains(&month) {
        return Err(Problem::Validation(format!(
            "Poland PESEL decoded month must be 01-12, got {:02}",
            month
        )));
    }

    if !(1..=31).contains(&day) {
        return Err(Problem::Validation(format!(
            "Poland PESEL day must be 01-31, got {:02}",
            day
        )));
    }

    Ok(())
}

/// Validate Poland PESEL with weighted checksum
///
/// Uses weights [1, 3, 7, 9, 1, 3, 7, 9, 1, 3] on first 10 digits.
/// Check digit = (10 - (weighted_sum % 10)) % 10
///
/// # Errors
///
/// Returns `Problem::Validation` if format or checksum is invalid.
pub fn validate_poland_pesel_with_checksum(value: &str) -> Result<(), Problem> {
    validate_poland_pesel(value)?;

    let trimmed = value.trim();
    let digits: Vec<u32> = trimmed.chars().filter_map(|c| c.to_digit(10)).collect();

    if digits.len() != 11 {
        return Err(Problem::Validation(
            "Poland PESEL: failed to parse digits".to_string(),
        ));
    }

    let weighted_sum: u32 = digits
        .iter()
        .take(10)
        .zip(WEIGHTS.iter())
        .map(|(d, w)| d.saturating_mul(*w))
        .fold(0u32, |acc, x| acc.saturating_add(x));

    let expected = (10u32.saturating_sub(weighted_sum % 10)) % 10;
    let actual = digits.get(10).copied().unwrap_or(0);

    if actual != expected {
        return Err(Problem::Validation(format!(
            "Poland PESEL checksum failed: expected {}, got {}",
            expected, actual
        )));
    }

    Ok(())
}

/// Check if a Poland PESEL is a test/dummy pattern
#[must_use]
pub fn is_test_poland_pesel(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() != 11 {
        return false;
    }

    // All zeros
    if trimmed.chars().all(|c| c == '0') {
        return true;
    }

    // All same digit
    let first = trimmed.chars().next().unwrap_or('x');
    if first.is_ascii_digit() && trimmed.chars().all(|c| c == first) {
        return true;
    }

    // Sequential ascending (12345678901)
    if trimmed == "12345678901" {
        return true;
    }

    false
}

// ============================================================================
// Private Helpers
// ============================================================================

/// Parse two digit characters at the given offset into a u32
fn parse_two_digits(chars: &[char], offset: usize) -> Result<u32, Problem> {
    let d1 = chars.get(offset).and_then(|c| c.to_digit(10)).unwrap_or(0);
    let d2 = chars
        .get(offset.saturating_add(1))
        .and_then(|c| c.to_digit(10))
        .unwrap_or(0);
    Ok(d1.saturating_mul(10).saturating_add(d2))
}

/// Decode century-encoded month to actual month (1-12)
///
/// Returns the decoded month, or an error if the raw value is invalid.
fn decode_month(raw_month: u32) -> Result<u32, Problem> {
    match raw_month {
        1..=12 => Ok(raw_month),                     // 1900s
        21..=32 => Ok(raw_month.saturating_sub(20)), // 2000s
        41..=52 => Ok(raw_month.saturating_sub(40)), // 2100s
        61..=72 => Ok(raw_month.saturating_sub(60)), // 2200s
        81..=92 => Ok(raw_month.saturating_sub(80)), // 1800s
        _ => Err(Problem::Validation(format!(
            "Poland PESEL invalid century-encoded month: {:02}",
            raw_month
        ))),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    /// Compute PESEL check digit from first 10 digits
    fn compute_check_digit(first_10: &str) -> char {
        let digits: Vec<u32> = first_10.chars().filter_map(|c| c.to_digit(10)).collect();
        assert_eq!(digits.len(), 10, "Need exactly 10 digits");
        let weighted_sum: u32 = digits.iter().zip(WEIGHTS.iter()).map(|(d, w)| d * w).sum();
        let check = (10 - (weighted_sum % 10)) % 10;
        char::from_digit(check, 10).expect("check digit is 0-9")
    }

    /// Build a valid PESEL from date components and serial (4 digits)
    fn make_valid_pesel(yy: &str, mm_encoded: &str, dd: &str, ssss: &str) -> String {
        let first_10 = format!("{}{}{}{}", yy, mm_encoded, dd, ssss);
        assert_eq!(first_10.len(), 10, "YY(2)+MM(2)+DD(2)+SSSS(4) = 10");
        let check = compute_check_digit(&first_10);
        format!("{}{}", first_10, check)
    }

    // ===== Format validation =====

    #[test]
    fn test_validate_pesel_valid_1900s() {
        // Born 15 June 1985 (month=06, 1900s encoding)
        let pesel = make_valid_pesel("85", "06", "15", "1234");
        assert!(validate_poland_pesel(&pesel).is_ok());
    }

    #[test]
    fn test_validate_pesel_valid_2000s() {
        // Born 1 March 2001 (month=03+20=23, 2000s encoding)
        let pesel = make_valid_pesel("01", "23", "01", "4567");
        assert!(validate_poland_pesel(&pesel).is_ok());
    }

    #[test]
    fn test_validate_pesel_valid_2100s() {
        // Born 25 Dec 2150 (month=12+40=52, 2100s encoding)
        let pesel = make_valid_pesel("50", "52", "25", "7890");
        assert!(validate_poland_pesel(&pesel).is_ok());
    }

    #[test]
    fn test_validate_pesel_valid_2200s() {
        // Born 10 Jan 2200 (month=01+60=61, 2200s encoding)
        let pesel = make_valid_pesel("00", "61", "10", "2345");
        assert!(validate_poland_pesel(&pesel).is_ok());
    }

    #[test]
    fn test_validate_pesel_valid_1800s() {
        // Born 20 Jul 1850 (month=07+80=87, 1800s encoding)
        let pesel = make_valid_pesel("50", "87", "20", "5678");
        assert!(validate_poland_pesel(&pesel).is_ok());
    }

    #[test]
    fn test_validate_pesel_empty() {
        assert!(validate_poland_pesel("").is_err());
    }

    #[test]
    fn test_validate_pesel_wrong_length() {
        assert!(validate_poland_pesel("1234567890").is_err()); // 10 digits
        assert!(validate_poland_pesel("123456789012").is_err()); // 12 digits
    }

    #[test]
    fn test_validate_pesel_non_digits() {
        assert!(validate_poland_pesel("8506150123A").is_err());
        assert!(validate_poland_pesel("85061501-34").is_err());
    }

    #[test]
    fn test_validate_pesel_invalid_month() {
        // Raw month 13 is invalid (not in any century range)
        assert!(validate_poland_pesel("85130115001").is_err());
        // Raw month 00 is invalid
        assert!(validate_poland_pesel("85000115001").is_err());
    }

    #[test]
    fn test_validate_pesel_invalid_day() {
        // Day 00
        assert!(validate_poland_pesel("85060015001").is_err());
        // Day 32
        assert!(validate_poland_pesel("85063215001").is_err());
    }

    // ===== Checksum validation =====

    #[test]
    fn test_validate_pesel_with_checksum_valid() {
        let pesel = make_valid_pesel("85", "06", "15", "1234");
        assert!(
            validate_poland_pesel_with_checksum(&pesel).is_ok(),
            "Valid PESEL: {}",
            pesel
        );
    }

    #[test]
    fn test_validate_pesel_with_checksum_2000s() {
        let pesel = make_valid_pesel("01", "23", "01", "4567");
        assert!(
            validate_poland_pesel_with_checksum(&pesel).is_ok(),
            "Valid 2000s PESEL: {}",
            pesel
        );
    }

    #[test]
    fn test_validate_pesel_with_checksum_invalid() {
        let pesel = make_valid_pesel("85", "06", "15", "1234");
        // Tamper with check digit
        let mut chars: Vec<char> = pesel.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_poland_pesel_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_pesel_with_checksum_all_century_encodings() {
        // Test each century encoding produces a valid checksum
        let cases = [
            ("85", "06", "15", "1234"), // 1900s
            ("01", "23", "01", "4567"), // 2000s
            ("50", "52", "25", "7890"), // 2100s
            ("00", "61", "10", "2345"), // 2200s
            ("50", "87", "20", "5678"), // 1800s
        ];
        for (yy, mm, dd, nnn) in &cases {
            let pesel = make_valid_pesel(yy, mm, dd, nnn);
            assert!(
                validate_poland_pesel_with_checksum(&pesel).is_ok(),
                "Should be valid PESEL: {}",
                pesel
            );
        }
    }

    // ===== Test pattern detection =====

    #[test]
    fn test_is_test_pesel() {
        assert!(is_test_poland_pesel("00000000000"));
        assert!(is_test_poland_pesel("11111111111"));
        assert!(is_test_poland_pesel("12345678901"));
    }

    #[test]
    fn test_is_test_pesel_not_test() {
        let pesel = make_valid_pesel("85", "06", "15", "1234");
        assert!(!is_test_poland_pesel(&pesel));
    }

    #[test]
    fn test_is_test_pesel_wrong_length() {
        assert!(!is_test_poland_pesel("12345"));
        assert!(!is_test_poland_pesel(""));
    }

    // ===== Decode month =====

    #[test]
    fn test_decode_month_all_centuries() {
        // 1900s: raw 01-12 → month 1-12
        assert_eq!(decode_month(1).expect("ok"), 1);
        assert_eq!(decode_month(12).expect("ok"), 12);

        // 2000s: raw 21-32 → month 1-12
        assert_eq!(decode_month(21).expect("ok"), 1);
        assert_eq!(decode_month(32).expect("ok"), 12);

        // 2100s: raw 41-52 → month 1-12
        assert_eq!(decode_month(41).expect("ok"), 1);
        assert_eq!(decode_month(52).expect("ok"), 12);

        // 2200s: raw 61-72 → month 1-12
        assert_eq!(decode_month(61).expect("ok"), 1);
        assert_eq!(decode_month(72).expect("ok"), 12);

        // 1800s: raw 81-92 → month 1-12
        assert_eq!(decode_month(81).expect("ok"), 1);
        assert_eq!(decode_month(92).expect("ok"), 12);
    }

    #[test]
    fn test_decode_month_invalid() {
        assert!(decode_month(0).is_err());
        assert!(decode_month(13).is_err());
        assert!(decode_month(20).is_err());
        assert!(decode_month(33).is_err());
        assert!(decode_month(99).is_err());
    }

    // ===== Weights verification =====

    #[test]
    fn test_weights_length() {
        assert_eq!(WEIGHTS.len(), 10);
    }
}

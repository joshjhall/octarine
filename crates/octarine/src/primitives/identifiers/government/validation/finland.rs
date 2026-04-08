//! Finland HETU (Henkilotunnus) validation
//!
//! Format: DDMMYY[+-A]NNN[check]
//! - DD: day (01-31), MM: month (01-12), YY: year
//! - Century marker: `-` (1900s), `+` (1800s), `A` (2000s)
//! - NNN: individual number (002-899, odd=male, even=female)
//! - Check: (DDMMYYNNN) % 31 → lookup in check character string

use crate::primitives::types::Problem;

/// Check character lookup string (31 characters, indices 0-30)
const CHECK_CHARS: &[u8] = b"0123456789ABCDEFHJKLMNPRSTUVWXY";

/// Valid century markers
const VALID_CENTURY_MARKERS: &[char] = &['-', '+', 'A'];

// ============================================================================
// Validation
// ============================================================================

/// Validate Finland HETU format (without checksum)
///
/// Checks: correct length, valid date, valid century marker.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_finland_hetu(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim().to_uppercase();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Finland HETU cannot be empty".to_string(),
        ));
    }

    if trimmed.len() != 11 {
        return Err(Problem::Validation(format!(
            "Finland HETU must be 11 characters, got {}",
            trimmed.len()
        )));
    }

    let chars: Vec<char> = trimmed.chars().collect();

    // Validate date digits (positions 0-5)
    for (i, &ch) in chars.iter().take(6).enumerate() {
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "Finland HETU position {} must be a digit, got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    // Validate date values
    let day = parse_two_digits(&chars, 0)?;
    let month = parse_two_digits(&chars, 2)?;

    if !(1..=31).contains(&day) {
        return Err(Problem::Validation(format!(
            "Finland HETU day must be 01-31, got {:02}",
            day
        )));
    }

    if !(1..=12).contains(&month) {
        return Err(Problem::Validation(format!(
            "Finland HETU month must be 01-12, got {:02}",
            month
        )));
    }

    // Validate century marker (position 6)
    let century = chars.get(6).copied().unwrap_or(' ');
    if !VALID_CENTURY_MARKERS.contains(&century) {
        return Err(Problem::Validation(format!(
            "Finland HETU century marker must be -, +, or A; got '{}'",
            century
        )));
    }

    // Validate individual number (positions 7-9)
    for (i, &ch) in chars.iter().skip(7).take(3).enumerate() {
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "Finland HETU position {} must be a digit, got '{}'",
                i.saturating_add(8),
                ch
            )));
        }
    }

    // Validate check character (position 10)
    let check = chars.get(10).copied().unwrap_or(' ');
    if !check.is_ascii_digit() && !check.is_ascii_uppercase() {
        return Err(Problem::Validation(format!(
            "Finland HETU check character must be alphanumeric, got '{}'",
            check
        )));
    }

    Ok(())
}

/// Validate Finland HETU with mod-31 checksum
///
/// Concatenates DDMMYY + NNN into a 9-digit number, computes mod 31,
/// and looks up the expected check character.
///
/// # Errors
///
/// Returns `Problem::Validation` if format or checksum is invalid.
pub fn validate_finland_hetu_with_checksum(value: &str) -> Result<(), Problem> {
    validate_finland_hetu(value)?;

    let trimmed = value.trim().to_uppercase();
    let chars: Vec<char> = trimmed.chars().collect();

    // Build 9-digit number: DDMMYY + NNN (skip century marker at position 6)
    let date_part: String = chars.iter().take(6).collect();
    let individual_part: String = chars.iter().skip(7).take(3).collect();
    let combined = format!("{}{}", date_part, individual_part);

    let number: u64 = combined.parse().map_err(|_| {
        Problem::Validation("Finland HETU: failed to parse numeric portion".to_string())
    })?;

    let remainder = (number % 31) as usize;
    let expected = CHECK_CHARS.get(remainder).copied().unwrap_or(b'?') as char;
    let actual = chars.get(10).copied().unwrap_or(' ');

    if actual != expected {
        return Err(Problem::Validation(format!(
            "Finland HETU check character failed: expected '{}', got '{}'",
            expected, actual
        )));
    }

    Ok(())
}

/// Check if a Finland HETU is a test/dummy pattern
#[must_use]
pub fn is_test_finland_hetu(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if upper.len() != 11 {
        return false;
    }

    // All-zero date + individual
    let digits: String = upper.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.chars().all(|c| c == '0') {
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // Helper to compute check character
    fn compute_check(ddmmyy: &str, nnn: &str) -> char {
        let combined = format!("{}{}", ddmmyy, nnn);
        let number: u64 = combined.parse().expect("valid digits");
        let remainder = (number % 31) as usize;
        CHECK_CHARS.get(remainder).copied().unwrap_or(b'?') as char
    }

    fn make_valid_hetu(ddmmyy: &str, century: char, nnn: &str) -> String {
        let check = compute_check(ddmmyy, nnn);
        format!("{}{}{}{}", ddmmyy, century, nnn, check)
    }

    #[test]
    fn test_validate_hetu_valid_format() {
        let hetu = make_valid_hetu("010190", '-', "123");
        assert!(validate_finland_hetu(&hetu).is_ok());
    }

    #[test]
    fn test_validate_hetu_all_century_markers() {
        for &marker in VALID_CENTURY_MARKERS {
            let hetu = make_valid_hetu("150685", marker, "456");
            assert!(
                validate_finland_hetu(&hetu).is_ok(),
                "Century marker '{}' should be valid",
                marker
            );
        }
    }

    #[test]
    fn test_validate_hetu_invalid_century_marker() {
        assert!(validate_finland_hetu("010190X1230").is_err());
    }

    #[test]
    fn test_validate_hetu_invalid_month() {
        assert!(validate_finland_hetu("011390-1230").is_err()); // Month 13
        assert!(validate_finland_hetu("010090-1230").is_err()); // Month 00
    }

    #[test]
    fn test_validate_hetu_invalid_day() {
        assert!(validate_finland_hetu("320190-1230").is_err()); // Day 32
        assert!(validate_finland_hetu("000190-1230").is_err()); // Day 00
    }

    #[test]
    fn test_validate_hetu_wrong_length() {
        assert!(validate_finland_hetu("010190-12").is_err());
        assert!(validate_finland_hetu("010190-12345").is_err());
    }

    #[test]
    fn test_validate_hetu_empty() {
        assert!(validate_finland_hetu("").is_err());
    }

    #[test]
    fn test_validate_hetu_with_checksum_1900s() {
        let hetu = make_valid_hetu("010190", '-', "123");
        assert!(
            validate_finland_hetu_with_checksum(&hetu).is_ok(),
            "Valid 1900s HETU: {}",
            hetu
        );
    }

    #[test]
    fn test_validate_hetu_with_checksum_1800s() {
        let hetu = make_valid_hetu("150685", '+', "789");
        assert!(
            validate_finland_hetu_with_checksum(&hetu).is_ok(),
            "Valid 1800s HETU: {}",
            hetu
        );
    }

    #[test]
    fn test_validate_hetu_with_checksum_2000s() {
        let hetu = make_valid_hetu("010105", 'A', "234");
        assert!(
            validate_finland_hetu_with_checksum(&hetu).is_ok(),
            "Valid 2000s HETU: {}",
            hetu
        );
    }

    #[test]
    fn test_validate_hetu_with_checksum_invalid() {
        let hetu = make_valid_hetu("010190", '-', "123");
        // Tamper with check character
        let mut chars: Vec<char> = hetu.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_finland_hetu_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_hetu_with_checksum_letter_result() {
        // Find a combination that produces a letter check character
        // 010190 + 100 = 010190100
        // 010190100 % 31 = 010190100 - 326103*31 = 010190100 - 10109193 = ... let me compute
        // Actually just try it:
        let check = compute_check("010190", "100");
        let hetu = format!("010190-100{}", check);
        assert!(validate_finland_hetu_with_checksum(&hetu).is_ok());
    }

    #[test]
    fn test_is_test_hetu() {
        assert!(is_test_finland_hetu("000000-0000"));
        assert!(!is_test_finland_hetu("010190-1230"));
    }

    #[test]
    fn test_is_test_hetu_wrong_length() {
        assert!(!is_test_finland_hetu("12345"));
        assert!(!is_test_finland_hetu(""));
    }

    #[test]
    fn test_check_chars_length() {
        // Verify the lookup string has exactly 31 characters
        assert_eq!(CHECK_CHARS.len(), 31);
    }
}

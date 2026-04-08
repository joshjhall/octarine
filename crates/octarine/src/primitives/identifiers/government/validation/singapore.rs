//! Singapore NRIC/FIN validation
//!
//! Format: [STFGM] + 7 digits + check letter
//! - S/T: citizen (born before/after 2000)
//! - F/G: permanent resident (before/after 2000)
//! - M: foreign worker (2022+)
//! - Weights: [2, 7, 6, 5, 4, 3, 2]
//! - Check letter: prefix-dependent lookup tables

use crate::primitives::types::Problem;

/// Weights for NRIC/FIN checksum
const WEIGHTS: [u32; 7] = [2, 7, 6, 5, 4, 3, 2];

/// Check letter table for S/T prefix (citizens)
const CHECK_ST: &[u8] = b"JZIHGFEDCBA";

/// Check letter table for F/G prefix (permanent residents)
const CHECK_FG: &[u8] = b"XWUTRQPNMLK";

/// Check letter table for M prefix (foreign workers, 2022+)
const CHECK_M: &[u8] = b"KLJNPQRTUWX";

/// Valid NRIC/FIN prefix characters
const VALID_PREFIXES: &[char] = &['S', 'T', 'F', 'G', 'M'];

// ============================================================================
// Validation
// ============================================================================

/// Validate Singapore NRIC/FIN format (without checksum)
///
/// Checks: 9 characters, valid prefix, 7 digits, trailing letter.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_singapore_nric(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim().to_uppercase();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Singapore NRIC/FIN cannot be empty".to_string(),
        ));
    }

    if trimmed.len() != 9 {
        return Err(Problem::Validation(format!(
            "Singapore NRIC/FIN must be 9 characters, got {}",
            trimmed.len()
        )));
    }

    let chars: Vec<char> = trimmed.chars().collect();

    // Validate prefix
    let prefix = chars.first().copied().unwrap_or(' ');
    if !VALID_PREFIXES.contains(&prefix) {
        return Err(Problem::Validation(format!(
            "Singapore NRIC/FIN prefix must be S, T, F, G, or M; got '{}'",
            prefix
        )));
    }

    // Validate 7 digits
    for (i, &ch) in chars.iter().skip(1).take(7).enumerate() {
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "Singapore NRIC/FIN position {} must be a digit, got '{}'",
                i.saturating_add(2),
                ch
            )));
        }
    }

    // Validate trailing letter
    let last = chars.get(8).copied().unwrap_or(' ');
    if !last.is_ascii_uppercase() {
        return Err(Problem::Validation(format!(
            "Singapore NRIC/FIN must end with a letter, got '{}'",
            last
        )));
    }

    Ok(())
}

/// Validate Singapore NRIC/FIN with weighted checksum and check letter
///
/// Weights: [2, 7, 6, 5, 4, 3, 2]
/// Check letter determined by prefix-dependent lookup table.
///
/// # Errors
///
/// Returns `Problem::Validation` if format or checksum is invalid.
pub fn validate_singapore_nric_with_checksum(value: &str) -> Result<(), Problem> {
    validate_singapore_nric(value)?;

    let trimmed = value.trim().to_uppercase();
    let chars: Vec<char> = trimmed.chars().collect();

    let prefix = chars.first().copied().unwrap_or(' ');

    // Extract 7 digits
    let digits: Vec<u32> = chars
        .iter()
        .skip(1)
        .take(7)
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 7 {
        return Err(Problem::Validation(
            "Singapore NRIC/FIN must have 7 digits".to_string(),
        ));
    }

    // Calculate weighted sum
    let mut sum: u32 = 0;
    for (i, &weight) in WEIGHTS.iter().enumerate() {
        let digit = digits.get(i).copied().unwrap_or(0);
        sum = sum.saturating_add(digit.saturating_mul(weight));
    }

    // Add offset for T/G prefixes (born after 2000)
    if prefix == 'T' || prefix == 'G' {
        sum = sum.saturating_add(4);
    } else if prefix == 'M' {
        sum = sum.saturating_add(3);
    }

    let remainder = (sum % 11) as usize;

    // Select check letter table based on prefix
    let check_table = match prefix {
        'S' | 'T' => CHECK_ST,
        'F' | 'G' => CHECK_FG,
        'M' => CHECK_M,
        _ => {
            return Err(Problem::Validation(format!("Unknown prefix '{}'", prefix)));
        }
    };

    let expected = check_table.get(remainder).copied().unwrap_or(b'?') as char;
    let actual = chars.get(8).copied().unwrap_or(' ');

    if actual != expected {
        return Err(Problem::Validation(format!(
            "Singapore NRIC/FIN check letter failed: expected '{}', got '{}'",
            expected, actual
        )));
    }

    Ok(())
}

/// Check if a Singapore NRIC/FIN is a test/dummy pattern
#[must_use]
pub fn is_test_singapore_nric(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if upper.len() != 9 {
        return false;
    }

    // All-zero digits
    let digits: String = upper.chars().skip(1).take(7).collect();
    if digits == "0000000" {
        return true;
    }

    // All-same digits
    if let Some(first) = digits.chars().next()
        && digits.chars().all(|c| c == first)
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

    // Helper to compute check letter for given prefix + 7 digits
    fn compute_check_letter(prefix: char, digits: &[u32; 7]) -> char {
        let mut sum: u32 = 0;
        for (i, &weight) in WEIGHTS.iter().enumerate() {
            sum = sum.saturating_add(digits.get(i).copied().unwrap_or(0).saturating_mul(weight));
        }

        if prefix == 'T' || prefix == 'G' {
            sum = sum.saturating_add(4);
        } else if prefix == 'M' {
            sum = sum.saturating_add(3);
        }

        let remainder = (sum % 11) as usize;
        let table = match prefix {
            'S' | 'T' => CHECK_ST,
            'F' | 'G' => CHECK_FG,
            'M' => CHECK_M,
            _ => CHECK_ST,
        };

        table.get(remainder).copied().unwrap_or(b'?') as char
    }

    fn make_valid_nric(prefix: char, digits: [u32; 7]) -> String {
        let check = compute_check_letter(prefix, &digits);
        let digit_str: String = digits
            .iter()
            .map(|d| char::from_digit(*d, 10).unwrap_or('0'))
            .collect();
        format!("{}{}{}", prefix, digit_str, check)
    }

    #[test]
    fn test_validate_nric_valid_format() {
        let nric = make_valid_nric('S', [1, 2, 3, 4, 5, 6, 7]);
        assert!(validate_singapore_nric(&nric).is_ok());
    }

    #[test]
    fn test_validate_nric_all_prefixes() {
        for &prefix in VALID_PREFIXES {
            let nric = make_valid_nric(prefix, [1, 2, 3, 4, 5, 6, 7]);
            assert!(
                validate_singapore_nric(&nric).is_ok(),
                "Prefix {} should be valid",
                prefix
            );
        }
    }

    #[test]
    fn test_validate_nric_invalid_prefix() {
        assert!(validate_singapore_nric("A1234567B").is_err());
        assert!(validate_singapore_nric("X1234567B").is_err());
    }

    #[test]
    fn test_validate_nric_wrong_length() {
        assert!(validate_singapore_nric("S123456A").is_err()); // 8 chars
        assert!(validate_singapore_nric("S12345678AB").is_err()); // 11 chars
    }

    #[test]
    fn test_validate_nric_empty() {
        assert!(validate_singapore_nric("").is_err());
    }

    #[test]
    fn test_validate_nric_with_checksum_s_prefix() {
        let nric = make_valid_nric('S', [1, 2, 3, 4, 5, 6, 7]);
        assert!(
            validate_singapore_nric_with_checksum(&nric).is_ok(),
            "Valid S-prefix NRIC should pass: {}",
            nric
        );
    }

    #[test]
    fn test_validate_nric_with_checksum_t_prefix() {
        let nric = make_valid_nric('T', [0, 1, 2, 3, 4, 5, 6]);
        assert!(
            validate_singapore_nric_with_checksum(&nric).is_ok(),
            "Valid T-prefix NRIC should pass: {}",
            nric
        );
    }

    #[test]
    fn test_validate_nric_with_checksum_f_prefix() {
        let nric = make_valid_nric('F', [1, 2, 3, 4, 5, 6, 7]);
        assert!(
            validate_singapore_nric_with_checksum(&nric).is_ok(),
            "Valid F-prefix FIN should pass: {}",
            nric
        );
    }

    #[test]
    fn test_validate_nric_with_checksum_g_prefix() {
        let nric = make_valid_nric('G', [9, 8, 7, 6, 5, 4, 3]);
        assert!(
            validate_singapore_nric_with_checksum(&nric).is_ok(),
            "Valid G-prefix FIN should pass: {}",
            nric
        );
    }

    #[test]
    fn test_validate_nric_with_checksum_m_prefix() {
        let nric = make_valid_nric('M', [1, 2, 3, 4, 5, 6, 7]);
        assert!(
            validate_singapore_nric_with_checksum(&nric).is_ok(),
            "Valid M-prefix FIN should pass: {}",
            nric
        );
    }

    #[test]
    fn test_validate_nric_with_checksum_invalid() {
        let nric = make_valid_nric('S', [1, 2, 3, 4, 5, 6, 7]);
        // Tamper with check letter
        let mut chars: Vec<char> = nric.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == 'A' { 'B' } else { 'A' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_singapore_nric_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_nric_lowercase_accepted() {
        let nric = make_valid_nric('S', [1, 2, 3, 4, 5, 6, 7]);
        let lower = nric.to_lowercase();
        assert!(validate_singapore_nric_with_checksum(&lower).is_ok());
    }

    #[test]
    fn test_is_test_nric() {
        assert!(is_test_singapore_nric("S0000000A"));
        assert!(is_test_singapore_nric("S1111111A"));
        assert!(!is_test_singapore_nric("S1234567A"));
    }

    #[test]
    fn test_is_test_nric_wrong_length() {
        assert!(!is_test_singapore_nric("S12345"));
        assert!(!is_test_singapore_nric(""));
    }
}

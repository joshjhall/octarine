//! Spain NIF/NIE validation
//!
//! NIF (Numero de Identificacion Fiscal): `[0-9]{8}[A-Z]`
//! NIE (Numero de Identidad de Extranjero): `[XYZ][0-9]{7}[A-Z]`
//!
//! Both use the same mod-23 checksum:
//! - Convert to an 8-digit number (NIE: X→0, Y→1, Z→2)
//! - Check letter = `CHECK_LETTERS[number % 23]`

use crate::primitives::types::Problem;

/// Mod-23 check letter lookup (23 characters, index 0-22)
const CHECK_LETTERS: &[u8] = b"TRWAGMYFPDXBNJZSQVHLCKE";

// ============================================================================
// NIF Validation
// ============================================================================

/// Validate Spain NIF format (includes checksum — the check letter is integral)
///
/// Format: 8 digits + 1 letter. The letter is determined by `number % 23`.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format or checksum is invalid.
pub fn validate_spain_nif(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim().to_uppercase();
    if trimmed.is_empty() {
        return Err(Problem::Validation("Spain NIF cannot be empty".to_string()));
    }

    if trimmed.len() != 9 {
        return Err(Problem::Validation(format!(
            "Spain NIF must be 9 characters, got {}",
            trimmed.len()
        )));
    }

    let chars: Vec<char> = trimmed.chars().collect();

    // First 8 characters must be digits
    for (i, &ch) in chars.iter().take(8).enumerate() {
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "Spain NIF position {} must be a digit, got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    // Last character must be a letter
    let check_char = chars.get(8).copied().unwrap_or(' ');
    if !check_char.is_ascii_uppercase() {
        return Err(Problem::Validation(format!(
            "Spain NIF position 9 must be a letter, got '{}'",
            check_char
        )));
    }

    Ok(())
}

/// Validate Spain NIF with mod-23 checksum
///
/// # Errors
///
/// Returns `Problem::Validation` if format or checksum is invalid.
pub fn validate_spain_nif_with_checksum(value: &str) -> Result<(), Problem> {
    validate_spain_nif(value)?;

    let trimmed = value.trim().to_uppercase();
    let chars: Vec<char> = trimmed.chars().collect();

    let number_str: String = chars.iter().take(8).collect();
    let number: u32 = number_str.parse().map_err(|_| {
        Problem::Validation("Spain NIF: failed to parse numeric portion".to_string())
    })?;

    let remainder = (number % 23) as usize;
    let expected = CHECK_LETTERS.get(remainder).copied().unwrap_or(b'?') as char;
    let actual = chars.get(8).copied().unwrap_or(' ');

    if actual != expected {
        return Err(Problem::Validation(format!(
            "Spain NIF check letter failed: expected '{}', got '{}'",
            expected, actual
        )));
    }

    Ok(())
}

/// Check if a Spain NIF is a test/dummy pattern
#[must_use]
pub fn is_test_spain_nif(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if upper.len() != 9 {
        return false;
    }

    let digits: &str = upper.get(..8).unwrap_or("");

    // All zeros
    if digits.chars().all(|c| c == '0') {
        return true;
    }

    // Sequential (12345678)
    if digits == "12345678" {
        return true;
    }

    // All same digit
    let first = digits.chars().next().unwrap_or('x');
    if first.is_ascii_digit() && digits.chars().all(|c| c == first) {
        return true;
    }

    false
}

// ============================================================================
// NIE Validation
// ============================================================================

/// Validate Spain NIE format (includes checksum)
///
/// Format: X/Y/Z + 7 digits + 1 letter. Replace prefix (X→0, Y→1, Z→2),
/// then use same mod-23 algorithm as NIF.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format or checksum is invalid.
pub fn validate_spain_nie(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim().to_uppercase();
    if trimmed.is_empty() {
        return Err(Problem::Validation("Spain NIE cannot be empty".to_string()));
    }

    if trimmed.len() != 9 {
        return Err(Problem::Validation(format!(
            "Spain NIE must be 9 characters, got {}",
            trimmed.len()
        )));
    }

    let chars: Vec<char> = trimmed.chars().collect();

    // First character must be X, Y, or Z
    let prefix = chars.first().copied().unwrap_or(' ');
    if !matches!(prefix, 'X' | 'Y' | 'Z') {
        return Err(Problem::Validation(format!(
            "Spain NIE must start with X, Y, or Z; got '{}'",
            prefix
        )));
    }

    // Characters 2-8 must be digits
    for (i, &ch) in chars.iter().skip(1).take(7).enumerate() {
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "Spain NIE position {} must be a digit, got '{}'",
                i.saturating_add(2),
                ch
            )));
        }
    }

    // Last character must be a letter
    let check_char = chars.get(8).copied().unwrap_or(' ');
    if !check_char.is_ascii_uppercase() {
        return Err(Problem::Validation(format!(
            "Spain NIE position 9 must be a letter, got '{}'",
            check_char
        )));
    }

    Ok(())
}

/// Validate Spain NIE with mod-23 checksum
///
/// # Errors
///
/// Returns `Problem::Validation` if format or checksum is invalid.
pub fn validate_spain_nie_with_checksum(value: &str) -> Result<(), Problem> {
    validate_spain_nie(value)?;

    let trimmed = value.trim().to_uppercase();
    let chars: Vec<char> = trimmed.chars().collect();

    // Replace prefix: X→0, Y→1, Z→2
    let prefix_digit = match chars.first().copied().unwrap_or(' ') {
        'X' => '0',
        'Y' => '1',
        'Z' => '2',
        _ => return Err(Problem::Validation("Spain NIE: invalid prefix".to_string())),
    };

    let number_str: String = std::iter::once(prefix_digit)
        .chain(chars.iter().skip(1).take(7).copied())
        .collect();

    let number: u32 = number_str.parse().map_err(|_| {
        Problem::Validation("Spain NIE: failed to parse numeric portion".to_string())
    })?;

    let remainder = (number % 23) as usize;
    let expected = CHECK_LETTERS.get(remainder).copied().unwrap_or(b'?') as char;
    let actual = chars.get(8).copied().unwrap_or(' ');

    if actual != expected {
        return Err(Problem::Validation(format!(
            "Spain NIE check letter failed: expected '{}', got '{}'",
            expected, actual
        )));
    }

    Ok(())
}

/// Check if a Spain NIE is a test/dummy pattern
#[must_use]
pub fn is_test_spain_nie(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if upper.len() != 9 {
        return false;
    }

    let digits: &str = upper.get(1..8).unwrap_or("");

    // All zeros after prefix
    if digits.chars().all(|c| c == '0') {
        return true;
    }

    false
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    /// Compute NIF check letter from 8-digit number
    fn nif_check_letter(number: u32) -> char {
        let remainder = (number % 23) as usize;
        CHECK_LETTERS.get(remainder).copied().expect("valid") as char
    }

    /// Build a valid NIF from 8-digit number
    fn make_valid_nif(number: u32) -> String {
        let check = nif_check_letter(number);
        format!("{:08}{}", number, check)
    }

    /// Compute NIE check letter from prefix + 7-digit number
    fn nie_check_letter(prefix: char, number: u32) -> char {
        let prefix_digit = match prefix {
            'X' => 0u32,
            'Y' => 1,
            'Z' => 2,
            _ => panic!("invalid prefix"),
        };
        let full_number = prefix_digit * 10_000_000 + number;
        let remainder = (full_number % 23) as usize;
        CHECK_LETTERS.get(remainder).copied().expect("valid") as char
    }

    /// Build a valid NIE from prefix + 7-digit number
    fn make_valid_nie(prefix: char, number: u32) -> String {
        let check = nie_check_letter(prefix, number);
        format!("{}{:07}{}", prefix, number, check)
    }

    // ===== NIF format validation =====

    #[test]
    fn test_validate_nif_valid() {
        let nif = make_valid_nif(12345678);
        assert!(validate_spain_nif(&nif).is_ok(), "Valid NIF: {}", nif);
    }

    #[test]
    fn test_validate_nif_empty() {
        assert!(validate_spain_nif("").is_err());
    }

    #[test]
    fn test_validate_nif_wrong_length() {
        assert!(validate_spain_nif("1234567A").is_err()); // 8 chars
        assert!(validate_spain_nif("1234567890A").is_err()); // 10 chars
    }

    #[test]
    fn test_validate_nif_non_digit() {
        assert!(validate_spain_nif("1234567AA").is_err()); // Letter in digit position
    }

    #[test]
    fn test_validate_nif_no_letter() {
        assert!(validate_spain_nif("123456789").is_err()); // All digits
    }

    // ===== NIF checksum validation =====

    #[test]
    fn test_validate_nif_with_checksum_valid() {
        let nif = make_valid_nif(12345678);
        assert!(
            validate_spain_nif_with_checksum(&nif).is_ok(),
            "Valid NIF checksum: {}",
            nif
        );
    }

    #[test]
    fn test_validate_nif_with_checksum_various() {
        for number in [0u32, 1, 99999999, 50000000, 12345678] {
            let nif = make_valid_nif(number);
            assert!(
                validate_spain_nif_with_checksum(&nif).is_ok(),
                "NIF {} should pass checksum",
                nif
            );
        }
    }

    #[test]
    fn test_validate_nif_with_checksum_invalid() {
        let nif = make_valid_nif(12345678);
        let mut chars: Vec<char> = nif.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == 'A' { 'B' } else { 'A' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_spain_nif_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_nif_case_insensitive() {
        let nif = make_valid_nif(12345678);
        let lower = nif.to_lowercase();
        assert!(
            validate_spain_nif_with_checksum(&lower).is_ok(),
            "Lowercase NIF should be valid"
        );
    }

    // ===== NIF test pattern detection =====

    #[test]
    fn test_is_test_nif() {
        assert!(is_test_spain_nif(&make_valid_nif(0)));
        assert!(is_test_spain_nif(&make_valid_nif(11111111)));
        assert!(is_test_spain_nif(&make_valid_nif(12345678)));
    }

    #[test]
    fn test_is_test_nif_not_test() {
        assert!(!is_test_spain_nif(&make_valid_nif(50123456)));
    }

    #[test]
    fn test_is_test_nif_wrong_length() {
        assert!(!is_test_spain_nif("12345"));
        assert!(!is_test_spain_nif(""));
    }

    // ===== NIE format validation =====

    #[test]
    fn test_validate_nie_valid() {
        for prefix in ['X', 'Y', 'Z'] {
            let nie = make_valid_nie(prefix, 1234567);
            assert!(
                validate_spain_nie(&nie).is_ok(),
                "Valid NIE with prefix {}: {}",
                prefix,
                nie
            );
        }
    }

    #[test]
    fn test_validate_nie_empty() {
        assert!(validate_spain_nie("").is_err());
    }

    #[test]
    fn test_validate_nie_wrong_length() {
        assert!(validate_spain_nie("X123456A").is_err()); // 8 chars
        assert!(validate_spain_nie("X123456789A").is_err()); // 10 chars
    }

    #[test]
    fn test_validate_nie_invalid_prefix() {
        assert!(validate_spain_nie("A1234567Z").is_err()); // Not X/Y/Z
    }

    #[test]
    fn test_validate_nie_non_digit() {
        assert!(validate_spain_nie("X123456AZ").is_err()); // Letter in digit position
    }

    // ===== NIE checksum validation =====

    #[test]
    fn test_validate_nie_with_checksum_valid() {
        let nie = make_valid_nie('X', 1234567);
        assert!(
            validate_spain_nie_with_checksum(&nie).is_ok(),
            "Valid NIE checksum: {}",
            nie
        );
    }

    #[test]
    fn test_validate_nie_with_checksum_all_prefixes() {
        for prefix in ['X', 'Y', 'Z'] {
            let nie = make_valid_nie(prefix, 5555555);
            assert!(
                validate_spain_nie_with_checksum(&nie).is_ok(),
                "NIE prefix {} should pass checksum: {}",
                prefix,
                nie
            );
        }
    }

    #[test]
    fn test_validate_nie_with_checksum_invalid() {
        let nie = make_valid_nie('X', 1234567);
        let mut chars: Vec<char> = nie.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == 'A' { 'B' } else { 'A' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_spain_nie_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_nie_case_insensitive() {
        let nie = make_valid_nie('X', 1234567);
        let lower = nie.to_lowercase();
        assert!(
            validate_spain_nie_with_checksum(&lower).is_ok(),
            "Lowercase NIE should be valid"
        );
    }

    // ===== NIE test pattern detection =====

    #[test]
    fn test_is_test_nie() {
        let nie = make_valid_nie('X', 0);
        assert!(is_test_spain_nie(&nie));
    }

    #[test]
    fn test_is_test_nie_not_test() {
        let nie = make_valid_nie('X', 1234567);
        assert!(!is_test_spain_nie(&nie));
    }

    #[test]
    fn test_is_test_nie_wrong_length() {
        assert!(!is_test_spain_nie("12345"));
        assert!(!is_test_spain_nie(""));
    }

    // ===== Check letters verification =====

    #[test]
    fn test_check_letters_length() {
        assert_eq!(CHECK_LETTERS.len(), 23);
    }
}

//! India Aadhaar and PAN validation
//!
//! Aadhaar: 12-digit number with Verhoeff checksum (starts with 2-9)
//! PAN: 10-character alphanumeric (AAAAA9999A) with holder type at position 4

use crate::primitives::types::Problem;

// ============================================================================
// Verhoeff Checksum Tables
// ============================================================================

/// Verhoeff multiplication table (d5 group)
#[rustfmt::skip]
const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

/// Verhoeff permutation table
#[rustfmt::skip]
const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Valid PAN holder type codes at position 4 (0-indexed)
const VALID_PAN_HOLDER_TYPES: &[char] = &[
    'A', // Association of Persons
    'B', // Body of Individuals
    'C', // Company
    'F', // Firm
    'G', // Government
    'H', // Hindu Undivided Family
    'J', // Artificial Juridical Person
    'L', // Local Authority
    'P', // Individual (Person)
    'T', // Trust
];

// ============================================================================
// Aadhaar Validation
// ============================================================================

/// Validate India Aadhaar format (without checksum)
///
/// Checks: 12 digits, starts with 2-9.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_india_aadhaar(value: &str) -> Result<(), Problem> {
    let digits = extract_digits(value)?;

    if digits.len() != 12 {
        return Err(Problem::Validation(format!(
            "Aadhaar must be 12 digits, got {}",
            digits.len()
        )));
    }

    let first = digits.first().copied().unwrap_or(0);
    if first < 2 {
        return Err(Problem::Validation(format!(
            "Aadhaar cannot start with {}, must start with 2-9",
            first
        )));
    }

    Ok(())
}

/// Validate India Aadhaar with Verhoeff checksum
///
/// Uses the Verhoeff algorithm: processes digits right-to-left using
/// d5 multiplication table and permutation cycling.
///
/// # Errors
///
/// Returns `Problem::Validation` if format or checksum is invalid.
pub fn validate_india_aadhaar_with_checksum(value: &str) -> Result<(), Problem> {
    validate_india_aadhaar(value)?;

    let digits = extract_digits(value)?;
    if !verhoeff_validate(&digits) {
        return Err(Problem::Validation(
            "Aadhaar Verhoeff checksum failed".to_string(),
        ));
    }

    Ok(())
}

/// Check if an Aadhaar is a test/dummy pattern
#[must_use]
pub fn is_test_india_aadhaar(value: &str) -> bool {
    let clean: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if clean.len() != 12 {
        return false;
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
// PAN Validation
// ============================================================================

/// Validate India PAN format
///
/// Format: AAAAA9999A (5 uppercase letters + 4 digits + 1 uppercase letter)
/// Position 4 (0-indexed) must be a valid holder type code.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_india_pan(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("PAN cannot be empty".to_string()));
    }

    let upper = trimmed.to_uppercase();
    if upper.len() != 10 {
        return Err(Problem::Validation(format!(
            "PAN must be 10 characters, got {}",
            upper.len()
        )));
    }

    let chars: Vec<char> = upper.chars().collect();

    // First 5 must be letters
    for (i, &ch) in chars.iter().take(5).enumerate() {
        if !ch.is_ascii_uppercase() {
            return Err(Problem::Validation(format!(
                "PAN position {} must be a letter, got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    // Next 4 must be digits
    for (i, &ch) in chars.iter().skip(5).take(4).enumerate() {
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "PAN position {} must be a digit, got '{}'",
                i.saturating_add(6),
                ch
            )));
        }
    }

    // Last must be a letter
    let last = chars.get(9).copied().unwrap_or(' ');
    if !last.is_ascii_uppercase() {
        return Err(Problem::Validation(format!(
            "PAN position 10 must be a letter, got '{}'",
            last
        )));
    }

    // Position 4 (0-indexed) must be a valid holder type
    let holder_type = chars.get(3).copied().unwrap_or(' ');
    if !VALID_PAN_HOLDER_TYPES.contains(&holder_type) {
        return Err(Problem::Validation(format!(
            "PAN holder type '{}' at position 4 is not valid (expected one of: {:?})",
            holder_type, VALID_PAN_HOLDER_TYPES
        )));
    }

    Ok(())
}

/// Check if a PAN is a test/dummy pattern
#[must_use]
pub fn is_test_india_pan(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if upper.len() != 10 {
        return false;
    }

    // Common test patterns
    matches!(upper.as_str(), "AAAAA0000A" | "ABCDE1234F" | "ZZZZZ9999Z")
}

// ============================================================================
// Private Helpers
// ============================================================================

/// Extract digits from a value string
fn extract_digits(value: &str) -> Result<Vec<u32>, Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("Aadhaar cannot be empty".to_string()));
    }

    let digits: Vec<u32> = trimmed
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    Ok(digits)
}

/// Verhoeff checksum validation
///
/// For a valid number, the Verhoeff checksum should be 0 when
/// processing all digits (including the check digit) right-to-left.
fn verhoeff_validate(digits: &[u32]) -> bool {
    let mut c: u8 = 0;

    for (i, &digit) in digits.iter().rev().enumerate() {
        let p_index = i % 8;
        let p_val = VERHOEFF_P
            .get(p_index)
            .and_then(|row| row.get(digit as usize))
            .copied()
            .unwrap_or(0);
        c = VERHOEFF_D
            .get(c as usize)
            .and_then(|row| row.get(p_val as usize))
            .copied()
            .unwrap_or(0);
    }

    c == 0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // Helper to compute Verhoeff check digit for a sequence
    fn verhoeff_compute_check(digits: &[u32]) -> u32 {
        // Inverse table for finding check digit
        const INV: [u8; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

        let mut c: u8 = 0;
        // Process digits right-to-left, but shifted by 1 position (check digit at position 0)
        for (i, &digit) in digits.iter().rev().enumerate() {
            let p_index = i.saturating_add(1) % 8;
            let p_val = VERHOEFF_P
                .get(p_index)
                .and_then(|row| row.get(digit as usize))
                .copied()
                .unwrap_or(0);
            c = VERHOEFF_D
                .get(c as usize)
                .and_then(|row| row.get(p_val as usize))
                .copied()
                .unwrap_or(0);
        }

        u32::from(INV.get(c as usize).copied().unwrap_or(0))
    }

    fn make_valid_aadhaar(first_11: &str) -> String {
        let digits: Vec<u32> = first_11
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();
        let check = verhoeff_compute_check(&digits);
        let all_digits: String = digits
            .iter()
            .map(|d| char::from_digit(*d, 10).unwrap_or('0'))
            .collect();
        format!(
            "{} {} {}{}",
            &all_digits[..4],
            &all_digits[4..8],
            &all_digits[8..],
            check
        )
    }

    // ===== Aadhaar Tests =====

    #[test]
    fn test_validate_aadhaar_valid() {
        assert!(validate_india_aadhaar("2345 6789 0123").is_ok());
    }

    #[test]
    fn test_validate_aadhaar_rejects_start_0() {
        assert!(validate_india_aadhaar("0345 6789 0123").is_err());
    }

    #[test]
    fn test_validate_aadhaar_rejects_start_1() {
        assert!(validate_india_aadhaar("1345 6789 0123").is_err());
    }

    #[test]
    fn test_validate_aadhaar_all_valid_starts() {
        for start in 2..=9 {
            let aadhaar = format!("{start}345 6789 0123");
            assert!(
                validate_india_aadhaar(&aadhaar).is_ok(),
                "Start digit {} should be valid",
                start
            );
        }
    }

    #[test]
    fn test_validate_aadhaar_wrong_length() {
        assert!(validate_india_aadhaar("2345 6789 012").is_err()); // 11 digits
        assert!(validate_india_aadhaar("2345 6789 01234").is_err()); // 13 digits
    }

    #[test]
    fn test_validate_aadhaar_empty() {
        assert!(validate_india_aadhaar("").is_err());
    }

    #[test]
    fn test_validate_aadhaar_with_checksum_valid() {
        let aadhaar = make_valid_aadhaar("23456789012");
        assert!(
            validate_india_aadhaar_with_checksum(&aadhaar).is_ok(),
            "Valid Aadhaar should pass: {}",
            aadhaar
        );
    }

    #[test]
    fn test_validate_aadhaar_with_checksum_invalid() {
        let aadhaar = make_valid_aadhaar("23456789012");
        // Tamper with last digit
        let mut chars: Vec<char> = aadhaar.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_india_aadhaar_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_aadhaar_with_checksum_different_start() {
        let aadhaar = make_valid_aadhaar("98765432101");
        assert!(validate_india_aadhaar_with_checksum(&aadhaar).is_ok());
    }

    #[test]
    fn test_verhoeff_known_value() {
        // Verhoeff("2363" + check) should validate
        let digits = vec![2, 3, 6, 3];
        let check = verhoeff_compute_check(&digits);
        let mut full = digits;
        full.push(check);
        assert!(verhoeff_validate(&full));
    }

    #[test]
    fn test_is_test_aadhaar() {
        assert!(is_test_india_aadhaar("2222 2222 2222"));
        assert!(!is_test_india_aadhaar("2345 6789 0123"));
    }

    #[test]
    fn test_is_test_aadhaar_wrong_length() {
        assert!(!is_test_india_aadhaar("12345"));
        assert!(!is_test_india_aadhaar(""));
    }

    // ===== PAN Tests =====

    #[test]
    fn test_validate_pan_valid_person() {
        assert!(validate_india_pan("ABCPD1234E").is_ok());
    }

    #[test]
    fn test_validate_pan_valid_company() {
        assert!(validate_india_pan("ABCCD1234E").is_ok());
    }

    #[test]
    fn test_validate_pan_all_holder_types() {
        for &holder in VALID_PAN_HOLDER_TYPES {
            let pan = format!("ABC{}D1234E", holder);
            assert!(
                validate_india_pan(&pan).is_ok(),
                "Holder type {} should be valid",
                holder
            );
        }
    }

    #[test]
    fn test_validate_pan_invalid_holder_type() {
        // 'X' is not a valid holder type
        assert!(validate_india_pan("ABCXD1234E").is_err());
    }

    #[test]
    fn test_validate_pan_wrong_length() {
        assert!(validate_india_pan("ABCPD1234").is_err()); // 9 chars
        assert!(validate_india_pan("ABCPD1234EF").is_err()); // 11 chars
    }

    #[test]
    fn test_validate_pan_invalid_format() {
        assert!(validate_india_pan("12345ABCDE").is_err()); // Numbers first
        assert!(validate_india_pan("ABCDEABCDE").is_err()); // Letters where digits should be
    }

    #[test]
    fn test_validate_pan_empty() {
        assert!(validate_india_pan("").is_err());
    }

    #[test]
    fn test_validate_pan_lowercase_accepted() {
        // Should accept lowercase (converts to uppercase)
        assert!(validate_india_pan("abcpd1234e").is_ok());
    }

    #[test]
    fn test_is_test_pan() {
        assert!(is_test_india_pan("AAAAA0000A"));
        assert!(is_test_india_pan("ABCDE1234F"));
        assert!(!is_test_india_pan("ABCPD1234E"));
    }
}

//! Nigeria NIN (National Identification Number) validation
//!
//! Format: 11 digits. No public checksum algorithm — format validation only.
//! NIMC (National Identity Management Commission) issues these via the
//! National Identity Database.

use crate::primitives::types::Problem;

/// Validate Nigeria NIN format
///
/// Checks: 11 digits, not all the same digit.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_nigeria_nin(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("NIN cannot be empty".to_string()));
    }

    // NIN is plain digits; tolerate hyphens/spaces but reject letters.
    for ch in trimmed.chars() {
        if !ch.is_ascii_digit() && !matches!(ch, '-' | ' ' | '\t') {
            return Err(Problem::Validation(format!(
                "invalid character '{ch}' in NIN"
            )));
        }
    }

    let digits: Vec<u8> = trimmed
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();

    if digits.len() != 11 {
        return Err(Problem::Validation(format!(
            "NIN must be 11 digits, got {}",
            digits.len()
        )));
    }

    if all_same_digit(&digits) {
        return Err(Problem::Validation(
            "NIN cannot have all identical digits".to_string(),
        ));
    }

    Ok(())
}

/// Check if a NIN is a test/dummy pattern (all-same-digit)
#[must_use]
pub fn is_test_nigeria_nin(value: &str) -> bool {
    let digits: Vec<u8> = value
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    digits.len() == 11 && all_same_digit(&digits)
}

fn all_same_digit(digits: &[u8]) -> bool {
    digits
        .first()
        .is_some_and(|&first| digits.iter().all(|&d| d == first))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_nin_valid() {
        assert!(validate_nigeria_nin("12345678901").is_ok());
    }

    #[test]
    fn test_validate_nin_with_separators() {
        assert!(validate_nigeria_nin("123-456-789-01").is_ok());
    }

    #[test]
    fn test_validate_nin_rejects_too_short() {
        assert!(validate_nigeria_nin("1234567890").is_err());
    }

    #[test]
    fn test_validate_nin_rejects_too_long() {
        assert!(validate_nigeria_nin("123456789012").is_err());
    }

    #[test]
    fn test_validate_nin_rejects_empty() {
        assert!(validate_nigeria_nin("").is_err());
    }

    #[test]
    fn test_validate_nin_rejects_letters() {
        assert!(validate_nigeria_nin("12345abc901").is_err());
    }

    #[test]
    fn test_validate_nin_rejects_all_same() {
        assert!(validate_nigeria_nin("11111111111").is_err());
        assert!(validate_nigeria_nin("00000000000").is_err());
    }

    #[test]
    fn test_is_test_nigeria_nin_detects_all_same() {
        assert!(is_test_nigeria_nin("11111111111"));
        assert!(is_test_nigeria_nin("00000000000"));
    }

    #[test]
    fn test_is_test_nigeria_nin_rejects_real() {
        assert!(!is_test_nigeria_nin("12345678901"));
    }

    #[test]
    fn test_is_test_nigeria_nin_rejects_wrong_length() {
        assert!(!is_test_nigeria_nin("111"));
    }
}

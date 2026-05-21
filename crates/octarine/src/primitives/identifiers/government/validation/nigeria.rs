//! Nigeria identifier validation — NIN, BVN, and vehicle registration.
//!
//! Format-only checks. NIN and BVN are 11-digit identifiers with no public
//! checksum algorithm. Vehicle registration validates against the current
//! post-2020 layout (3 letters + 3 digits + 2 letters) and the pre-2020
//! legacy layout (2 letters + 3 digits + 3 letters). State / LGA codes are
//! not enforced against a closed list — issuance is ongoing and lists vary
//! by source.

use crate::primitives::types::Problem;

// ============================================================================
// NIN Validation
// ============================================================================

/// Validate Nigeria NIN format
///
/// Checks: 11 digits, not all the same digit.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_nigeria_nin(value: &str) -> Result<(), Problem> {
    validate_eleven_digit_id(value, "NIN")
}

/// Check if a NIN is a test/dummy pattern (all-same-digit)
#[must_use]
pub fn is_test_nigeria_nin(value: &str) -> bool {
    is_test_eleven_digit_id(value)
}

// ============================================================================
// BVN Validation
// ============================================================================

/// Validate Nigeria BVN format
///
/// Checks: 11 digits, not all the same digit. BVN has no public checksum
/// algorithm — format validation only.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_nigeria_bvn(value: &str) -> Result<(), Problem> {
    validate_eleven_digit_id(value, "BVN")
}

/// Check if a BVN is a test/dummy pattern (all-same-digit)
#[must_use]
pub fn is_test_nigeria_bvn(value: &str) -> bool {
    is_test_eleven_digit_id(value)
}

// ============================================================================
// Vehicle Registration Validation
// ============================================================================

/// Validate Nigeria vehicle registration plate
///
/// Accepts two layouts after stripping whitespace/`-` and uppercasing:
///   * Current (post-2020): 3 letters + 3 digits + 2 letters (e.g. `LAG-123-AB`)
///   * Legacy (pre-2020):   2 letters + 3 digits + 3 letters (e.g. `LA123-ABC`)
///
/// LGA / state codes are not enforced against a closed list.
///
/// # Errors
///
/// Returns `Problem::Validation` if neither layout matches.
pub fn validate_nigeria_vehicle_registration(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Vehicle registration cannot be empty".to_string(),
        ));
    }

    let normalized: String = trimmed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase();

    if normalized.len() != 8 {
        return Err(Problem::Validation(format!(
            "Vehicle registration must be 8 chars (excl. separators), got {}",
            normalized.len()
        )));
    }

    let chars: Vec<char> = normalized.chars().collect();

    if matches_layout(&chars, &[3, 3, 2]) || matches_layout(&chars, &[2, 3, 3]) {
        Ok(())
    } else {
        Err(Problem::Validation(format!(
            "Vehicle registration '{normalized}' does not match XXX-NNN-XX or AA999-AAA layout"
        )))
    }
}

/// Check if a vehicle registration is a test/dummy pattern
///
/// Returns true when all letter positions hold the same letter AND all digit
/// positions hold the same digit (e.g. `AAA-000-AA`, `XXX-111-XX`).
#[must_use]
pub fn is_test_nigeria_vehicle_registration(value: &str) -> bool {
    let normalized: String = value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase();

    if normalized.len() != 8 {
        return false;
    }

    let chars: Vec<char> = normalized.chars().collect();
    if !(matches_layout(&chars, &[3, 3, 2]) || matches_layout(&chars, &[2, 3, 3])) {
        return false;
    }

    let letters: Vec<char> = chars
        .iter()
        .copied()
        .filter(char::is_ascii_alphabetic)
        .collect();
    let digits: Vec<char> = chars.iter().copied().filter(char::is_ascii_digit).collect();

    all_same_char(&letters) && all_same_char(&digits)
}

// ============================================================================
// Shared helpers
// ============================================================================

/// Validate an 11-digit Nigerian identifier (NIN or BVN).
fn validate_eleven_digit_id(value: &str, label: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(format!("{label} cannot be empty")));
    }

    for ch in trimmed.chars() {
        if !ch.is_ascii_digit() && !matches!(ch, '-' | ' ' | '\t') {
            return Err(Problem::Validation(format!(
                "invalid character '{ch}' in {label}"
            )));
        }
    }

    let digits: Vec<u8> = trimmed
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();

    if digits.len() != 11 {
        return Err(Problem::Validation(format!(
            "{label} must be 11 digits, got {}",
            digits.len()
        )));
    }

    if all_same_digit(&digits) {
        return Err(Problem::Validation(format!(
            "{label} cannot have all identical digits"
        )));
    }

    Ok(())
}

fn is_test_eleven_digit_id(value: &str) -> bool {
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

fn all_same_char(chars: &[char]) -> bool {
    chars
        .first()
        .is_some_and(|&first| chars.iter().all(|&c| c == first))
}

/// Check whether `chars` follows `pattern` where each entry alternates
/// letters / digits / letters, starting with letters.
fn matches_layout(chars: &[char], pattern: &[usize]) -> bool {
    if chars.len() != pattern.iter().sum::<usize>() {
        return false;
    }
    let mut idx: usize = 0;
    for (segment, &count) in pattern.iter().enumerate() {
        let expect_letter = segment.is_multiple_of(2);
        for _ in 0..count {
            let Some(&ch) = chars.get(idx) else {
                return false;
            };
            let ok = if expect_letter {
                ch.is_ascii_uppercase()
            } else {
                ch.is_ascii_digit()
            };
            if !ok {
                return false;
            }
            idx = idx.saturating_add(1);
        }
    }
    idx == chars.len()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // ---------------- NIN ----------------

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

    // ---------------- BVN ----------------

    #[test]
    fn test_validate_bvn_valid() {
        assert!(validate_nigeria_bvn("12345678901").is_ok());
    }

    #[test]
    fn test_validate_bvn_with_separators() {
        assert!(validate_nigeria_bvn("123-456-789-01").is_ok());
    }

    #[test]
    fn test_validate_bvn_rejects_too_short() {
        assert!(validate_nigeria_bvn("1234567890").is_err());
    }

    #[test]
    fn test_validate_bvn_rejects_too_long() {
        assert!(validate_nigeria_bvn("123456789012").is_err());
    }

    #[test]
    fn test_validate_bvn_rejects_empty() {
        assert!(validate_nigeria_bvn("").is_err());
    }

    #[test]
    fn test_validate_bvn_rejects_letters() {
        assert!(validate_nigeria_bvn("12345abc901").is_err());
    }

    #[test]
    fn test_validate_bvn_rejects_all_same() {
        assert!(validate_nigeria_bvn("11111111111").is_err());
        assert!(validate_nigeria_bvn("99999999999").is_err());
    }

    #[test]
    fn test_is_test_nigeria_bvn_detects_all_same() {
        assert!(is_test_nigeria_bvn("11111111111"));
        assert!(is_test_nigeria_bvn("99999999999"));
    }

    #[test]
    fn test_is_test_nigeria_bvn_rejects_real() {
        assert!(!is_test_nigeria_bvn("12345678901"));
    }

    #[test]
    fn test_is_test_nigeria_bvn_rejects_wrong_length() {
        assert!(!is_test_nigeria_bvn("111"));
    }

    // ---------------- Vehicle Registration ----------------

    #[test]
    fn test_validate_vehicle_current_no_separators() {
        assert!(validate_nigeria_vehicle_registration("LAG123AB").is_ok());
        assert!(validate_nigeria_vehicle_registration("ABC456XY").is_ok());
    }

    #[test]
    fn test_validate_vehicle_current_with_dashes() {
        assert!(validate_nigeria_vehicle_registration("LAG-123-AB").is_ok());
    }

    #[test]
    fn test_validate_vehicle_current_with_spaces() {
        assert!(validate_nigeria_vehicle_registration("LAG 123 AB").is_ok());
    }

    #[test]
    fn test_validate_vehicle_legacy_format() {
        assert!(validate_nigeria_vehicle_registration("LA123-ABC").is_ok());
        assert!(validate_nigeria_vehicle_registration("LA 123 ABC").is_ok());
    }

    #[test]
    fn test_validate_vehicle_rejects_empty() {
        assert!(validate_nigeria_vehicle_registration("").is_err());
    }

    #[test]
    fn test_validate_vehicle_rejects_short_lga_on_current() {
        // 2 letters + 3 digits + 2 letters = 7 chars, not 8
        assert!(validate_nigeria_vehicle_registration("LA-123-AB").is_err());
    }

    #[test]
    fn test_validate_vehicle_rejects_all_digit_lga() {
        assert!(validate_nigeria_vehicle_registration("123-456-AB").is_err());
    }

    #[test]
    fn test_validate_vehicle_rejects_too_many_district_digits() {
        assert!(validate_nigeria_vehicle_registration("LAG-1234-AB").is_err());
    }

    #[test]
    fn test_validate_vehicle_rejects_trailing_garbage() {
        assert!(validate_nigeria_vehicle_registration("LAG-123-ABXY").is_err());
    }

    #[test]
    fn test_validate_vehicle_normalizes_case() {
        assert!(validate_nigeria_vehicle_registration("lag-123-ab").is_ok());
    }

    #[test]
    fn test_is_test_vehicle_detects_dummy_current() {
        assert!(is_test_nigeria_vehicle_registration("AAA-000-AA"));
        assert!(is_test_nigeria_vehicle_registration("XXX111XX"));
    }

    #[test]
    fn test_is_test_vehicle_detects_dummy_legacy() {
        assert!(is_test_nigeria_vehicle_registration("AA000-AAA"));
    }

    #[test]
    fn test_is_test_vehicle_rejects_real() {
        assert!(!is_test_nigeria_vehicle_registration("LAG-123-AB"));
    }

    #[test]
    fn test_is_test_vehicle_rejects_wrong_length() {
        assert!(!is_test_nigeria_vehicle_registration("AAA-000"));
    }
}

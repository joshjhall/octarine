//! Mexico CURP (Clave Única de Registro de Población) validation
//!
//! Format (18 characters):
//! - Positions 1-4: name letters (initials of paternal surname, maternal
//!   surname, given name)
//! - Positions 5-10: date of birth `YYMMDD`
//! - Position 11: gender (`H` male, `M` female)
//! - Positions 12-13: state/entity code (one of 33 — 32 states plus `NE` for
//!   foreign-born)
//! - Positions 14-16: three consonants from the names
//! - Position 17: disambiguator (digit for pre-2000 births, letter A-Z for
//!   post-2000 births)
//! - Position 18: check digit (mod-10 over weighted character values)

use crate::primitives::types::Problem;

/// Valid Mexican state/entity codes used in positions 12-13.
const VALID_STATE_CODES: &[&str] = &[
    "AS", "BC", "BS", "CC", "CL", "CM", "CS", "CH", "DF", "DG", "GT", "GR", "HG", "JC", "MC", "MN",
    "MS", "NT", "NL", "OC", "PL", "QT", "QR", "SP", "SL", "SR", "TC", "TS", "TL", "VZ", "YN", "ZS",
    "NE", // foreign-born
];

/// Validate Mexico CURP format (without checksum)
///
/// Checks: 18 chars, structural composition (letters, digits, gender, state).
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_mexico_curp(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation("CURP cannot be empty".to_string()));
    }

    let upper = trimmed.to_uppercase();
    let chars: Vec<char> = upper.chars().collect();

    if chars.len() != 18 {
        return Err(Problem::Validation(format!(
            "CURP must be 18 characters, got {}",
            chars.len()
        )));
    }

    // Positions 1-4 (0..4): letters
    for (idx, &ch) in chars.iter().take(4).enumerate() {
        if !ch.is_ascii_uppercase() {
            return Err(Problem::Validation(format!(
                "CURP position {} must be a letter, got '{}'",
                idx.saturating_add(1),
                ch
            )));
        }
    }

    // Positions 5-10 (4..10): YYMMDD digits
    for (idx, &ch) in chars.iter().skip(4).take(6).enumerate() {
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "CURP position {} (date) must be a digit, got '{}'",
                idx.saturating_add(5),
                ch
            )));
        }
    }

    // Position 11 (index 10): gender
    let gender = chars.get(10).copied().unwrap_or(' ');
    if gender != 'H' && gender != 'M' {
        return Err(Problem::Validation(format!(
            "CURP position 11 (gender) must be 'H' or 'M', got '{gender}'"
        )));
    }

    // Positions 12-13 (indices 11..13): state code
    let state: String = chars.iter().skip(11).take(2).collect();
    if !VALID_STATE_CODES.contains(&state.as_str()) {
        return Err(Problem::Validation(format!(
            "CURP state code '{state}' is not a valid Mexican entity code"
        )));
    }

    // Positions 14-16 (indices 13..16): consonants
    for (i, &ch) in chars.iter().skip(13).take(3).enumerate() {
        if !ch.is_ascii_uppercase() {
            return Err(Problem::Validation(format!(
                "CURP position {} must be a letter, got '{}'",
                i.saturating_add(14),
                ch
            )));
        }
    }

    // Position 17 (index 16): disambiguator (digit OR letter)
    let disamb = chars.get(16).copied().unwrap_or(' ');
    if !disamb.is_ascii_digit() && !disamb.is_ascii_uppercase() {
        return Err(Problem::Validation(format!(
            "CURP position 17 must be a digit or uppercase letter, got '{disamb}'"
        )));
    }

    // Position 18 (index 17): check digit (single digit 0-9)
    let check = chars.get(17).copied().unwrap_or(' ');
    if !check.is_ascii_digit() {
        return Err(Problem::Validation(format!(
            "CURP position 18 (check digit) must be a digit, got '{check}'"
        )));
    }

    Ok(())
}

/// Validate Mexico CURP with check digit verification
///
/// Algorithm: each of positions 1-17 maps to a character value (0-9 for
/// digits, 10..35 for A..Z), multiplied by weight `19 - position`. Sum,
/// take mod 10, then check digit = `(10 - remainder) % 10`.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format or check digit is invalid.
pub fn validate_mexico_curp_with_checksum(value: &str) -> Result<(), Problem> {
    validate_mexico_curp(value)?;

    let upper = value.trim().to_uppercase();
    let chars: Vec<char> = upper.chars().collect();

    let computed = compute_curp_check_digit(chars.get(..17).unwrap_or(&[]));
    let actual = chars.get(17).and_then(|c| c.to_digit(10)).unwrap_or(99);

    if computed != actual {
        return Err(Problem::Validation(format!(
            "CURP check digit mismatch: expected {computed}, got {actual}"
        )));
    }

    Ok(())
}

/// Check if a CURP is a test/dummy pattern
///
/// Currently detects all-same-character inputs (e.g. `AAAAAAAAAAAAAAAAAA`).
#[must_use]
pub fn is_test_mexico_curp(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    let chars: Vec<char> = upper.chars().collect();
    if chars.len() != 18 {
        return false;
    }
    chars
        .first()
        .is_some_and(|&first| chars.iter().all(|&c| c == first))
}

// ============================================================================
// Helpers
// ============================================================================

/// Map a CURP character to its numeric value:
/// - `'0'..='9'` → 0..9
/// - `'A'..='Z'` → 10..35
/// - Anything else → 0
fn char_value(ch: char) -> u32 {
    if let Some(d) = ch.to_digit(10) {
        d
    } else if ch.is_ascii_uppercase() {
        u32::from(ch)
            .saturating_sub(u32::from('A'))
            .saturating_add(10)
    } else {
        0
    }
}

/// Compute the CURP check digit given the first 17 characters.
fn compute_curp_check_digit(first_17: &[char]) -> u32 {
    let mut sum: u32 = 0;
    for (i, &ch) in first_17.iter().enumerate() {
        let weight = 18_u32.saturating_sub(i as u32);
        sum = sum.saturating_add(char_value(ch).saturating_mul(weight));
    }
    let r = sum.checked_rem(10).unwrap_or(0);
    10_u32.saturating_sub(r).checked_rem(10).unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_valid_curp(first_17: &str) -> String {
        let chars: Vec<char> = first_17.to_uppercase().chars().collect();
        assert_eq!(chars.len(), 17, "make_valid_curp needs 17 chars");
        let check = compute_curp_check_digit(&chars);
        let mut out: String = chars.iter().collect();
        out.push(char::from_digit(check, 10).unwrap_or('0'));
        out
    }

    // ===== Format Tests =====

    #[test]
    fn test_validate_curp_well_formed() {
        // Generated CURP that satisfies all structural rules
        let curp = make_valid_curp("BADD110313HCMLNS0");
        assert!(validate_mexico_curp(&curp).is_ok());
    }

    #[test]
    fn test_validate_curp_lowercase_normalized() {
        let curp = make_valid_curp("BADD110313HCMLNS0");
        let lower = curp.to_lowercase();
        assert!(validate_mexico_curp(&lower).is_ok());
    }

    #[test]
    fn test_validate_curp_rejects_wrong_length() {
        assert!(validate_mexico_curp("BADD110313HDFLNS").is_err()); // 16
        assert!(validate_mexico_curp("BADD110313HDFLNS099").is_err()); // 19
    }

    #[test]
    fn test_validate_curp_rejects_empty() {
        assert!(validate_mexico_curp("").is_err());
    }

    #[test]
    fn test_validate_curp_rejects_bad_gender() {
        // Position 11 must be H or M
        let bad = "BADD110313XDFLNS09";
        assert!(validate_mexico_curp(bad).is_err());
    }

    #[test]
    fn test_validate_curp_rejects_bad_state() {
        // ZZ is not a valid Mexican state code
        let bad = "BADD110313HZZLNS09";
        assert!(validate_mexico_curp(bad).is_err());
    }

    #[test]
    fn test_validate_curp_accepts_foreign_born_ne() {
        let curp = make_valid_curp("BADD110313HNELNS0");
        assert!(validate_mexico_curp(&curp).is_ok());
    }

    #[test]
    fn test_validate_curp_rejects_digits_in_name() {
        let bad = "BAD0110313HDFLNS09";
        assert!(validate_mexico_curp(bad).is_err());
    }

    #[test]
    fn test_validate_curp_rejects_letters_in_date() {
        let bad = "BADDA10313HDFLNS09";
        assert!(validate_mexico_curp(bad).is_err());
    }

    // ===== Checksum Tests =====

    #[test]
    fn test_validate_curp_with_checksum_generated() {
        let curp = make_valid_curp("BADD110313HCMLNS0");
        assert!(validate_mexico_curp_with_checksum(&curp).is_ok());
    }

    #[test]
    fn test_validate_curp_with_checksum_tampered_last_digit() {
        let curp = make_valid_curp("BADD110313HCMLNS0");
        let mut chars: Vec<char> = curp.chars().collect();
        if let Some(c) = chars.last_mut() {
            *c = if *c == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_mexico_curp_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_curp_with_checksum_multiple_seeds() {
        for seed in &[
            "BADD110313HCMLNS0",
            "MEFR000123MJCLNS5",
            "PEAR700515HVZRLN8",
        ] {
            let curp = make_valid_curp(seed);
            assert!(
                validate_mexico_curp_with_checksum(&curp).is_ok(),
                "Generated CURP {curp} from seed {seed} should validate"
            );
        }
    }

    // ===== Test Pattern Tests =====

    #[test]
    fn test_is_test_mexico_curp_all_same() {
        assert!(is_test_mexico_curp("AAAAAAAAAAAAAAAAAA"));
        assert!(is_test_mexico_curp("000000000000000000"));
    }

    #[test]
    fn test_is_test_mexico_curp_rejects_real() {
        let curp = make_valid_curp("BADD110313HCMLNS0");
        assert!(!is_test_mexico_curp(&curp));
    }

    #[test]
    fn test_is_test_mexico_curp_rejects_wrong_length() {
        assert!(!is_test_mexico_curp("AAA"));
    }
}

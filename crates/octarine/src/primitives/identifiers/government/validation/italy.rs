//! Italy Codice Fiscale (fiscal code) validation
//!
//! Format: `[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]` (16 characters)
//!
//! Structure:
//! - Positions 1-3: surname consonants (then vowels, then X padding)
//! - Positions 4-6: name consonants (then vowels, then X padding)
//! - Positions 7-8: year of birth (last 2 digits)
//! - Position 9: month letter (A=Jan, B=Feb, ..., T=Dec)
//! - Positions 10-11: day of birth (females add 40)
//! - Position 12: municipality letter
//! - Positions 13-15: municipality digits
//! - Position 16: check character (computed from positions 1-15)
//!
//! Check character algorithm:
//! - Odd positions (1,3,5,...,15) use a special lookup table
//! - Even positions (2,4,6,...,14) use ordinal values
//! - Sum all values, mod 26, map to A-Z

use crate::primitives::types::Problem;

/// Valid month letters (A=Jan through T=Dec, not all letters used)
const MONTH_LETTERS: &[u8] = b"ABCDEHLMPRST";

/// Odd-position lookup values (indexed by character ordinal)
/// For digits 0-9 and letters A-Z
const ODD_VALUES: [u32; 36] = [
    // 0-9
    1, 0, 5, 7, 9, 13, 15, 17, 19, 21, // A-Z
    1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23,
];

/// Even-position lookup values (indexed by character ordinal)
/// Digits 0-9 → 0-9, Letters A-Z → 0-25
const EVEN_VALUES: [u32; 36] = [
    // 0-9
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, // A-Z
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
];

// ============================================================================
// Validation
// ============================================================================

/// Validate Italy Codice Fiscale format (without check character)
///
/// Checks: correct length, correct character types at each position,
/// valid month letter, valid day range.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_italy_fiscal_code(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim().to_uppercase();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Italy Codice Fiscale cannot be empty".to_string(),
        ));
    }

    if trimmed.len() != 16 {
        return Err(Problem::Validation(format!(
            "Italy Codice Fiscale must be 16 characters, got {}",
            trimmed.len()
        )));
    }

    let chars: Vec<char> = trimmed.chars().collect();

    // Positions 1-6 (index 0-5): letters
    for i in 0..6 {
        let ch = chars.get(i).copied().unwrap_or(' ');
        if !ch.is_ascii_uppercase() {
            return Err(Problem::Validation(format!(
                "Italy Codice Fiscale position {} must be a letter, got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    // Positions 7-8 (index 6-7): digits
    for i in 6..8 {
        let ch = chars.get(i).copied().unwrap_or(' ');
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "Italy Codice Fiscale position {} must be a digit, got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    // Position 9 (index 8): month letter
    let month_char = chars.get(8).copied().unwrap_or(' ');
    if !month_char.is_ascii_uppercase() {
        return Err(Problem::Validation(format!(
            "Italy Codice Fiscale position 9 must be a letter, got '{}'",
            month_char
        )));
    }
    if !MONTH_LETTERS.contains(&(month_char as u8)) {
        return Err(Problem::Validation(format!(
            "Italy Codice Fiscale invalid month letter '{}'",
            month_char
        )));
    }

    // Positions 10-11 (index 9-10): day digits
    for i in 9..11 {
        let ch = chars.get(i).copied().unwrap_or(' ');
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "Italy Codice Fiscale position {} must be a digit, got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    // Validate day (01-31 for males, 41-71 for females)
    let day = parse_two_digits(&chars, 9)?;
    if !((1..=31).contains(&day) || (41..=71).contains(&day)) {
        return Err(Problem::Validation(format!(
            "Italy Codice Fiscale day must be 01-31 (male) or 41-71 (female), got {:02}",
            day
        )));
    }

    // Position 12 (index 11): municipality letter
    let mun_char = chars.get(11).copied().unwrap_or(' ');
    if !mun_char.is_ascii_uppercase() {
        return Err(Problem::Validation(format!(
            "Italy Codice Fiscale position 12 must be a letter, got '{}'",
            mun_char
        )));
    }

    // Positions 13-15 (index 12-14): municipality digits
    for i in 12..15 {
        let ch = chars.get(i).copied().unwrap_or(' ');
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "Italy Codice Fiscale position {} must be a digit, got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    // Position 16 (index 15): check character (letter)
    let check_char = chars.get(15).copied().unwrap_or(' ');
    if !check_char.is_ascii_uppercase() {
        return Err(Problem::Validation(format!(
            "Italy Codice Fiscale position 16 must be a letter, got '{}'",
            check_char
        )));
    }

    Ok(())
}

/// Validate Italy Codice Fiscale with check character
///
/// Computes the check character from positions 1-15 using odd/even
/// position lookup tables and compares with position 16.
///
/// # Errors
///
/// Returns `Problem::Validation` if format or check character is invalid.
pub fn validate_italy_fiscal_code_with_checksum(value: &str) -> Result<(), Problem> {
    validate_italy_fiscal_code(value)?;

    let trimmed = value.trim().to_uppercase();
    let chars: Vec<char> = trimmed.chars().collect();

    let mut sum = 0u32;

    // Process positions 1-15 (index 0-14)
    for i in 0..15 {
        let ch = chars.get(i).copied().unwrap_or(' ');
        let idx = char_to_index(ch)?;

        // 1-indexed: odd positions (1,3,5,...) use odd table
        // Even positions (2,4,6,...) use even table
        let position_1indexed = i.saturating_add(1);
        let value = if position_1indexed % 2 == 1 {
            ODD_VALUES.get(idx).copied().unwrap_or(0)
        } else {
            EVEN_VALUES.get(idx).copied().unwrap_or(0)
        };

        sum = sum.saturating_add(value);
    }

    let remainder = (sum % 26) as u8;
    let expected = (b'A').saturating_add(remainder) as char;
    let actual = chars.get(15).copied().unwrap_or(' ');

    if actual != expected {
        return Err(Problem::Validation(format!(
            "Italy Codice Fiscale check character failed: expected '{}', got '{}'",
            expected, actual
        )));
    }

    Ok(())
}

/// Check if an Italy Codice Fiscale is a test/dummy pattern
#[must_use]
pub fn is_test_italy_fiscal_code(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if upper.len() != 16 {
        return false;
    }

    // All X's in name portion (common test pattern)
    if upper.starts_with("XXXXXX") {
        return true;
    }

    // All same letter in surname+name
    let name_part: &str = upper.get(..6).unwrap_or("");
    let first = name_part.chars().next().unwrap_or('_');
    if first.is_ascii_uppercase() && name_part.chars().all(|c| c == first) {
        return true;
    }

    false
}

// ============================================================================
// Italy Partita IVA (VAT) — 11 digits, mod-10 Luhn-style checksum
// ============================================================================

/// Validate Italy Partita IVA (VAT) format: exactly 11 digits.
///
/// Does NOT verify the mod-10 checksum — see
/// [`validate_italy_vat_with_checksum`] for that.
///
/// # Errors
///
/// Returns `Problem::Validation` if the value is not exactly 11 ASCII
/// digits.
pub fn validate_italy_vat(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.len() != 11 {
        return Err(Problem::Validation(format!(
            "Italy VAT must be exactly 11 digits, got {} characters",
            trimmed.len()
        )));
    }
    if !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Err(Problem::Validation(
            "Italy VAT must contain only digits".to_string(),
        ));
    }
    Ok(())
}

/// Validate Italy Partita IVA with mod-10 Luhn-style checksum.
///
/// Algorithm: positions 1,3,5,7,9 (1-indexed odd) are summed as-is.
/// Positions 2,4,6,8,10 are doubled; if the doubled value is ≥ 10, the
/// digits of the doubled value are summed. The check digit (position 11)
/// must equal `(10 - (sum % 10)) % 10`.
///
/// # Errors
///
/// Returns `Problem::Validation` if format or checksum is invalid.
pub fn validate_italy_vat_with_checksum(value: &str) -> Result<(), Problem> {
    validate_italy_vat(value)?;

    let trimmed = value.trim();
    let digits: Vec<u32> = trimmed.chars().filter_map(|c| c.to_digit(10)).collect();

    if digits.len() != 11 {
        return Err(Problem::Validation(
            "Italy VAT: expected 11 digits after parsing".to_string(),
        ));
    }

    let mut sum: u32 = 0;
    for (i, digit) in digits.iter().take(10).enumerate() {
        let position_1indexed = i.saturating_add(1);
        if position_1indexed.is_multiple_of(2) {
            // Even position (2,4,6,8,10) — double; if ≥ 10, sum the digits
            let doubled = digit.saturating_mul(2);
            sum = sum.saturating_add(if doubled >= 10 {
                doubled.saturating_sub(9)
            } else {
                doubled
            });
        } else {
            // Odd position (1,3,5,7,9) — add as-is
            sum = sum.saturating_add(*digit);
        }
    }

    let expected = (10u32.saturating_sub(sum % 10)) % 10;
    let actual = digits.get(10).copied().unwrap_or(99);

    if actual != expected {
        return Err(Problem::Validation(format!(
            "Italy VAT checksum failed: expected '{}', got '{}'",
            expected, actual
        )));
    }

    Ok(())
}

/// Check if an Italy VAT is a test/dummy pattern (all same digit, or
/// the common sequential `12345678901` form).
#[must_use]
pub fn is_test_italy_vat(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() != 11 {
        return false;
    }
    if !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    // All same digit (00000000000, 11111111111, ...)
    let first = trimmed.chars().next().unwrap_or('_');
    if trimmed.chars().all(|c| c == first) {
        return true;
    }
    // Sequential test pattern
    if trimmed == "12345678901" || trimmed == "01234567890" {
        return true;
    }
    false
}

// ============================================================================
// Italy Passport — 2 uppercase letters + 7 digits
// ============================================================================

/// Validate Italy passport format: 2 uppercase letters + 7 digits.
///
/// Case-insensitive. Italian passports have no public checksum, so this
/// is a format check only.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_italy_passport(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.len() != 9 {
        return Err(Problem::Validation(format!(
            "Italy passport must be 9 characters (2 letters + 7 digits), got {}",
            trimmed.len()
        )));
    }
    let upper = trimmed.to_uppercase();
    let mut chars = upper.chars();
    let c1 = chars.next().unwrap_or(' ');
    let c2 = chars.next().unwrap_or(' ');
    if !c1.is_ascii_uppercase() || !c2.is_ascii_uppercase() {
        return Err(Problem::Validation(
            "Italy passport must start with 2 letters".to_string(),
        ));
    }
    if !chars.all(|c| c.is_ascii_digit()) {
        return Err(Problem::Validation(
            "Italy passport positions 3-9 must be digits".to_string(),
        ));
    }
    Ok(())
}

/// Check if an Italy passport is a test/dummy pattern.
#[must_use]
pub fn is_test_italy_passport(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if upper.len() != 9 {
        return false;
    }
    // Common test prefixes
    upper.starts_with("AA")
        && upper
            .get(2..)
            .is_some_and(|d| d == "1234567" || d == "0000000")
}

// ============================================================================
// Italy Identity Card (Carta d'Identità) — three coexisting formats
// ============================================================================

/// Identity card format variant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItalyIdentityCardFormat {
    /// Legacy paper: 2 letters + (optional space) + 7 digits
    Paper,
    /// CIE 2.0: 7 digits + 2 letters
    CieV2,
    /// CIE 3.0: 2 letters + 5 digits + 2 letters
    CieV3,
}

/// Validate Italy identity card against any of the three supported formats.
///
/// Format only — no public checksum.
///
/// # Errors
///
/// Returns `Problem::Validation` if the value matches none of: paper,
/// CIE 2.0, or CIE 3.0.
pub fn validate_italy_identity_card(value: &str) -> Result<(), Problem> {
    identify_italy_identity_card_format(value).map(|_| ())
}

/// Return which Italy identity card format the value matches, if any.
///
/// # Errors
///
/// Returns `Problem::Validation` if the value matches none of the three
/// supported layouts.
pub fn identify_italy_identity_card_format(
    value: &str,
) -> Result<ItalyIdentityCardFormat, Problem> {
    let upper: String = value
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();

    let chars: Vec<char> = upper.chars().collect();

    // Paper: 2 letters + 7 digits (9 chars after whitespace removal)
    if chars.len() == 9
        && chars.iter().take(2).all(|c| c.is_ascii_uppercase())
        && chars.iter().skip(2).all(|c| c.is_ascii_digit())
    {
        return Ok(ItalyIdentityCardFormat::Paper);
    }

    // CIE 2.0: 7 digits + 2 letters (9 chars)
    if chars.len() == 9
        && chars.iter().take(7).all(|c| c.is_ascii_digit())
        && chars.iter().skip(7).all(|c| c.is_ascii_uppercase())
    {
        return Ok(ItalyIdentityCardFormat::CieV2);
    }

    // CIE 3.0: 2 letters + 5 digits + 2 letters (9 chars)
    if chars.len() == 9
        && chars.iter().take(2).all(|c| c.is_ascii_uppercase())
        && chars.iter().skip(2).take(5).all(|c| c.is_ascii_digit())
        && chars.iter().skip(7).all(|c| c.is_ascii_uppercase())
    {
        return Ok(ItalyIdentityCardFormat::CieV3);
    }

    Err(Problem::Validation(format!(
        "Italy identity card does not match paper, CIE 2.0, or CIE 3.0 format: {}",
        value
    )))
}

/// Check if an Italy identity card is a test/dummy pattern.
#[must_use]
pub fn is_test_italy_identity_card(value: &str) -> bool {
    let upper: String = value
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    if upper.len() != 9 {
        return false;
    }
    // All-same character is the most common test pattern (e.g., AAAAAAAAA);
    // also detect the documentation-style "AA0000000" / "CA1111111" forms
    // where the leading two characters precede a repeating digit run.
    let chars: Vec<char> = upper.chars().collect();
    let all_same_suffix = chars.iter().skip(2).all(|c| Some(c) == chars.get(2));
    let suffix_is_test_digits = chars.iter().skip(2).all(|c| matches!(c, '0' | '1'));
    all_same_suffix || suffix_is_test_digits
}

// ============================================================================
// Italy Driver License (Patente di Guida)
// ============================================================================

/// Validate Italy driver license format: either `AA1234567A` (standard
/// modern form, 2 letters + 7 digits + 1 letter) or the legacy `U1` Carta
/// Conducente form (`U1` + 7 chars from the restricted alphabet
/// `BCDEFGHLJKMNPRSTUWYXZ0-9` + 1 letter).
///
/// Format only — no public checksum.
///
/// # Errors
///
/// Returns `Problem::Validation` if the value matches neither form.
pub fn validate_italy_driver_license(value: &str) -> Result<(), Problem> {
    let upper = value.trim().to_uppercase();
    if upper.len() != 10 {
        return Err(Problem::Validation(format!(
            "Italy driver license must be 10 characters, got {}",
            upper.len()
        )));
    }
    let chars: Vec<char> = upper.chars().collect();

    // Standard: [A-Z]{2}\d{7}[A-Z]
    let is_standard = chars.iter().take(2).all(|c| c.is_ascii_uppercase())
        && chars.iter().skip(2).take(7).all(|c| c.is_ascii_digit())
        && chars.get(9).is_some_and(|c| c.is_ascii_uppercase());

    // Legacy U1: U1 + 7 chars from restricted alphabet + 1 letter
    let restricted = "BCDEFGHLJKMNPRSTUWYXZ0123456789";
    let is_u1 = chars.first() == Some(&'U')
        && chars.get(1) == Some(&'1')
        && chars
            .iter()
            .skip(2)
            .take(7)
            .all(|c| restricted.contains(*c))
        && chars.get(9).is_some_and(|c| c.is_ascii_uppercase());

    if !is_standard && !is_u1 {
        return Err(Problem::Validation(format!(
            "Italy driver license does not match standard or U1 form: {}",
            value
        )));
    }
    Ok(())
}

/// Check if an Italy driver license is a test/dummy pattern.
#[must_use]
pub fn is_test_italy_driver_license(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if upper.len() != 10 {
        return false;
    }
    // Standard prefix `AA` with test-looking middle (0000000 or 1234567)
    if upper.starts_with("AA")
        && let Some(mid) = upper.get(2..9)
    {
        return mid == "0000000" || mid == "1234567";
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

/// Convert a character to its index in the lookup tables
/// Digits 0-9 → index 0-9, Letters A-Z → index 10-35
fn char_to_index(ch: char) -> Result<usize, Problem> {
    if ch.is_ascii_digit() {
        Ok((ch as usize).saturating_sub('0' as usize))
    } else if ch.is_ascii_uppercase() {
        Ok((ch as usize)
            .saturating_sub('A' as usize)
            .saturating_add(10))
    } else {
        Err(Problem::Validation(format!(
            "Italy Codice Fiscale: invalid character '{}'",
            ch
        )))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    /// Compute check character from first 15 characters
    fn compute_check_char(first_15: &str) -> char {
        assert_eq!(first_15.len(), 15, "Need exactly 15 characters");
        let upper = first_15.to_uppercase();
        let mut sum = 0u32;

        for (i, ch) in upper.chars().enumerate() {
            let idx = char_to_index(ch).expect("valid char");
            let position = i + 1; // 1-indexed
            let value = if position % 2 == 1 {
                ODD_VALUES.get(idx).copied().expect("valid index")
            } else {
                EVEN_VALUES.get(idx).copied().expect("valid index")
            };
            sum += value;
        }

        let remainder = (sum % 26) as u8;
        (b'A' + remainder) as char
    }

    /// Build a valid Codice Fiscale from components
    fn make_valid_cf(
        surname: &str,
        name: &str,
        year: &str,
        month: char,
        day: &str,
        municipality: &str,
    ) -> String {
        let first_15 = format!(
            "{}{}{}{}{}{}",
            surname, name, year, month, day, municipality
        );
        assert_eq!(first_15.len(), 15, "Components must total 15 chars");
        let check = compute_check_char(&first_15);
        format!("{}{}", first_15, check)
    }

    // ===== Format validation =====

    #[test]
    fn test_validate_cf_valid() {
        // RSSMRA85M01H501 + check
        let cf = make_valid_cf("RSS", "MRA", "85", 'M', "01", "H501");
        assert!(validate_italy_fiscal_code(&cf).is_ok(), "Valid CF: {}", cf);
    }

    #[test]
    fn test_validate_cf_female() {
        // Day 41-71 for females (day + 40)
        let cf = make_valid_cf("RSS", "MRA", "85", 'M', "41", "H501");
        assert!(
            validate_italy_fiscal_code(&cf).is_ok(),
            "Valid female CF: {}",
            cf
        );
    }

    #[test]
    fn test_validate_cf_all_month_letters() {
        for &month in MONTH_LETTERS {
            let cf = make_valid_cf("RSS", "MRA", "85", month as char, "01", "H501");
            assert!(
                validate_italy_fiscal_code(&cf).is_ok(),
                "Month '{}' should be valid",
                month as char
            );
        }
    }

    #[test]
    fn test_validate_cf_empty() {
        assert!(validate_italy_fiscal_code("").is_err());
    }

    #[test]
    fn test_validate_cf_wrong_length() {
        assert!(validate_italy_fiscal_code("RSSMRA85M01H50").is_err()); // 14 chars
        assert!(validate_italy_fiscal_code("RSSMRA85M01H501ZZ").is_err()); // 17 chars
    }

    #[test]
    fn test_validate_cf_invalid_month_letter() {
        // 'F' is not a valid month letter
        assert!(validate_italy_fiscal_code("RSSMRA85F01H501Z").is_err());
    }

    #[test]
    fn test_validate_cf_invalid_day() {
        // Day 00 invalid
        assert!(validate_italy_fiscal_code("RSSMRA85M00H501Z").is_err());
        // Day 32 invalid (neither male 01-31 nor female 41-71)
        assert!(validate_italy_fiscal_code("RSSMRA85M32H501Z").is_err());
        // Day 40 invalid (between male and female ranges)
        assert!(validate_italy_fiscal_code("RSSMRA85M40H501Z").is_err());
        // Day 72 invalid
        assert!(validate_italy_fiscal_code("RSSMRA85M72H501Z").is_err());
    }

    #[test]
    fn test_validate_cf_digit_where_letter_expected() {
        assert!(validate_italy_fiscal_code("1SSMRA85M01H501Z").is_err()); // Pos 1 digit
    }

    #[test]
    fn test_validate_cf_letter_where_digit_expected() {
        assert!(validate_italy_fiscal_code("RSSMRAAM01H501Z").is_err()); // Pos 7-8 letters
    }

    // ===== Checksum validation =====

    #[test]
    fn test_validate_cf_with_checksum_valid() {
        let cf = make_valid_cf("RSS", "MRA", "85", 'M', "01", "H501");
        assert!(
            validate_italy_fiscal_code_with_checksum(&cf).is_ok(),
            "Valid CF with checksum: {}",
            cf
        );
    }

    #[test]
    fn test_validate_cf_with_checksum_female() {
        let cf = make_valid_cf("RSS", "MRA", "85", 'M', "41", "H501");
        assert!(
            validate_italy_fiscal_code_with_checksum(&cf).is_ok(),
            "Valid female CF with checksum: {}",
            cf
        );
    }

    #[test]
    fn test_validate_cf_with_checksum_invalid() {
        let cf = make_valid_cf("RSS", "MRA", "85", 'M', "01", "H501");
        // Tamper with check character
        let mut chars: Vec<char> = cf.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == 'A' { 'B' } else { 'A' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_italy_fiscal_code_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_validate_cf_with_checksum_all_months() {
        for &month in MONTH_LETTERS {
            let cf = make_valid_cf("BNC", "LRA", "90", month as char, "15", "F205");
            assert!(
                validate_italy_fiscal_code_with_checksum(&cf).is_ok(),
                "Month '{}' CF should pass checksum: {}",
                month as char,
                cf
            );
        }
    }

    #[test]
    fn test_validate_cf_case_insensitive() {
        let cf = make_valid_cf("RSS", "MRA", "85", 'M', "01", "H501");
        let lower = cf.to_lowercase();
        assert!(
            validate_italy_fiscal_code_with_checksum(&lower).is_ok(),
            "Lowercase CF should be valid: {}",
            lower
        );
    }

    // ===== Test pattern detection =====

    #[test]
    fn test_is_test_cf() {
        // All X's in name
        let cf = make_valid_cf("XXX", "XXX", "00", 'A', "01", "A000");
        assert!(is_test_italy_fiscal_code(&cf));
    }

    #[test]
    fn test_is_test_cf_same_letter() {
        let cf = make_valid_cf("AAA", "AAA", "00", 'A', "01", "A000");
        assert!(is_test_italy_fiscal_code(&cf));
    }

    #[test]
    fn test_is_test_cf_not_test() {
        let cf = make_valid_cf("RSS", "MRA", "85", 'M', "01", "H501");
        assert!(!is_test_italy_fiscal_code(&cf));
    }

    #[test]
    fn test_is_test_cf_wrong_length() {
        assert!(!is_test_italy_fiscal_code("12345"));
        assert!(!is_test_italy_fiscal_code(""));
    }

    // ===== Lookup table verification =====

    #[test]
    fn test_odd_values_length() {
        assert_eq!(ODD_VALUES.len(), 36); // 10 digits + 26 letters
    }

    #[test]
    fn test_even_values_length() {
        assert_eq!(EVEN_VALUES.len(), 36);
    }

    #[test]
    fn test_month_letters_length() {
        assert_eq!(MONTH_LETTERS.len(), 12); // 12 months
    }

    #[test]
    fn test_char_to_index() {
        assert_eq!(char_to_index('0').expect("ok"), 0);
        assert_eq!(char_to_index('9').expect("ok"), 9);
        assert_eq!(char_to_index('A').expect("ok"), 10);
        assert_eq!(char_to_index('Z').expect("ok"), 35);
        assert!(char_to_index('a').is_err()); // lowercase
    }

    // =========================================================================
    // Italy VAT (Partita IVA) tests
    // =========================================================================

    #[test]
    fn test_validate_italy_vat_format() {
        assert!(validate_italy_vat("12345678903").is_ok());
        assert!(validate_italy_vat("00000000000").is_ok());
        assert!(validate_italy_vat("01234567897").is_ok());
    }

    #[test]
    fn test_validate_italy_vat_wrong_length() {
        assert!(validate_italy_vat("1234567890").is_err()); // 10 digits
        assert!(validate_italy_vat("123456789012").is_err()); // 12 digits
        assert!(validate_italy_vat("").is_err());
    }

    #[test]
    fn test_validate_italy_vat_non_digit() {
        assert!(validate_italy_vat("1234567890A").is_err());
        assert!(validate_italy_vat("ABCDEFGHIJK").is_err());
    }

    #[test]
    fn test_validate_italy_vat_with_checksum_valid() {
        // 12345678903: odd-pos sum 1+3+5+7+9=25;
        // even-pos doubled+digit-sum 4+8+3+7+0=22; total 47;
        // check (10 - 47%10) % 10 = 3 ✓
        assert!(validate_italy_vat_with_checksum("12345678903").is_ok());
        // 01234567897: odd 0+2+4+6+8=20; even 2+6+1+5+9=23; total 43; check 7 ✓
        assert!(validate_italy_vat_with_checksum("01234567897").is_ok());
        // 00000000000: sum 0; check 0 ✓
        assert!(validate_italy_vat_with_checksum("00000000000").is_ok());
    }

    #[test]
    fn test_validate_italy_vat_with_checksum_invalid() {
        // Wrong check digit
        assert!(validate_italy_vat_with_checksum("12345678901").is_err());
        assert!(validate_italy_vat_with_checksum("12345678904").is_err());
    }

    #[test]
    fn test_is_test_italy_vat() {
        assert!(is_test_italy_vat("00000000000"));
        assert!(is_test_italy_vat("11111111111"));
        assert!(is_test_italy_vat("12345678901"));
        assert!(!is_test_italy_vat("12345678903"));
        assert!(!is_test_italy_vat("invalid"));
    }

    // =========================================================================
    // Italy passport tests
    // =========================================================================

    #[test]
    fn test_validate_italy_passport_valid() {
        assert!(validate_italy_passport("AA1234567").is_ok());
        assert!(validate_italy_passport("YA0000000").is_ok());
        // Lowercase accepted (case-insensitive uppercased internally)
        assert!(validate_italy_passport("aa1234567").is_ok());
    }

    #[test]
    fn test_validate_italy_passport_invalid() {
        assert!(validate_italy_passport("A1234567").is_err()); // 8 chars
        assert!(validate_italy_passport("AA12345678").is_err()); // 10 chars
        assert!(validate_italy_passport("1A1234567").is_err()); // digit at pos 1
        assert!(validate_italy_passport("AAA234567").is_err()); // letter at pos 3
        assert!(validate_italy_passport("").is_err());
    }

    #[test]
    fn test_is_test_italy_passport() {
        assert!(is_test_italy_passport("AA1234567"));
        assert!(is_test_italy_passport("AA0000000"));
        assert!(!is_test_italy_passport("YA1357924"));
    }

    // =========================================================================
    // Italy identity card tests (paper, CIE 2.0, CIE 3.0)
    // =========================================================================

    #[test]
    fn test_validate_italy_identity_card_paper() {
        // Paper: 2 letters + 7 digits (with or without space)
        assert!(validate_italy_identity_card("CA1234567").is_ok());
        assert!(validate_italy_identity_card("CA 1234567").is_ok());
        assert_eq!(
            identify_italy_identity_card_format("CA1234567").expect("ok"),
            ItalyIdentityCardFormat::Paper
        );
    }

    #[test]
    fn test_validate_italy_identity_card_cie_v2() {
        // CIE 2.0: 7 digits + 2 letters
        assert!(validate_italy_identity_card("1234567AB").is_ok());
        assert_eq!(
            identify_italy_identity_card_format("1234567AB").expect("ok"),
            ItalyIdentityCardFormat::CieV2
        );
    }

    #[test]
    fn test_validate_italy_identity_card_cie_v3() {
        // CIE 3.0: 2 letters + 5 digits + 2 letters
        assert!(validate_italy_identity_card("CA12345AB").is_ok());
        assert_eq!(
            identify_italy_identity_card_format("CA12345AB").expect("ok"),
            ItalyIdentityCardFormat::CieV3
        );
    }

    #[test]
    fn test_validate_italy_identity_card_invalid() {
        assert!(validate_italy_identity_card("").is_err());
        assert!(validate_italy_identity_card("ABCDEFGHI").is_err()); // all letters
        assert!(validate_italy_identity_card("123456789").is_err()); // all digits
        assert!(validate_italy_identity_card("CA12345").is_err()); // too short
    }

    #[test]
    fn test_is_test_italy_identity_card() {
        assert!(is_test_italy_identity_card("AA0000000"));
        assert!(is_test_italy_identity_card("CA1111111"));
        assert!(!is_test_italy_identity_card("CA7395182"));
    }

    // =========================================================================
    // Italy driver license tests (standard + legacy U1 Carta Conducente)
    // =========================================================================

    #[test]
    fn test_validate_italy_driver_license_standard() {
        assert!(validate_italy_driver_license("AB1234567C").is_ok());
        assert!(validate_italy_driver_license("MI0123456Z").is_ok());
        // Case-insensitive
        assert!(validate_italy_driver_license("ab1234567c").is_ok());
    }

    #[test]
    fn test_validate_italy_driver_license_u1() {
        // U1 Carta Conducente — restricted alphabet excludes A, I, O, Q, V
        assert!(validate_italy_driver_license("U1B123456C").is_ok());
        assert!(validate_italy_driver_license("U1D7654321K").is_err()); // too long
        assert!(validate_italy_driver_license("U1B234567C").is_ok());
    }

    #[test]
    fn test_validate_italy_driver_license_invalid() {
        assert!(validate_italy_driver_license("").is_err());
        assert!(validate_italy_driver_license("AB1234567").is_err()); // 9 chars
        assert!(validate_italy_driver_license("AB12345678C").is_err()); // 11 chars
        assert!(validate_italy_driver_license("1B1234567C").is_err()); // digit at pos 1
        // U1 form with excluded letter (A) in restricted middle
        assert!(validate_italy_driver_license("U1A234567C").is_err());
    }

    #[test]
    fn test_is_test_italy_driver_license() {
        assert!(is_test_italy_driver_license("AA0000000Z"));
        assert!(is_test_italy_driver_license("AA1234567Z"));
        assert!(!is_test_italy_driver_license("MI7395182Z"));
    }
}

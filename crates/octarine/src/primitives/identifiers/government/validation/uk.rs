//! UK identifier validation — NHS Number, Passport, Driving Licence (DVLA)
//!
//! - **NHS Number**: 10 digits with a mod-11 weighted checksum. The first
//!   9 digits are multiplied by weights `10, 9, 8, 7, 6, 5, 4, 3, 2`; the
//!   weighted sum mod 11 yields the expected check digit (11 minus remainder,
//!   with remainder 0 → check digit 0 and remainder 1 → invalid number).
//! - **UK Passport**: 2 uppercase letters + 7 digits. No publicly published
//!   checksum, so validation is format-only.
//! - **UK Driving Licence (DVLA)**: 16-character structural shape
//!   `[A-Z9]{5}\d{6}[A-Z9]{2}\d[A-Z0-9]{2}`. DVLA's check-digit algorithm is
//!   not publicly published, so validation is shape-only with placeholder
//!   rejection (all-9 surname is the canonical sentinel).
//!
//! Layer 1: Pure functions, no observe dependencies.

use crate::primitives::types::Problem;

// ============================================================================
// UK NHS Number — 10 digits, mod-11 weighted checksum
// ============================================================================

/// Strip space and hyphen separators from an NHS Number candidate.
fn strip_nhs_separators(value: &str) -> String {
    value.chars().filter(|c| *c != ' ' && *c != '-').collect()
}

/// Validate UK NHS Number format (10 digits after stripping spaces/hyphens).
///
/// Accepts the grouped `NNN NNN NNNN` display form and the bare 10-digit form.
/// This is a format-only check — use
/// [`validate_uk_nhs_with_checksum`] to additionally verify the
/// mod-11 weighted check digit.
///
/// # Errors
///
/// Returns `Problem::Validation` if the input does not have exactly 10
/// decimal digits after separator removal.
pub fn validate_uk_nhs(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "UK NHS Number cannot be empty".to_string(),
        ));
    }
    let stripped = strip_nhs_separators(trimmed);
    if stripped.len() != 10 {
        return Err(Problem::Validation(format!(
            "UK NHS Number must be 10 digits, got {}",
            stripped.len()
        )));
    }
    if !stripped.chars().all(|c| c.is_ascii_digit()) {
        return Err(Problem::Validation(
            "UK NHS Number must contain only digits".to_string(),
        ));
    }
    Ok(())
}

/// Validate UK NHS Number including the mod-11 weighted checksum.
///
/// Algorithm: multiply the first 9 digits by descending weights `10..=2`,
/// sum, then take mod 11. The expected check digit is `11 - remainder`
/// (with remainder 0 mapping to 0). A remainder of 1 means the number is
/// invalid — no NHS Number assigns a check digit of 10.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format check fails, the number is
/// a placeholder (all-same-digit), or the checksum does not match.
pub fn validate_uk_nhs_with_checksum(value: &str) -> Result<(), Problem> {
    validate_uk_nhs(value)?;

    let stripped = strip_nhs_separators(value.trim());
    let digits: Vec<u32> = stripped.chars().filter_map(|c| c.to_digit(10)).collect();

    // Placeholder rejection: all-same-digit numbers (0000000000, 9999999999)
    // are test fixtures, not real NHS Numbers, even when they happen to pass
    // the checksum.
    let first = digits.first().copied().unwrap_or(99);
    if digits.iter().all(|&d| d == first) {
        return Err(Problem::Validation(
            "UK NHS Number is a placeholder pattern (all identical digits)".to_string(),
        ));
    }

    let mut sum: u32 = 0;
    for (i, &d) in digits.iter().take(9).enumerate() {
        let weight = 10u32.saturating_sub(i as u32);
        sum = sum.saturating_add(d.saturating_mul(weight));
    }
    let remainder = sum % 11;

    if remainder == 1 {
        return Err(Problem::Validation(
            "UK NHS Number checksum remainder is 1 (no valid number maps to check digit 10)"
                .to_string(),
        ));
    }

    let expected = if remainder == 0 {
        0
    } else {
        11u32.saturating_sub(remainder)
    };
    let actual = digits.get(9).copied().unwrap_or(99);
    if actual != expected {
        return Err(Problem::Validation(format!(
            "UK NHS Number checksum failed: expected '{}', got '{}'",
            expected, actual
        )));
    }
    Ok(())
}

/// Check if a UK NHS Number is a test/dummy pattern.
#[must_use]
pub fn is_test_uk_nhs(value: &str) -> bool {
    let stripped = strip_nhs_separators(value.trim());
    if stripped.len() != 10 || !stripped.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let first = stripped.chars().next().unwrap_or('_');
    stripped.chars().all(|c| c == first)
}

// ============================================================================
// UK Passport — 2 uppercase letters + 7 digits
// ============================================================================

/// Validate UK passport format: 2 uppercase letters + 7 digits.
///
/// Case-insensitive. The UK passport number has no publicly published
/// checksum, so this is a format check only.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_uk_passport(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.len() != 9 {
        return Err(Problem::Validation(format!(
            "UK passport must be 9 characters (2 letters + 7 digits), got {}",
            trimmed.len()
        )));
    }
    let upper = trimmed.to_uppercase();
    let mut chars = upper.chars();
    let c1 = chars.next().unwrap_or(' ');
    let c2 = chars.next().unwrap_or(' ');
    if !c1.is_ascii_uppercase() || !c2.is_ascii_uppercase() {
        return Err(Problem::Validation(
            "UK passport must start with 2 letters".to_string(),
        ));
    }
    if !chars.all(|c| c.is_ascii_digit()) {
        return Err(Problem::Validation(
            "UK passport positions 3-9 must be digits".to_string(),
        ));
    }
    Ok(())
}

/// Check if a UK passport is a test/dummy pattern.
#[must_use]
pub fn is_test_uk_passport(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if upper.len() != 9 {
        return false;
    }
    let digits = match upper.get(2..) {
        Some(d) => d,
        None => return false,
    };
    digits == "0000000" || digits == "1234567"
}

// ============================================================================
// UK Driving Licence (DVLA) — 16-character structural format
// ============================================================================

/// Validate UK DVLA driving licence shape (16 characters).
///
/// Layout: `[A-Z9]{5}\d{6}[A-Z9]{2}\d[A-Z0-9]{2}`
///   - Positions 1-5: surname (padded with `9` to fill 5 chars)
///   - Positions 6-11: DOB-derived digits
///   - Positions 12-13: initials (filled with `9` if missing)
///   - Position 14: check digit (algorithm not publicly published)
///   - Positions 15-16: control characters (uppercase letters or digits)
///
/// DVLA's check-digit algorithm is not public, so this is a shape-only check
/// with placeholder rejection: a surname of `99999` is the DVLA sentinel for
/// an unassigned licence and is rejected here as a synthetic value.
///
/// # Errors
///
/// Returns `Problem::Validation` if the length, character classes, or
/// surname placeholder check fails.
pub fn validate_uk_driving_licence(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "UK driving licence cannot be empty".to_string(),
        ));
    }
    if trimmed.len() != 16 {
        return Err(Problem::Validation(format!(
            "UK driving licence must be 16 characters, got {}",
            trimmed.len()
        )));
    }
    let upper = trimmed.to_uppercase();
    let chars: Vec<char> = upper.chars().collect();

    // Positions 1-5 (index 0-4): uppercase letters or '9' padding
    for i in 0..5 {
        let ch = chars.get(i).copied().unwrap_or(' ');
        if !(ch.is_ascii_uppercase() || ch == '9') {
            return Err(Problem::Validation(format!(
                "UK driving licence position {} must be A-Z or '9', got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    // Surname placeholder rejection: all '9' is the DVLA sentinel for an
    // unassigned licence — Presidio rejects it because real DVLA records
    // never use this pattern.
    let surname = chars.get(0..5).unwrap_or(&[]);
    if !surname.is_empty() && surname.iter().all(|&c| c == '9') {
        return Err(Problem::Validation(
            "UK driving licence surname is the placeholder '99999'".to_string(),
        ));
    }

    // Positions 6-11 (index 5-10): digits
    for i in 5..11 {
        let ch = chars.get(i).copied().unwrap_or(' ');
        if !ch.is_ascii_digit() {
            return Err(Problem::Validation(format!(
                "UK driving licence position {} must be a digit, got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    // Positions 12-13 (index 11-12): uppercase letters or '9' padding
    for i in 11..13 {
        let ch = chars.get(i).copied().unwrap_or(' ');
        if !(ch.is_ascii_uppercase() || ch == '9') {
            return Err(Problem::Validation(format!(
                "UK driving licence position {} must be A-Z or '9', got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    // Position 14 (index 13): check digit
    let check = chars.get(13).copied().unwrap_or(' ');
    if !check.is_ascii_digit() {
        return Err(Problem::Validation(format!(
            "UK driving licence position 14 must be a digit, got '{}'",
            check
        )));
    }

    // Positions 15-16 (index 14-15): control alphanumeric
    for i in 14..16 {
        let ch = chars.get(i).copied().unwrap_or(' ');
        if !(ch.is_ascii_uppercase() || ch.is_ascii_digit()) {
            return Err(Problem::Validation(format!(
                "UK driving licence position {} must be alphanumeric, got '{}'",
                i.saturating_add(1),
                ch
            )));
        }
    }

    Ok(())
}

/// Check if a UK driving licence is a test/dummy pattern.
#[must_use]
pub fn is_test_uk_driving_licence(value: &str) -> bool {
    let upper = value.trim().to_uppercase();
    if upper.len() != 16 {
        return false;
    }
    let chars: Vec<char> = upper.chars().collect();
    // All-9 surname is the DVLA placeholder
    let surname = chars.get(0..5).unwrap_or(&[]);
    !surname.is_empty() && surname.iter().all(|&c| c == '9')
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ----- NHS Number -----

    #[test]
    fn test_nhs_real_test_number_passes_checksum() {
        // 9434765919 is the canonical NHS Digital test number used in DCB0129
        // / DCB0160 fixtures and documentation.
        validate_uk_nhs("9434765919").expect("format should be valid");
        validate_uk_nhs_with_checksum("9434765919").expect("checksum should match");
    }

    #[test]
    fn test_nhs_grouped_display_form_accepted() {
        validate_uk_nhs("943 476 5919").expect("grouped form should validate");
        validate_uk_nhs_with_checksum("943 476 5919").expect("grouped form should pass checksum");
        validate_uk_nhs_with_checksum("943-476-5919")
            .expect("hyphenated form should pass checksum");
    }

    #[test]
    fn test_nhs_bad_checksum_rejected() {
        // Flip the last digit so the checksum no longer matches.
        assert!(validate_uk_nhs_with_checksum("9434765910").is_err());
        assert!(validate_uk_nhs_with_checksum("9434765918").is_err());
    }

    #[test]
    fn test_nhs_placeholder_pattern_rejected() {
        // All-same-digit numbers are placeholder fixtures, never real NHS IDs.
        assert!(validate_uk_nhs_with_checksum("0000000000").is_err());
        assert!(validate_uk_nhs_with_checksum("9999999999").is_err());
        assert!(is_test_uk_nhs("0000000000"));
        assert!(is_test_uk_nhs("9999999999"));
    }

    #[test]
    fn test_nhs_wrong_length_rejected() {
        assert!(validate_uk_nhs("943476591").is_err()); // 9 digits
        assert!(validate_uk_nhs("94347659190").is_err()); // 11 digits
        assert!(validate_uk_nhs("").is_err());
    }

    #[test]
    fn test_nhs_non_digit_rejected() {
        assert!(validate_uk_nhs("943476591A").is_err());
    }

    // ----- UK Passport -----

    #[test]
    fn test_uk_passport_canonical_shape_accepted() {
        validate_uk_passport("AB1234567").expect("AB1234567 should validate");
        validate_uk_passport("ZZ0000001").expect("any 2-letter prefix + 7 digits accepted");
    }

    #[test]
    fn test_uk_passport_wrong_length_rejected() {
        assert!(validate_uk_passport("AB123456").is_err()); // 8 chars
        assert!(validate_uk_passport("AB12345678").is_err()); // 10 chars
    }

    #[test]
    fn test_uk_passport_must_start_with_letters() {
        assert!(validate_uk_passport("123456789").is_err());
        assert!(validate_uk_passport("A12345678").is_err());
    }

    #[test]
    fn test_uk_passport_must_end_with_digits() {
        assert!(validate_uk_passport("ABCDEFGHI").is_err());
        assert!(validate_uk_passport("AB123456X").is_err());
    }

    // ----- UK Driving Licence -----

    #[test]
    fn test_uk_driving_licence_canonical_shape_accepted() {
        // MORGA753116SM9IJ — sample DVLA-style shape from the issue test plan
        validate_uk_driving_licence("MORGA753116SM9IJ").expect("DVLA shape should validate");
    }

    #[test]
    fn test_uk_driving_licence_short_surname_uses_padding() {
        // Short surnames are padded with '9' (DVLA convention)
        assert!(validate_uk_driving_licence("LI9999753116AB1XY").is_err()); // 17 chars rejected
        validate_uk_driving_licence("LI999753116AB1XY").expect("'9' padding in surname accepted");
    }

    #[test]
    fn test_uk_driving_licence_all_nine_surname_rejected() {
        // All-9 surname is the DVLA placeholder for an unassigned licence
        assert!(validate_uk_driving_licence("99999753116AB1XY").is_err());
        assert!(is_test_uk_driving_licence("99999753116AB1XY"));
    }

    #[test]
    fn test_uk_driving_licence_wrong_length_rejected() {
        assert!(validate_uk_driving_licence("MORGA75311").is_err());
        assert!(validate_uk_driving_licence("MORGA753116SM9IJXX").is_err());
        assert!(validate_uk_driving_licence("").is_err());
    }

    #[test]
    fn test_uk_driving_licence_position_mismatches_rejected() {
        // Position 14 must be a digit (not a letter)
        assert!(validate_uk_driving_licence("MORGA753116SMXIJ").is_err());
        // Positions 6-11 must be digits
        assert!(validate_uk_driving_licence("MORGAX53116SM9IJ").is_err());
    }
}

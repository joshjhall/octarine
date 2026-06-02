//! Sweden Personnummer and Organisationsnummer validation
//!
//! - **Personnummer**: `YYMMDD-NNNC`, `YYMMDD+NNNC` (`+` marks 100+ years), or
//!   `YYYYMMDDNNNC`. Month 01-12; day 01-31, or 61-91 for a samordningsnummer
//!   (coordination number, real day = day - 60). Checksum is Luhn (mod-10)
//!   over the 10-digit core `YYMMDD` + `NNN` + check.
//! - **Organisationsnummer**: 10 digits (`NNNNNN-NNNN` or bare). The third
//!   digit is `>= 2`, distinguishing it from a personnummer. Checksum is Luhn
//!   over all 10 digits.
//!
//! Luhn is shared with [`super::national_id::luhn_check`] rather than
//! reimplemented.

use super::national_id::luhn_check;
use crate::primitives::types::Problem;

// ============================================================================
// Personnummer
// ============================================================================

/// Reduce a personnummer to its 10-digit core, validating the separator rules.
///
/// Accepts the 10-digit (`YYMMDD-NNNC` / `YYMMDD+NNNC` / bare `YYMMDDNNNC`) and
/// 12-digit (`YYYYMMDDNNNC`) forms. At most one `-`/`+` separator is allowed.
fn personnummer_core_digits(value: &str) -> Result<String, Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Sweden personnummer cannot be empty".to_string(),
        ));
    }

    let separators = trimmed.chars().filter(|c| *c == '-' || *c == '+').count();
    if separators > 1 {
        return Err(Problem::Validation(
            "Sweden personnummer may contain at most one separator".to_string(),
        ));
    }

    if let Some(bad) = trimmed
        .chars()
        .find(|c| !c.is_ascii_digit() && *c != '-' && *c != '+')
    {
        return Err(Problem::Validation(format!(
            "Sweden personnummer contains invalid character '{bad}'"
        )));
    }

    let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();
    match digits.len() {
        10 => Ok(digits),
        // Drop the two century digits to obtain the 10-digit core.
        12 => Ok(digits.get(2..).unwrap_or("").to_string()),
        other => Err(Problem::Validation(format!(
            "Sweden personnummer must have 10 or 12 digits, got {other}"
        ))),
    }
}

/// Parse two ASCII digits of `core` at `offset` into a number (0-99).
fn two_digits(core: &str, offset: usize) -> u32 {
    let bytes = core.as_bytes();
    let d = |i: usize| -> u32 {
        bytes
            .get(i)
            .map(|b| u32::from(b.saturating_sub(b'0')))
            .unwrap_or(99)
    };
    d(offset)
        .saturating_mul(10)
        .saturating_add(d(offset.saturating_add(1)))
}

/// Validate Sweden personnummer format (without checksum)
///
/// Checks length/separator rules and date sanity: month 01-12, day 01-31 or
/// 61-91 (samordningsnummer).
///
/// # Errors
///
/// Returns `Problem::Validation` if the format or date is invalid.
pub fn validate_sweden_personnummer(value: &str) -> Result<(), Problem> {
    let core = personnummer_core_digits(value)?;

    let month = two_digits(&core, 2);
    if !(1..=12).contains(&month) {
        return Err(Problem::Validation(format!(
            "Sweden personnummer month must be 01-12, got {month:02}"
        )));
    }

    let day = two_digits(&core, 4);
    let day_ok = (1..=31).contains(&day) || (61..=91).contains(&day);
    if !day_ok {
        return Err(Problem::Validation(format!(
            "Sweden personnummer day must be 01-31 or 61-91 (samordningsnummer), got {day:02}"
        )));
    }

    Ok(())
}

/// Validate Sweden personnummer with Luhn checksum over the 10-digit core
///
/// # Errors
///
/// Returns `Problem::Validation` if format, date, or checksum is invalid.
pub fn validate_sweden_personnummer_with_checksum(value: &str) -> Result<(), Problem> {
    validate_sweden_personnummer(value)?;

    let core = personnummer_core_digits(value)?;
    if !luhn_check(&core) {
        return Err(Problem::Validation(
            "Sweden personnummer checksum (Luhn) validation failed".to_string(),
        ));
    }

    Ok(())
}

/// Check if a Sweden personnummer is a test/dummy pattern (all-zero core)
#[must_use]
pub fn is_test_sweden_personnummer(value: &str) -> bool {
    matches!(personnummer_core_digits(value), Ok(core) if core.chars().all(|c| c == '0'))
}

// ============================================================================
// Organisationsnummer
// ============================================================================

/// Extract the 10 digits of an organisationsnummer, validating separator rules.
fn orgnummer_core_digits(value: &str) -> Result<String, Problem> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Sweden organisationsnummer cannot be empty".to_string(),
        ));
    }

    if trimmed.chars().filter(|c| *c == '-').count() > 1 {
        return Err(Problem::Validation(
            "Sweden organisationsnummer may contain at most one separator".to_string(),
        ));
    }

    if let Some(bad) = trimmed.chars().find(|c| !c.is_ascii_digit() && *c != '-') {
        return Err(Problem::Validation(format!(
            "Sweden organisationsnummer contains invalid character '{bad}'"
        )));
    }

    let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();
    if digits.len() != 10 {
        return Err(Problem::Validation(format!(
            "Sweden organisationsnummer must have 10 digits, got {}",
            digits.len()
        )));
    }

    Ok(digits)
}

/// Validate Sweden organisationsnummer format (without checksum)
///
/// Checks length and the third-digit `>= 2` rule that distinguishes an
/// orgnummer from a personnummer.
///
/// # Errors
///
/// Returns `Problem::Validation` if the format is invalid.
pub fn validate_sweden_orgnummer(value: &str) -> Result<(), Problem> {
    let digits = orgnummer_core_digits(value)?;

    let third = digits
        .as_bytes()
        .get(2)
        .map(|b| b.saturating_sub(b'0'))
        .unwrap_or(0);
    if third < 2 {
        return Err(Problem::Validation(format!(
            "Sweden organisationsnummer third digit must be >= 2, got {third}"
        )));
    }

    Ok(())
}

/// Validate Sweden organisationsnummer with Luhn checksum over all 10 digits
///
/// # Errors
///
/// Returns `Problem::Validation` if format or checksum is invalid.
pub fn validate_sweden_orgnummer_with_checksum(value: &str) -> Result<(), Problem> {
    validate_sweden_orgnummer(value)?;

    let digits = orgnummer_core_digits(value)?;
    if !luhn_check(&digits) {
        return Err(Problem::Validation(
            "Sweden organisationsnummer checksum (Luhn) validation failed".to_string(),
        ));
    }

    Ok(())
}

/// Check if a Sweden organisationsnummer is a test/dummy pattern (all-zero)
#[must_use]
pub fn is_test_sweden_orgnummer(value: &str) -> bool {
    matches!(orgnummer_core_digits(value), Ok(digits) if digits.chars().all(|c| c == '0'))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    /// Append the Luhn check digit to a 9-digit stem, producing a 10-digit core.
    fn with_luhn_check(stem9: &str) -> String {
        assert_eq!(stem9.len(), 9, "stem must be 9 digits");
        // Find the check digit d such that stem9 + d passes Luhn.
        for d in 0..=9u32 {
            let candidate = format!("{stem9}{d}");
            if luhn_check(&candidate) {
                return candidate;
            }
        }
        panic!("no Luhn check digit found for {stem9}");
    }

    // ---- Personnummer: format + date sanity --------------------------------

    #[test]
    fn test_personnummer_known_value_accepted() {
        // 19121212-1212 is the canonical Swedish test personnummer; its 10-digit
        // core 1212121212 has a valid Luhn check digit.
        assert!(validate_sweden_personnummer("19121212-1212").is_ok());
        assert!(validate_sweden_personnummer("121212-1212").is_ok());
        assert!(validate_sweden_personnummer("1212121212").is_ok());
        assert!(validate_sweden_personnummer_with_checksum("19121212-1212").is_ok());
        assert!(validate_sweden_personnummer_with_checksum("121212-1212").is_ok());
    }

    #[test]
    fn test_personnummer_plus_separator_accepted() {
        assert!(validate_sweden_personnummer("121212+1212").is_ok());
    }

    #[test]
    fn test_personnummer_samordningsnummer() {
        // Day 62 (= real day 2) is a valid coordination number.
        assert!(validate_sweden_personnummer("811262-1234").is_ok());
        // Day 32 is in the dead gap between 31 and 61.
        assert!(validate_sweden_personnummer("811232-1234").is_err());
        // Day 92 is above the samordningsnummer range.
        assert!(validate_sweden_personnummer("811292-1234").is_err());
    }

    #[test]
    fn test_personnummer_rejects_bad_month() {
        assert!(validate_sweden_personnummer("811328-1234").is_err()); // month 13
        assert!(validate_sweden_personnummer("810028-1234").is_err()); // month 00
    }

    #[test]
    fn test_personnummer_rejects_wrong_length() {
        assert!(validate_sweden_personnummer("12345").is_err());
        assert!(validate_sweden_personnummer("12121212345").is_err()); // 11 digits
        assert!(validate_sweden_personnummer("").is_err());
    }

    #[test]
    fn test_personnummer_rejects_extra_separators() {
        assert!(validate_sweden_personnummer("12-12-12-1212").is_err());
        assert!(validate_sweden_personnummer("121212/1212").is_err());
    }

    // ---- Personnummer: checksum --------------------------------------------

    #[test]
    fn test_personnummer_bad_luhn_rejected() {
        // Build a valid-date stem, take the correct check digit, then tamper it.
        let core = with_luhn_check("811218987"); // 18 Dec 1981 + individual 987
        assert!(validate_sweden_personnummer_with_checksum(&core).is_ok());

        let mut chars: Vec<char> = core.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        // Date still valid, so format passes; only the checksum fails.
        assert!(validate_sweden_personnummer(&tampered).is_ok());
        assert!(validate_sweden_personnummer_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_personnummer_twelve_digit_checksum() {
        // 12-digit form: drop century, Luhn over the last 10.
        let core = with_luhn_check("900101001");
        let twelve = format!("19{core}");
        assert!(validate_sweden_personnummer_with_checksum(&twelve).is_ok());
    }

    #[test]
    fn test_is_test_personnummer() {
        assert!(is_test_sweden_personnummer("000000-0000"));
        assert!(!is_test_sweden_personnummer("19121212-1212"));
    }

    // ---- Organisationsnummer -----------------------------------------------

    #[test]
    fn test_orgnummer_third_digit_rule() {
        let valid = with_luhn_check("556016068"); // third digit = 6
        assert!(validate_sweden_orgnummer(&valid).is_ok());
        assert!(validate_sweden_orgnummer_with_checksum(&valid).is_ok());

        // Third digit < 2 → rejected (that shape is a personnummer).
        let bad_third = with_luhn_check("551016068"); // third digit = 1
        assert!(validate_sweden_orgnummer(&bad_third).is_err());
    }

    #[test]
    fn test_orgnummer_formatted_and_bare() {
        let valid = with_luhn_check("556016068");
        let head = valid.get(..6).unwrap_or_default();
        let tail = valid.get(6..).unwrap_or_default();
        let formatted = format!("{head}-{tail}");
        assert!(validate_sweden_orgnummer(&formatted).is_ok());
        assert!(validate_sweden_orgnummer(&valid).is_ok());
    }

    #[test]
    fn test_orgnummer_bad_luhn_rejected() {
        let valid = with_luhn_check("556016068");
        let mut chars: Vec<char> = valid.chars().collect();
        if let Some(last) = chars.last_mut() {
            *last = if *last == '0' { '1' } else { '0' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(validate_sweden_orgnummer(&tampered).is_ok());
        assert!(validate_sweden_orgnummer_with_checksum(&tampered).is_err());
    }

    #[test]
    fn test_orgnummer_rejects_wrong_length() {
        assert!(validate_sweden_orgnummer("12345").is_err());
        assert!(validate_sweden_orgnummer("55601606801").is_err()); // 11 digits
        assert!(validate_sweden_orgnummer("").is_err());
    }

    #[test]
    fn test_is_test_orgnummer() {
        assert!(is_test_sweden_orgnummer("000000-0000"));
        let valid = with_luhn_check("556016068");
        assert!(!is_test_sweden_orgnummer(&valid));
    }
}

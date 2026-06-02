//! Sweden identifier detection — Personnummer and Organisationsnummer.
//!
//! Detection functions are pattern-based (shape) plus the structural rules that
//! distinguish the two identifiers: a valid personnummer encodes a calendar
//! month (`MM` = 01-12), so its third digit is always 0 or 1, whereas an
//! organisationsnummer requires a third digit `>= 2`. This makes the two
//! mutually exclusive. Checksum (Luhn) verification is intentionally NOT done
//! here — use
//! [`super::super::validation::validate_sweden_personnummer_with_checksum`] and
//! [`super::super::validation::validate_sweden_orgnummer_with_checksum`].

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Extract the 10-digit personnummer core (`YYMMDD` + `NNN` + check) from a
/// value, accepting the 10-digit (`YYMMDD-NNNC` / `YYMMDD+NNNC`) and 12-digit
/// (`YYYYMMDDNNNC`) forms. At most one `-`/`+` separator is allowed; any other
/// non-digit character rejects the value. Returns the 10 core digits.
pub(super) fn personnummer_core(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed
        .chars()
        .any(|c| !c.is_ascii_digit() && c != '-' && c != '+')
    {
        return None;
    }
    if trimmed.chars().filter(|c| *c == '-' || *c == '+').count() > 1 {
        return None;
    }
    let digits: Vec<u8> = trimmed
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    match digits.len() {
        10 => Some(digits),
        12 => digits.get(2..).map(<[u8]>::to_vec),
        _ => None,
    }
}

/// Check the date portion of a 10-digit personnummer core.
///
/// Month must be 01-12. Day must be 01-31, or 61-91 for a samordningsnummer
/// (coordination number, where the real day is `day - 60`).
pub(super) fn personnummer_date_ok(core: &[u8]) -> bool {
    let two = |i: usize| -> u32 {
        let a = u32::from(core.get(i).copied().unwrap_or(9));
        let b = u32::from(core.get(i.saturating_add(1)).copied().unwrap_or(9));
        a.saturating_mul(10).saturating_add(b)
    };
    let month = two(2);
    let day = two(4);
    (1..=12).contains(&month) && ((1..=31).contains(&day) || (61..=91).contains(&day))
}

/// Extract the 10 digits of an organisationsnummer (`NNNNNN-NNNN` or bare).
/// At most one `-` separator is allowed.
pub(super) fn orgnummer_digits(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.chars().any(|c| !c.is_ascii_digit() && c != '-') {
        return None;
    }
    if trimmed.chars().filter(|c| *c == '-').count() > 1 {
        return None;
    }
    let digits: Vec<u8> = trimmed
        .chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    (digits.len() == 10).then_some(digits)
}

/// Check if a value matches Sweden personnummer format
///
/// Shape plus date sanity (month 01-12, day 01-31 or 61-91 for
/// samordningsnummer). Use
/// [`super::super::validation::validate_sweden_personnummer_with_checksum`] for
/// Luhn verification.
#[must_use]
pub fn is_sweden_personnummer(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    if !patterns::sweden_personnummer::all()
        .iter()
        .any(|p| p.is_match(value))
    {
        return false;
    }
    personnummer_core(value).is_some_and(|core| personnummer_date_ok(&core))
}

/// Find all Sweden personnummer patterns in text
///
/// Label-anchored only — a bare 10/12-digit run collides with dates, phone
/// numbers, and organisationsnummer, so text scanning requires context.
#[must_use]
pub fn find_sweden_personnummers_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::sweden_personnummer::labeled_only() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::SwedenPersonnummer,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Sweden organisationsnummer format
///
/// Shape (10 digits) plus the third-digit `>= 2` rule that distinguishes an
/// orgnummer from a personnummer. Use
/// [`super::super::validation::validate_sweden_orgnummer_with_checksum`] for
/// Luhn verification.
#[must_use]
pub fn is_sweden_orgnummer(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    if !patterns::sweden_orgnummer::all()
        .iter()
        .any(|p| p.is_match(value))
    {
        return false;
    }
    orgnummer_digits(value).is_some_and(|d| d.get(2).copied().unwrap_or(0) >= 2)
}

/// Find all Sweden organisationsnummer patterns in text
///
/// Label-anchored only — a bare 10-digit run collides with phone numbers and
/// personnummer, so text scanning requires context.
#[must_use]
pub fn find_sweden_orgnummers_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::sweden_orgnummer::labeled_only() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::SwedenOrgnummer,
            ));
        }
    }

    deduplicate_matches(matches)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sweden_personnummer_accepts_known_value() {
        // 19121212-1212 is the canonical Swedish test personnummer.
        assert!(is_sweden_personnummer("19121212-1212"));
        assert!(is_sweden_personnummer("121212-1212"));
        assert!(is_sweden_personnummer("1212121212"));
    }

    #[test]
    fn test_is_sweden_personnummer_plus_separator() {
        assert!(is_sweden_personnummer("121212+1212"));
    }

    #[test]
    fn test_is_sweden_personnummer_samordningsnummer() {
        // Day 62 (= real day 2) is a valid coordination number.
        assert!(is_sweden_personnummer("811262-1234"));
        // Day 32 is in the dead gap between 31 and 61.
        assert!(!is_sweden_personnummer("811232-1234"));
    }

    #[test]
    fn test_is_sweden_personnummer_rejects_bad_month() {
        assert!(!is_sweden_personnummer("811328-1234")); // month 13
        assert!(!is_sweden_personnummer("810028-1234")); // month 00
    }

    #[test]
    fn test_is_sweden_personnummer_rejects_wrong_length() {
        assert!(!is_sweden_personnummer("12345"));
        assert!(!is_sweden_personnummer("12121212345")); // 11 digits
    }

    #[test]
    fn test_is_sweden_orgnummer_third_digit_rule() {
        // Third digit >= 2 → valid orgnummer shape.
        assert!(is_sweden_orgnummer("556016-0680"));
        assert!(is_sweden_orgnummer("5560160680"));
        // Third digit < 2 → not an orgnummer (would be a personnummer shape).
        assert!(!is_sweden_orgnummer("551016-0680"));
    }

    #[test]
    fn test_personnummer_and_orgnummer_mutually_exclusive() {
        // A valid personnummer (month 01-12 → third digit 0/1) is never an
        // orgnummer, and vice versa.
        assert!(is_sweden_personnummer("121212-1212"));
        assert!(!is_sweden_orgnummer("121212-1212"));
        assert!(is_sweden_orgnummer("556016-0680"));
        assert!(!is_sweden_personnummer("556016-0680"));
    }

    #[test]
    fn test_find_sweden_personnummers_label_required() {
        let bare = find_sweden_personnummers_in_text("Random 19121212-1212 in the middle.");
        assert!(bare.is_empty(), "bare value must not match without a label");

        let labeled = find_sweden_personnummers_in_text("Patient personnummer: 19121212-1212.");
        assert_eq!(labeled.len(), 1);
    }

    #[test]
    fn test_find_sweden_orgnummers_label_required() {
        let bare = find_sweden_orgnummers_in_text("Random 556016-0680 in the middle.");
        assert!(bare.is_empty(), "bare value must not match without a label");

        let labeled = find_sweden_orgnummers_in_text("Company orgnr: 556016-0680.");
        assert_eq!(labeled.len(), 1);
    }
}

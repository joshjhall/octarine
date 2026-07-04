//! German government-identifier detection — Steuer-IdNr (tax ID),
//! Personalausweis (nPA / national ID card), and Reisepass (passport).
//!
//! `is_*` checks are precise: the tax ID verifies the ISO 7064 mod-11,10
//! checksum plus the German structural rule, and the nPA/passport verify the
//! ICAO Doc 9303 check digit. This keeps the aggregate dispatcher from
//! misclassifying an arbitrary 11-digit run or 10-character token as a German
//! identifier. Deep checksum re-verification with `Result` errors lives in
//! `super::super::validation`.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::super::common::{germany_tax_id as tax_id_checks, icao_doc_9303};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Length of the ICAO document-number body (before the check digit) for the
/// German nPA and Reisepass.
const ICAO_DOC_BODY_LEN: usize = 9;

/// Extract just the digits from a value (drops spaces/grouping).
fn digits_only(value: &str) -> String {
    value.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Return the captured document number (group 1) if the pattern has one,
/// else the full match. Labeled patterns capture the bare identifier in
/// group 1 so checksum verification runs on the number, not the label.
fn captured_id<'a>(capture: &regex::Captures<'a>, full: &regex::Match<'a>) -> String {
    capture
        .get(1)
        .map_or_else(|| full.as_str().to_string(), |m| m.as_str().to_string())
}

// ============================================================================
// Steuer-IdNr (tax identification number)
// ============================================================================

/// Check if a value is a valid German Steuer-IdNr.
///
/// Verifies the 11-digit shape, the ISO 7064 mod-11,10 check digit, and the
/// German structural rule (exactly one repeated digit among the first ten,
/// non-zero leading digit).
#[must_use]
pub fn is_germany_tax_id(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    if !patterns::germany_tax_id::all()
        .iter()
        .any(|p| p.is_match(value))
    {
        return false;
    }
    let digits = digits_only(value);
    tax_id_checks::verify_structure(&digits) && tax_id_checks::verify_checksum(&digits)
}

/// Find all German Steuer-IdNr matches in text.
///
/// Label-anchored only: a bare 11-digit run collides with Nigeria NIN/BVN and
/// Italy VAT, so scanning requires a surrounding German/tax label.
#[must_use]
pub fn find_germany_tax_ids_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::germany_tax_id::labeled_only() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            let digits = digits_only(full_match.as_str());
            if tax_id_checks::verify_structure(&digits) && tax_id_checks::verify_checksum(&digits) {
                matches.push(IdentifierMatch::high_confidence(
                    full_match.start(),
                    full_match.end(),
                    full_match.as_str().to_string(),
                    IdentifierType::GermanyTaxId,
                ));
            }
        }
    }

    deduplicate_matches(matches)
}

// ============================================================================
// Personalausweis (nPA / national ID card)
// ============================================================================

/// Check if a value is a valid German Personalausweis (nPA) number.
///
/// Verifies the 9-character document body plus ICAO Doc 9303 check digit.
#[must_use]
pub fn is_germany_id_card(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    if !patterns::germany_id_card::all()
        .iter()
        .any(|p| p.is_match(value))
    {
        return false;
    }
    icao_doc_9303::verify(&value.to_uppercase(), ICAO_DOC_BODY_LEN)
}

/// Find all German Personalausweis matches in text.
///
/// Label-anchored only: the bare 10-character alphanumeric shape collides with
/// the German passport and other document numbers.
#[must_use]
pub fn find_germany_id_cards_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::germany_id_card::labeled_only() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            let id = captured_id(&capture, &full_match);
            if icao_doc_9303::verify(&id.to_uppercase(), ICAO_DOC_BODY_LEN) {
                matches.push(IdentifierMatch::high_confidence(
                    full_match.start(),
                    full_match.end(),
                    full_match.as_str().to_string(),
                    IdentifierType::GermanyIdCard,
                ));
            }
        }
    }

    deduplicate_matches(matches)
}

// ============================================================================
// Reisepass (passport)
// ============================================================================

/// Check if a value is a valid German Reisepass (passport) number.
///
/// Verifies the 9-character document body plus ICAO Doc 9303 check digit,
/// using the same reduced alphabet as the nPA.
#[must_use]
pub fn is_germany_passport(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    if !patterns::germany_passport::all()
        .iter()
        .any(|p| p.is_match(value))
    {
        return false;
    }
    icao_doc_9303::verify(&value.to_uppercase(), ICAO_DOC_BODY_LEN)
}

/// Find all German Reisepass matches in text.
///
/// Label-anchored only: the bare 10-character alphanumeric shape collides with
/// the German nPA and other document numbers.
#[must_use]
pub fn find_germany_passports_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::germany_passport::labeled_only() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            let id = captured_id(&capture, &full_match);
            if icao_doc_9303::verify(&id.to_uppercase(), ICAO_DOC_BODY_LEN) {
                matches.push(IdentifierMatch::high_confidence(
                    full_match.start(),
                    full_match.end(),
                    full_match.as_str().to_string(),
                    IdentifierType::GermanyPassport,
                ));
            }
        }
    }

    deduplicate_matches(matches)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // 10002345676: valid ISO 7064 mod-11,10 checksum, digit '0' repeats 3×,
    // non-zero leading digit.
    const VALID_TAX_ID: &str = "10002345676";
    // ICAO Doc 9303 document numbers with valid check digit and the German
    // reduced alphabet (excludes A,B,D,E,I,O,Q,S,U).
    const VALID_ID_CARD: &str = "CH20064148";
    const VALID_PASSPORT: &str = "T220001293";

    // ----- Steuer-IdNr -----

    #[test]
    fn test_is_germany_tax_id_valid() {
        assert!(is_germany_tax_id(VALID_TAX_ID));
    }

    #[test]
    fn test_is_germany_tax_id_rejects_bad_checksum() {
        assert!(!is_germany_tax_id("10002345675"));
    }

    #[test]
    fn test_is_germany_tax_id_rejects_leading_zero() {
        // BZSt documentation example — deliberately non-issuable.
        assert!(!is_germany_tax_id("02476291358"));
    }

    #[test]
    fn test_is_germany_tax_id_rejects_wrong_length() {
        assert!(!is_germany_tax_id("1000234567"));
        assert!(!is_germany_tax_id("100023456760"));
    }

    #[test]
    fn test_find_germany_tax_ids_requires_label() {
        let labeled = find_germany_tax_ids_in_text(&format!("Steuer-IdNr: {VALID_TAX_ID}"));
        assert_eq!(labeled.len(), 1);
        assert_eq!(
            labeled.first().expect("one match").identifier_type,
            IdentifierType::GermanyTaxId
        );
        // Bare, unlabeled → not scanned.
        let bare = find_germany_tax_ids_in_text(&format!("value {VALID_TAX_ID} here"));
        assert!(bare.is_empty());
    }

    // ----- Personalausweis (nPA) -----

    #[test]
    fn test_is_germany_id_card_valid() {
        assert!(is_germany_id_card(VALID_ID_CARD));
    }

    #[test]
    fn test_is_germany_id_card_rejects_bad_check_digit() {
        assert!(!is_germany_id_card("CH20064149"));
    }

    #[test]
    fn test_find_germany_id_cards_requires_label() {
        let labeled = find_germany_id_cards_in_text(&format!("Personalausweis {VALID_ID_CARD}"));
        assert_eq!(labeled.len(), 1);
        assert_eq!(
            labeled.first().expect("one match").identifier_type,
            IdentifierType::GermanyIdCard
        );
    }

    // ----- Reisepass -----

    #[test]
    fn test_is_germany_passport_valid() {
        assert!(is_germany_passport(VALID_PASSPORT));
    }

    #[test]
    fn test_is_germany_passport_rejects_bad_check_digit() {
        assert!(!is_germany_passport("T220001294"));
    }

    #[test]
    fn test_find_germany_passports_requires_label() {
        let labeled = find_germany_passports_in_text(&format!("Reisepass {VALID_PASSPORT}"));
        assert_eq!(labeled.len(), 1);
        assert_eq!(
            labeled.first().expect("one match").identifier_type,
            IdentifierType::GermanyPassport
        );
    }

    #[test]
    fn test_empty_input() {
        assert!(!is_germany_tax_id(""));
        assert!(!is_germany_id_card(""));
        assert!(!is_germany_passport(""));
    }
}

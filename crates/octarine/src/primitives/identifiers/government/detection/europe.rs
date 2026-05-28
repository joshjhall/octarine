//! European national-identifier detection — Spain (NIF/NIE), Italy (Codice
//! Fiscale), Finland (HETU), Poland (PESEL).
//!
//! Per-country `is_*` / `find_*_in_text` pairs only; checksum validation
//! lives in `super::super::validation`.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

/// Check if a value matches Finland HETU format
#[must_use]
pub fn is_finland_hetu(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::finland_hetu::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Finland HETU patterns in text
#[must_use]
pub fn find_finland_hetus_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::finland_hetu::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::FinlandHetu,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Spain NIF format
#[must_use]
pub fn is_spain_nif(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::spain_nif::all().iter().any(|p| p.is_match(value))
}

/// Find all Spain NIF patterns in text
#[must_use]
pub fn find_spain_nifs_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::spain_nif::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::SpainNif,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Spain NIE format
#[must_use]
pub fn is_spain_nie(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::spain_nie::all().iter().any(|p| p.is_match(value))
}

/// Find all Spain NIE patterns in text
#[must_use]
pub fn find_spain_nies_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::spain_nie::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::SpainNie,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Italy Codice Fiscale format
#[must_use]
pub fn is_italy_fiscal_code(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::italy_fiscal_code::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Italy Codice Fiscale patterns in text
#[must_use]
pub fn find_italy_fiscal_codes_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::italy_fiscal_code::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::ItalyFiscalCode,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Italy Partita IVA (VAT) format
///
/// Format-only check: exactly 11 digits. Use
/// [`super::super::validation::validate_italy_vat_with_checksum`] for the
/// mod-10 Luhn-style checksum.
#[must_use]
pub fn is_italy_vat(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::italy_vat::all().iter().any(|p| p.is_match(value))
}

/// Find all Italy VAT patterns in text
///
/// Uses the label-anchored pattern only in text scanning because a bare
/// 11-digit run is ambiguous with Poland PESEL and similar formats. Direct
/// `is_italy_vat` calls still accept bare 11-digit input.
#[must_use]
pub fn find_italy_vats_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::italy_vat::labeled_only() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::ItalyVat,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Italy passport format
#[must_use]
pub fn is_italy_passport(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::italy_passport::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Italy passport patterns in text
///
/// Text scanning uses the label-anchored pattern only: the bare
/// two-letter + seven-digit shape collides with too many other
/// identifier formats to scan safely without context.
#[must_use]
pub fn find_italy_passports_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::italy_passport::labeled_only() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::ItalyPassport,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Italy identity card format (paper, CIE 2.0,
/// or CIE 3.0)
#[must_use]
pub fn is_italy_identity_card(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::italy_identity_card::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Italy identity card patterns in text
///
/// Label-anchored only: the bare paper/CIE shapes overlap with passport
/// and other generic identifier formats.
#[must_use]
pub fn find_italy_identity_cards_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::italy_identity_card::labeled_only() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::ItalyIdentityCard,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Italy driver license format (standard or
/// legacy U1 Carta Conducente)
#[must_use]
pub fn is_italy_driver_license(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::italy_driver_license::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Italy driver license patterns in text
#[must_use]
pub fn find_italy_driver_licenses_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::italy_driver_license::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::ItalyDriverLicense,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches Poland PESEL format
#[must_use]
pub fn is_poland_pesel(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::poland_pesel::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all Poland PESEL patterns in text
#[must_use]
pub fn find_poland_pesels_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::poland_pesel::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::PolandPesel,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches UK NHS Number format (bare 10 digits or
/// grouped `NNN NNN NNNN`)
///
/// Format-only check. Use
/// [`super::super::validation::validate_uk_nhs_with_checksum`] for the
/// mod-11 weighted-sum checksum.
#[must_use]
pub fn is_uk_nhs(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::uk_nhs::all().iter().any(|p| p.is_match(value))
}

/// Find all UK NHS Number patterns in text
///
/// Label-anchored or grouped form only — a bare `\d{10}` collides with phone
/// numbers and many other formats, so direct `is_uk_nhs` calls still accept
/// the unlabeled bare form, but text scanning requires context.
#[must_use]
pub fn find_uk_nhs_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::uk_nhs::labeled_only() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::UkNhs,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches UK passport format (2 uppercase letters + 7 digits)
#[must_use]
pub fn is_uk_passport(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::uk_passport::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all UK passport patterns in text
///
/// Label-anchored only: the bare 2-letter + 7-digit shape collides with
/// Italian passport and other identifier formats.
#[must_use]
pub fn find_uk_passports_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::uk_passport::labeled_only() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::UkPassport,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Check if a value matches UK DVLA driving licence format (16-char
/// structural shape)
#[must_use]
pub fn is_uk_driving_licence(value: &str) -> bool {
    if exceeds_safe_length(value, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::uk_driving_licence::all()
        .iter()
        .any(|p| p.is_match(value))
}

/// Find all UK DVLA driving licence patterns in text
///
/// Label-anchored only: the bare 16-char alphanumeric shape can collide
/// with order numbers and other identifiers, so scanning requires context.
#[must_use]
pub fn find_uk_driving_licences_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::uk_driving_licence::labeled_only() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::UkDrivingLicence,
            ));
        }
    }

    deduplicate_matches(matches)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ----- UK NHS Number -----

    #[test]
    fn test_is_uk_nhs_bare_10_digits_accepted() {
        assert!(is_uk_nhs("9434765919"));
    }

    #[test]
    fn test_is_uk_nhs_grouped_display_form_accepted() {
        assert!(is_uk_nhs("943 476 5919"));
        assert!(is_uk_nhs("943-476-5919"));
    }

    #[test]
    fn test_is_uk_nhs_wrong_length_rejected() {
        assert!(!is_uk_nhs("12345"));
        // Note: bare 10-digit STANDARD pattern matches numeric inputs; we
        // exercise the grouped-form-only filter via `find_uk_nhs_in_text`.
    }

    #[test]
    fn test_find_uk_nhs_in_text_requires_label_or_grouped_form() {
        let matches = find_uk_nhs_in_text("Patient NHS: 943 476 5919, contact later");
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches.first().expect("one match").identifier_type,
            IdentifierType::UkNhs
        );
    }

    #[test]
    fn test_find_uk_nhs_in_text_no_label_no_match() {
        // Bare 10-digit run without label or grouping should not be picked up.
        let matches = find_uk_nhs_in_text("Call us on 9434765919 today.");
        assert!(matches.is_empty());
    }

    // ----- UK Passport -----

    #[test]
    fn test_is_uk_passport_accepts_2_letters_7_digits() {
        assert!(is_uk_passport("AB1234567"));
        assert!(is_uk_passport("ZZ0000001"));
    }

    #[test]
    fn test_is_uk_passport_rejects_wrong_length() {
        assert!(!is_uk_passport("A1234567"));
        assert!(!is_uk_passport("AB12345"));
    }

    #[test]
    fn test_find_uk_passports_in_text_requires_label() {
        let matches = find_uk_passports_in_text("UK passport: AB1234567 issued London");
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches.first().expect("one match").identifier_type,
            IdentifierType::UkPassport
        );
    }

    #[test]
    fn test_find_uk_passports_in_text_no_label_no_match() {
        // Bare 2-letter + 7-digit shape without UK-anchored label should not
        // match, because Italian passport has the identical shape.
        let matches = find_uk_passports_in_text("Reference AB1234567");
        assert!(matches.is_empty());
    }

    // ----- UK Driving Licence -----

    #[test]
    fn test_is_uk_driving_licence_canonical_shape_accepted() {
        // MORGA753116SM9IJ — sample DVLA-style shape
        assert!(is_uk_driving_licence("MORGA753116SM9IJ"));
    }

    #[test]
    fn test_is_uk_driving_licence_rejects_wrong_length() {
        assert!(!is_uk_driving_licence("MORGA75311"));
        assert!(!is_uk_driving_licence("MORGA753116SM9IJEXTRA"));
    }

    #[test]
    fn test_find_uk_driving_licences_in_text_requires_label() {
        let matches =
            find_uk_driving_licences_in_text("Driving licence: MORGA753116SM9IJ expires 2032");
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches.first().expect("one match").identifier_type,
            IdentifierType::UkDrivingLicence
        );
    }

    #[test]
    fn test_find_uk_driving_licences_dvla_label_accepted() {
        let matches = find_uk_driving_licences_in_text("DVLA MORGA753116SM9IJ");
        assert_eq!(matches.len(), 1);
    }
}

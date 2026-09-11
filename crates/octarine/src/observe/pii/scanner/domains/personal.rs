//! Personal PII scanning (email, phone, name, birthdate, username, age, NRP)
//!
//! Part of the PII scanner domain split (issue #411).

use super::super::super::types::PiiType;
use crate::primitives::identifiers::PersonalIdentifierBuilder;

/// Scan for personal PII (email, phone, name, birthdate, username, age, NRP)
pub(super) fn scan_personal(text: &str, pii_types: &mut Vec<PiiType>) {
    let personal = PersonalIdentifierBuilder::new();

    if personal.is_pii_present(text) {
        if !personal.detect_emails_in_text(text).is_empty() {
            pii_types.push(PiiType::Email);
        }
        if !personal.detect_phones_in_text(text).is_empty() {
            pii_types.push(PiiType::Phone);
        }
        if !personal.detect_names_in_text(text).is_empty() {
            pii_types.push(PiiType::Name);
        }
        if !personal.detect_birthdates_in_text(text).is_empty() {
            pii_types.push(PiiType::Birthdate);
        }
        if !personal.detect_usernames_in_text(text).is_empty() {
            pii_types.push(PiiType::Username);
        }
    }

    // Age and NRP detectors run unconditionally — `is_pii_present` is
    // a coarse pre-filter built around email/phone/name/etc. and may
    // return `false` for text that contains only an age or nationality
    // reference.
    if !personal.detect_ages_in_text(text).is_empty() {
        pii_types.push(PiiType::Age);
    }
    if !personal.detect_nationalities_in_text(text).is_empty() {
        pii_types.push(PiiType::Nationality);
    }
    if !personal.detect_religions_in_text(text).is_empty() {
        pii_types.push(PiiType::Religion);
    }
    if !personal
        .detect_political_affiliations_in_text(text)
        .is_empty()
    {
        pii_types.push(PiiType::PoliticalAffiliation);
    }
}

/// Coarse pre-filter for the personal domain.
///
/// Cheaper than [`scan_personal`] — used by the present-check dispatch path,
/// which only needs to know whether any PII exists, not which types.
pub(super) fn is_personal_present(text: &str) -> bool {
    PersonalIdentifierBuilder::new().is_pii_present(text)
}
#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_scan_personal_detects_age_and_nrp() {
        let text = "The 42-year-old American Catholic Democrat patient.";
        let mut pii_types = Vec::new();
        scan_personal(text, &mut pii_types);
        assert!(pii_types.contains(&PiiType::Age), "expected Age");
        assert!(
            pii_types.contains(&PiiType::Nationality),
            "expected Nationality"
        );
        assert!(pii_types.contains(&PiiType::Religion), "expected Religion");
        assert!(
            pii_types.contains(&PiiType::PoliticalAffiliation),
            "expected PoliticalAffiliation"
        );
    }

    #[test]
    fn test_scan_personal_age_only_no_other_pii() {
        // "in her eighties" — should trip Age but not email/phone/etc.
        let text = "in her eighties";
        let mut pii_types = Vec::new();
        scan_personal(text, &mut pii_types);
        assert!(pii_types.contains(&PiiType::Age));
        assert!(!pii_types.contains(&PiiType::Email));
        assert!(!pii_types.contains(&PiiType::Phone));
    }
}

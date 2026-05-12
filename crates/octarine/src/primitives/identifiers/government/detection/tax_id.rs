//! US tax identifier detection (EIN, TIN, ITIN)
//!
//! - `is_tax_id` is a broad superset matcher (any tax-shaped value).
//! - `is_ein` is strict — requires `XX-XXXXXXX` format **and** valid
//!   IRS campus-code prefix (delegates to `validation::validate_ein`).
//! - `find_eins_in_text` re-scans tax_id patterns and keeps only valid EINs.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::helpers::{MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length, get_full_match};

/// Check if a value matches tax ID format (EIN, TIN, ITIN)
///
/// This is a broad superset check — any value matching `is_ein` will also
/// match `is_tax_id`. Use `is_ein` when EIN-specific classification is needed.
#[must_use]
pub fn is_tax_id(value: &str) -> bool {
    patterns::tax_id::all().iter().any(|p| p.is_match(value))
}

/// Check if a value is a valid EIN (Employer Identification Number)
///
/// Distinguishes EINs from other tax IDs (ITINs, generic TINs) by validating
/// both the `XX-XXXXXXX` format and the IRS campus code prefix. Used by
/// `detect_government_identifier` to return `IdentifierType::Ein` for valid
/// EINs and fall through to `IdentifierType::TaxId` for other tax IDs.
#[must_use]
pub fn is_ein(value: &str) -> bool {
    super::super::validation::validate_ein(value).is_ok()
}

/// Find all tax ID patterns in text (EIN, TIN, ITIN)
///
/// Scans for any tax ID format and tags matches with `IdentifierType::TaxId`.
/// This is a broad superset finder — text containing a valid EIN will produce
/// matches here AND in `find_eins_in_text`. The PII scanner pushes both
/// `PiiType::TaxId` and `PiiType::Ein` for such inputs, which correctly
/// reflects that the value satisfies both classifications.
///
/// Use `find_eins_in_text` when EIN-specific classification is needed.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "Company EIN: 00-0000001";
/// let matches = detection::find_tax_ids_in_text(text);
/// assert_eq!(matches.len(), 1);
/// ```
#[must_use]
pub fn find_tax_ids_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::tax_id::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::TaxId,
            ));
        }
    }

    deduplicate_matches(matches)
}

/// Find all valid EIN patterns in text
///
/// Scans for tax ID format candidates and keeps only those that pass
/// `is_ein` (valid `XX-XXXXXXX` format with a valid IRS campus code prefix).
/// Matches are tagged with `IdentifierType::Ein`.
///
/// The same input string can also appear in `find_tax_ids_in_text` results
/// because EINs are a subset of tax IDs — see that function's documentation.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "Company EIN: 12-3456789";
/// let matches = detection::find_eins_in_text(text);
/// assert_eq!(matches.len(), 1);
/// ```
#[must_use]
pub fn find_eins_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::tax_id::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            let matched_text = full_match.as_str();
            if !is_ein(matched_text) {
                continue;
            }
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                matched_text.to_string(),
                IdentifierType::Ein,
            ));
        }
    }

    deduplicate_matches(matches)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_tax_id() {
        assert!(is_tax_id("00-0000001"));
        assert!(is_tax_id("912-34-5678")); // ITIN
        assert!(!is_tax_id("invalid"));
    }

    #[test]
    fn test_is_ein_valid_irs_prefix() {
        assert!(is_ein("12-3456789")); // Brookhaven
        assert!(is_ein("20-1234567")); // Austin
        assert!(is_ein("95-1234567")); // Internet
    }

    #[test]
    fn test_is_ein_rejects_invalid_prefix() {
        assert!(!is_ein("00-0000001")); // Invalid prefix 00
        assert!(!is_ein("07-1234567")); // Invalid prefix 07
        assert!(!is_ein("89-1234567")); // Invalid prefix 89
    }

    #[test]
    fn test_is_ein_rejects_itin_format() {
        // ITINs use SSN-style XXX-XX-XXXX format, not EIN's XX-XXXXXXX
        assert!(!is_ein("912-34-5678"));
        assert!(!is_ein("900-70-1234"));
    }

    #[test]
    fn test_is_ein_rejects_non_tax_ids() {
        assert!(!is_ein("invalid"));
        assert!(!is_ein(""));
        assert!(!is_ein("123456789")); // No dash
    }

    #[test]
    fn test_find_tax_ids_in_text() {
        let text = "Company EIN: 00-0000001";
        let matches = find_tax_ids_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect tax ID pattern");
        assert_eq!(first.identifier_type, IdentifierType::TaxId);
    }

    #[test]
    fn test_find_eins_in_text() {
        let text = "Company EIN: 12-3456789 and another 20-1234567";
        let matches = find_eins_in_text(text);
        assert_eq!(matches.len(), 2);
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::Ein),
            "All matches should be tagged Ein, not TaxId"
        );
    }

    #[test]
    fn test_find_eins_in_text_skips_invalid_prefix() {
        // 00-0000001 has invalid prefix; should NOT appear in EIN results
        let text = "Bad EIN: 00-0000001 and good EIN: 12-3456789";
        let matches = find_eins_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect valid EIN");
        assert_eq!(first.matched_text, "12-3456789");
    }

    #[test]
    fn test_find_eins_in_text_skips_itin() {
        // ITINs match the broader tax_id patterns but are not EINs
        let text = "ITIN: 912-34-5678";
        let matches = find_eins_in_text(text);
        assert!(matches.is_empty(), "ITINs must not be classified as EIN");
    }

    #[test]
    fn test_empty_input() {
        assert!(!is_tax_id(""));
    }
}

//! IBAN (International Bank Account Number) detection
//!
//! Detection with MOD-97 checksum validation per ISO 13616.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};

/// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 10_000;

/// Country-specific IBAN lengths (ISO 13616)
const COUNTRY_LENGTHS: &[(&str, usize)] = &[
    ("AL", 28),
    ("AT", 20),
    ("BE", 16),
    ("CH", 21),
    ("CZ", 24),
    ("DE", 22),
    ("DK", 18),
    ("ES", 24),
    ("FI", 18),
    ("FR", 27),
    ("GB", 22),
    ("GR", 27),
    ("HR", 21),
    ("HU", 28),
    ("IE", 22),
    ("IT", 27),
    ("LU", 20),
    ("NL", 18),
    ("NO", 15),
    ("PL", 28),
    ("PT", 25),
    ("RO", 24),
    ("SE", 24),
    ("SI", 19),
    ("SK", 24),
];

// ============================================================================
// Public API
// ============================================================================

/// Check if value is a valid IBAN (format + MOD-97 checksum)
#[must_use]
pub fn is_iban(value: &str) -> bool {
    let normalized = normalize_iban(value);
    if normalized.len() < 15 || normalized.len() > 34 {
        return false;
    }

    // Must start with 2 letters + 2 digits
    let chars: Vec<char> = normalized.chars().collect();
    if chars.len() < 4 {
        return false;
    }
    let first_two_alpha = chars.first().is_some_and(|c| c.is_ascii_uppercase())
        && chars.get(1).is_some_and(|c| c.is_ascii_uppercase());
    let next_two_digits = chars.get(2).is_some_and(|c| c.is_ascii_digit())
        && chars.get(3).is_some_and(|c| c.is_ascii_digit());

    if !first_two_alpha || !next_two_digits {
        return false;
    }

    // Validate country-specific length if known
    if let Some(country) = normalized.get(..2)
        && let Some(&(_, expected_len)) = COUNTRY_LENGTHS.iter().find(|&&(code, _)| code == country)
        && normalized.len() != expected_len
    {
        return false;
    }

    is_iban_checksum_valid(&normalized)
}

/// Validate IBAN MOD-97 checksum (ISO 7064)
///
/// Algorithm:
/// 1. Move first 4 chars to end
/// 2. Replace letters: A=10, B=11, ..., Z=35
/// 3. Compute number MOD 97 — must equal 1
#[must_use]
pub fn is_iban_checksum_valid(iban: &str) -> bool {
    let normalized = normalize_iban(iban);
    if normalized.len() < 5 {
        return false;
    }

    // Rearrange: move first 4 chars to end
    let (prefix, rest) = normalized.split_at(4);
    let rearranged = format!("{rest}{prefix}");

    // Convert to numeric string (A=10..Z=35) and compute MOD 97 iteratively
    let mut remainder: u64 = 0;
    for ch in rearranged.chars() {
        if ch.is_ascii_uppercase() {
            let value = (ch as u64).saturating_sub(b'A' as u64).saturating_add(10);
            // Two-digit number, so multiply remainder by 100
            remainder = (remainder.saturating_mul(100).saturating_add(value)) % 97;
        } else if ch.is_ascii_digit() {
            let value = (ch as u64).saturating_sub(b'0' as u64);
            remainder = (remainder.saturating_mul(10).saturating_add(value)) % 97;
        } else {
            return false; // Invalid character
        }
    }

    remainder == 1
}

/// Extract country code from an IBAN
#[must_use]
pub fn detect_iban_country(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.len() >= 2
        && trimmed
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_uppercase())
        && trimmed
            .as_bytes()
            .get(1)
            .is_some_and(|b| b.is_ascii_uppercase())
    {
        Some(&trimmed[..2])
    } else {
        None
    }
}

/// Detect all IBANs in text with checksum validation
#[allow(clippy::expect_used)]
#[must_use]
pub fn detect_ibans_in_text(text: &str) -> Vec<IdentifierMatch> {
    if text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();
    let upper_text = text.to_uppercase();

    for capture in patterns::bank_account::IBAN.captures_iter(&upper_text) {
        let full_match = capture.get(0).expect("BUG: capture group 0 always exists");
        let matched_text = full_match.as_str();

        // Validate with MOD-97 checksum
        if is_iban(matched_text) {
            // Use original text positions
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                text.get(full_match.start()..full_match.end())
                    .unwrap_or(matched_text)
                    .to_string(),
                IdentifierType::Iban,
            ));
        }
    }

    super::common::deduplicate_matches(matches)
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Normalize IBAN: uppercase, remove spaces
fn normalize_iban(value: &str) -> String {
    value
        .trim()
        .to_uppercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Known valid test IBANs
    const DE_IBAN: &str = "DE89370400440532013000";
    const GB_IBAN: &str = "GB29NWBK60161331926819";
    const FR_IBAN: &str = "FR7630006000011234567890189";
    const ES_IBAN: &str = "ES9121000418450200051332";
    const NL_IBAN: &str = "NL91ABNA0417164300";
    const CH_IBAN: &str = "CH9300762011623852957";
    const AT_IBAN: &str = "AT611904300234573201";
    const BE_IBAN: &str = "BE68539007547034";

    #[test]
    fn test_valid_ibans() {
        assert!(is_iban(DE_IBAN));
        assert!(is_iban(GB_IBAN));
        assert!(is_iban(FR_IBAN));
        assert!(is_iban(ES_IBAN));
        assert!(is_iban(NL_IBAN));
        assert!(is_iban(CH_IBAN));
        assert!(is_iban(AT_IBAN));
        assert!(is_iban(BE_IBAN));
    }

    #[test]
    fn test_iban_with_spaces() {
        assert!(is_iban("DE89 3704 0044 0532 0130 00"));
        assert!(is_iban("GB29 NWBK 6016 1331 9268 19"));
    }

    #[test]
    fn test_iban_lowercase() {
        assert!(is_iban("de89370400440532013000"));
        assert!(is_iban("gb29nwbk60161331926819"));
    }

    #[test]
    fn test_invalid_iban_checksum() {
        // Modified check digits — should fail MOD-97
        assert!(!is_iban("DE00370400440532013000"));
        assert!(!is_iban("GB00NWBK60161331926819"));
    }

    #[test]
    fn test_invalid_iban_length() {
        // DE should be 22, this is 20
        assert!(!is_iban("DE89370400440532"));
        // Too short
        assert!(!is_iban("DE89"));
        assert!(!is_iban(""));
    }

    #[test]
    fn test_detect_iban_country() {
        assert_eq!(detect_iban_country(DE_IBAN), Some("DE"));
        assert_eq!(detect_iban_country(GB_IBAN), Some("GB"));
        assert_eq!(detect_iban_country("not_iban"), None);
    }

    #[test]
    fn test_detect_ibans_in_text() {
        let text = "Transfer to DE89 3704 0044 0532 0130 00 or GB29 NWBK 6016 1331 9268 19";
        let matches = detect_ibans_in_text(text);
        assert_eq!(
            matches.len(),
            2,
            "expected 2 IBANs, got {}: {:?}",
            matches.len(),
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::Iban)
        );
    }

    #[test]
    fn test_detect_ibans_no_matches() {
        let text = "No IBANs here, just text and XX123456";
        let matches = detect_ibans_in_text(text);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_mod97_checksum_directly() {
        assert!(is_iban_checksum_valid("DE89370400440532013000"));
        assert!(!is_iban_checksum_valid("DE00370400440532013000"));
    }
}

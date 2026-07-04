//! Shared SSA-rule helpers used by both detection and validation.
//!
//! These are pure pattern-matching boolean helpers — no `Result`, no observe
//! dependencies. They live here (not under `detection/` or `validation/`)
//! because both layers consult them and the inheritance arrow forbids
//! `detection` from importing `validation`.

/// Check if SSN area code indicates ITIN
///
/// ITINs use area codes 900-999.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::common;
///
/// assert!(common::is_itin_area("912-34-5678"));
/// assert!(!common::is_itin_area("123-45-6789"));
/// ```
#[must_use]
pub(super) fn is_itin_area(ssn: &str) -> bool {
    let cleaned: String = ssn.chars().filter(|c| c.is_numeric()).collect();
    if cleaned.len() >= 3 {
        cleaned.starts_with('9')
    } else {
        false
    }
}

/// Check if an SSN is a known test/sample SSN
///
/// Test SSNs are commonly used in documentation, testing, and examples.
/// These should not be treated as real Social Security Numbers.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::common;
///
/// assert!(common::is_test_ssn("123-45-6789"));
/// assert!(common::is_test_ssn("078-05-1120")); // Woolworth's Wallet SSN
/// assert!(common::is_test_ssn("555-55-5555")); // All fives
/// assert!(!common::is_test_ssn("142-58-3697")); // Not a test pattern
/// ```
#[must_use]
pub(super) fn is_test_ssn(ssn: &str) -> bool {
    // Normalize: remove hyphens and spaces
    let cleaned: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();

    // Must be exactly 9 digits to be a valid SSN format
    if cleaned.len() != 9 {
        return false;
    }

    // Well-known test SSNs
    let test_ssns = [
        "078051120", // Woolworth's Wallet SSN (most famous invalid SSN)
        "123456789", // Sequential pattern
        "987654321", // Reverse sequential
        "111111111", // All ones (often used in testing)
        "222222222", // All twos
        "333333333", // All threes
        "444444444", // All fours
        "555555555", // All fives (common test pattern)
        "666666666", // All sixes
        "777777777", // All sevens
        "888888888", // All eights
        "999999999", // All nines
        "000000000", // All zeros
        // SSA and IRS example SSNs
        "219099999", // Used in some SSA examples
        "457555462", // Used in IRS examples
        // Credit card test patterns that look like SSNs
        "424242424", // Stripe test card fragment
        "401288888", // Visa test card fragment
        "401200000", // Visa test card fragment
        // Medical record test patterns
        "000000001", // Common placeholder
        "999999999", // Max value placeholder
    ];

    if test_ssns.contains(&cleaned.as_str()) {
        return true;
    }

    // Check for repeating digit patterns (all same digit)
    let chars: Vec<char> = cleaned.chars().collect();
    let first_char = chars.first().copied();
    if first_char.is_some() && chars.iter().all(|&c| Some(c) == first_char) {
        return true;
    }

    // Check for ascending sequential pattern (012345678, 123456789, etc.)
    // Note: char arithmetic is safe here as we're only dealing with ASCII digits
    #[allow(clippy::arithmetic_side_effects)]
    let is_ascending = chars.windows(2).all(|w| match (w.first(), w.get(1)) {
        (Some(&a), Some(&b)) => b as u8 == (a as u8).saturating_add(1) || (a == '9' && b == '0'),
        _ => false,
    });
    if is_ascending {
        return true;
    }

    // Check for descending sequential pattern (987654321, 876543210, etc.)
    // Note: char arithmetic is safe here as we're only dealing with ASCII digits
    #[allow(clippy::arithmetic_side_effects)]
    let is_descending = chars.windows(2).all(|w| match (w.first(), w.get(1)) {
        (Some(&a), Some(&b)) => a as u8 == (b as u8).saturating_add(1) || (b == '9' && a == '0'),
        _ => false,
    });
    if is_descending {
        return true;
    }

    false
}

/// ICAO Doc 9303 machine-readable-zone check-digit helpers.
///
/// Used by both German nPA (`GermanyIdCard`) and Reisepass
/// (`GermanyPassport`), and reusable for any future ICAO-compliant national
/// document number (Netherlands, France, …). Pure numeric helpers — no
/// `Result`, no observe — so both detection and validation may consult them
/// without violating the inheritance arrow.
pub(super) mod icao_doc_9303 {
    /// Repeating positional weights `7, 3, 1` per ICAO Doc 9303.
    const WEIGHTS: [u32; 3] = [7, 3, 1];

    /// Map a single MRZ character to its ICAO numeric value.
    ///
    /// Digits map to `0..=9`, letters `A..=Z` map to `10..=35`, and the
    /// filler `<` maps to `0`. Returns `None` for any other character.
    #[must_use]
    pub(crate) fn char_value(c: char) -> Option<u32> {
        match c {
            '0'..='9' => c.to_digit(10),
            'A'..='Z' => Some((c as u32).saturating_sub('A' as u32).saturating_add(10)),
            'a'..='z' => Some((c as u32).saturating_sub('a' as u32).saturating_add(10)),
            '<' => Some(0),
            _ => None,
        }
    }

    /// Compute the ICAO Doc 9303 check digit over `field`.
    ///
    /// Returns `None` if any character is outside the ICAO alphabet. The
    /// result is the weighted sum modulo 10.
    #[must_use]
    pub(crate) fn check_digit(field: &str) -> Option<u32> {
        let mut sum: u32 = 0;
        for (i, c) in field.chars().enumerate() {
            let value = char_value(c)?;
            let weight = WEIGHTS.get(i % 3).copied().unwrap_or(1);
            sum = sum.saturating_add(value.saturating_mul(weight));
        }
        Some(sum % 10)
    }

    /// Verify that the final character of `value` is the correct ICAO check
    /// digit for the preceding `body_len` characters.
    ///
    /// `value` must be exactly `body_len + 1` characters long; the trailing
    /// character is the check digit.
    #[must_use]
    pub(crate) fn verify(value: &str, body_len: usize) -> bool {
        let chars: Vec<char> = value.chars().collect();
        if chars.len() != body_len.saturating_add(1) {
            return false;
        }
        let body: String = chars.iter().take(body_len).collect();
        let Some(expected) = check_digit(&body) else {
            return false;
        };
        let Some(actual) = chars.get(body_len).and_then(|c| c.to_digit(10)) else {
            return false;
        };
        expected == actual
    }
}

/// Germany Steuer-IdNr (ISO 7064 mod-11,10) check-digit helpers.
///
/// Shared by `detection::is_germany_tax_id` and
/// `validation::validate_germany_tax_id_with_checksum`. Pure numeric — no
/// `Result`, no observe.
pub(super) mod germany_tax_id {
    /// Verify the ISO 7064 mod-11,10 check digit over an 11-digit string.
    ///
    /// The first 10 digits feed the algorithm; the 11th is the check digit.
    /// Returns `false` for any non-11-digit input or checksum mismatch.
    #[must_use]
    pub(crate) fn verify_checksum(digits: &str) -> bool {
        let ds: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
        if ds.len() != 11 {
            return false;
        }
        // ISO 7064 mod 11,10: iterate over the first 10 digits.
        let mut product: u32 = 10;
        for &d in ds.iter().take(10) {
            let mut sum = (d.saturating_add(product)) % 10;
            if sum == 0 {
                sum = 10;
            }
            product = (sum.saturating_mul(2)) % 11;
        }
        let check = (11u32.saturating_sub(product)) % 10;
        ds.get(10).copied() == Some(check)
    }

    /// Verify the German structural rule for a Steuer-IdNr's first 10 digits.
    ///
    /// Among the first 10 digits exactly one digit appears more than once
    /// (either twice, or — since 2016 — three times consecutively), and the
    /// leading digit is non-zero. Digits appearing 4+ times, or two distinct
    /// repeated digits, are invalid.
    #[must_use]
    pub(crate) fn verify_structure(digits: &str) -> bool {
        let ds: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
        if ds.len() != 11 {
            return false;
        }
        if ds.first().copied() == Some(0) {
            return false;
        }
        let mut counts = [0u8; 10];
        for &d in ds.iter().take(10) {
            if let Some(slot) = counts.get_mut(d as usize) {
                *slot = slot.saturating_add(1);
            }
        }
        let repeated = counts.iter().filter(|&&c| c >= 2).count();
        let max_count = counts.iter().copied().max().unwrap_or(0);
        // Exactly one digit repeats, and it repeats at most three times.
        repeated == 1 && (2..=3).contains(&max_count)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_icao_check_digit_known_vectors() {
        // ICAO Doc 9303 canonical MRZ example: passport number "L898902C3"
        // has published check digit 6.
        assert_eq!(icao_doc_9303::check_digit("L898902C3"), Some(6));
        // Date-of-birth field "740812" → check digit 2.
        assert_eq!(icao_doc_9303::check_digit("740812"), Some(2));
        // Expiry "120415" → check digit 9.
        assert_eq!(icao_doc_9303::check_digit("120415"), Some(9));
        // Non-ICAO character rejected.
        assert_eq!(icao_doc_9303::check_digit("ABC!"), None);
    }

    #[test]
    fn test_icao_verify() {
        assert!(icao_doc_9303::verify("L898902C36", 9));
        assert!(!icao_doc_9303::verify("L898902C35", 9)); // wrong check digit
        assert!(!icao_doc_9303::verify("L898902C3", 9)); // too short
    }

    #[test]
    fn test_germany_tax_id_structure_and_checksum() {
        // 10002345676: first 10 digits 1000234567, digit '0' repeats 3×
        // (exactly one repeated digit), leading digit non-zero, valid ISO
        // 7064 mod-11,10 check digit 6.
        assert!(germany_tax_id::verify_structure("10002345676"));
        assert!(germany_tax_id::verify_checksum("10002345676"));
        // Leading zero → invalid structure (BZSt doc examples like
        // 02476291358 are deliberately non-issuable).
        assert!(!germany_tax_id::verify_structure("02476291358"));
        // Ascending, no repeats → invalid (no repeated digit).
        assert!(!germany_tax_id::verify_structure("12345678905"));
        // Tampered check digit → checksum fails.
        assert!(!germany_tax_id::verify_checksum("10002345675"));
    }

    #[test]
    fn test_is_itin_area() {
        assert!(is_itin_area("912-34-5678"));
        assert!(is_itin_area("900-70-1234"));
        assert!(is_itin_area("999-88-7654"));
        assert!(!is_itin_area("123-45-6789"));
        assert!(!is_itin_area("517-29-8346"));
        // Too short to determine area
        assert!(!is_itin_area("12"));
        assert!(!is_itin_area(""));
    }

    #[test]
    fn test_is_test_ssn_known_patterns() {
        // Well-known test SSNs
        assert!(is_test_ssn("123-45-6789")); // Sequential
        assert!(is_test_ssn("123456789")); // Sequential without hyphens
        assert!(is_test_ssn("078-05-1120")); // Woolworth's Wallet SSN
        assert!(is_test_ssn("987-65-4321")); // Reverse sequential
        assert!(is_test_ssn("219-09-9999")); // SSA example
        assert!(is_test_ssn("457-55-5462")); // IRS example
    }

    #[test]
    fn test_is_test_ssn_repeating_patterns() {
        // All same digit patterns
        assert!(is_test_ssn("111-11-1111"));
        assert!(is_test_ssn("222-22-2222"));
        assert!(is_test_ssn("333-33-3333"));
        assert!(is_test_ssn("444-44-4444"));
        assert!(is_test_ssn("555-55-5555"));
        assert!(is_test_ssn("666-66-6666"));
        assert!(is_test_ssn("777-77-7777"));
        assert!(is_test_ssn("888-88-8888"));
        assert!(is_test_ssn("999-99-9999"));
        assert!(is_test_ssn("000-00-0000"));
    }

    #[test]
    fn test_is_test_ssn_not_test_patterns() {
        // Valid-looking SSNs that are NOT test patterns
        // (non-sequential, non-repeating, not in known test list)
        assert!(!is_test_ssn("142-58-3697")); // Random-looking pattern
        assert!(!is_test_ssn("903-75-2841")); // Random-looking pattern
        assert!(!is_test_ssn("517-29-8346")); // Random-looking pattern
        assert!(!is_test_ssn("628-41-9053")); // Random-looking pattern
        assert!(!is_test_ssn("900-01-0001")); // ITIN-like but not test pattern
    }

    #[test]
    fn test_is_test_ssn_invalid_format() {
        // Invalid format should return false (not a test SSN, not any SSN)
        assert!(!is_test_ssn("123-45-678")); // Too short
        assert!(!is_test_ssn("123-45-67890")); // Too long
        assert!(!is_test_ssn("abc-de-fghi")); // Letters
        assert!(!is_test_ssn("")); // Empty
    }

    #[test]
    fn test_is_test_ssn_credit_card_patterns() {
        // Credit card test patterns that look like SSNs
        assert!(is_test_ssn("424-24-2424")); // Stripe test card fragment
    }
}

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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

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

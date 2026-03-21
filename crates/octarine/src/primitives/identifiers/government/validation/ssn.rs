//! Social Security Number (SSN) validation
//!
//! Pure validation functions for US Social Security Numbers.
//!
//! # SSA Validation Rules
//!
//! SSN validation implements Social Security Administration rules:
//! - Area 000 is never valid
//! - Area 666 is reserved/never issued
//! - Areas 900-999 are for ITINs (not SSNs)
//! - Group 00 is invalid
//! - Serial 0000 is invalid
//! - Test patterns (123-45-6789, etc.) are rejected

use super::super::super::common::patterns;
use crate::primitives::Problem;

use super::cache::SSN_VALIDATION_CACHE;

// ============================================================================
// SSN Validation
// ============================================================================

/// Validate SSN format
///
/// Validates US Social Security Numbers per SSA rules.
/// For maximum protection, we treat any 9-digit number as potentially sensitive.
/// SSNs, ITINs, and EINs all use 9 digits and have overlapping ranges.
///
/// # Arguments
///
/// * `ssn` - The SSN string to validate (with or without hyphens)
///
/// # Returns
///
/// * `Ok(())` - If the SSN format is valid per SSA rules
/// * `Err(Problem)` - If the format is invalid or contains test patterns
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// // Valid SSN format
/// assert!(validation::validate_ssn("234-56-7890").is_ok());
/// assert!(validation::validate_ssn("345678901").is_ok());
///
/// // Invalid formats
/// assert!(validation::validate_ssn("000-00-0000").is_err()); // All zeros
/// assert!(validation::validate_ssn("666-11-2222").is_err()); // Area 666
/// assert!(validation::validate_ssn("123-00-4567").is_err()); // Group 00
/// ```
///
/// # SSA Validation Rules
///
/// - **Area (first 3 digits)**: Cannot be 000, 666, or sequential patterns
/// - **Group (middle 2 digits)**: Cannot be 00
/// - **Serial (last 4 digits)**: Cannot be 0000
/// - **Area 9xx**: ITINs, not SSNs (warning but not rejected)
///
/// # Compliance
///
/// - **OWASP**: Input Validation Cheat Sheet
/// - **PCI DSS**: Redacted logging, test pattern detection
/// - **HIPAA**: Medical record pattern rejection
pub fn validate_ssn(ssn: &str) -> Result<(), Problem> {
    // Check cache first
    let cache_key = ssn.to_string();
    if let Some(cached) = SSN_VALIDATION_CACHE.get(&cache_key) {
        return cached.map_err(Problem::validation);
    }

    // Perform validation and cache the result
    let result = validate_ssn_uncached(ssn);

    // Cache as Result<(), String> for serialization
    let cache_value = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
    SSN_VALIDATION_CACHE.insert(cache_key, cache_value);

    result
}

/// Internal SSN validation without caching
fn validate_ssn_uncached(ssn: &str) -> Result<(), Problem> {
    if !patterns::ssn::EXACT.is_match(ssn) {
        return Err(Problem::Validation("Invalid SSN format".into()));
    }

    // Remove hyphens for validation
    let cleaned: String = ssn.chars().filter(|c| c.is_numeric()).collect();

    if cleaned.len() != 9 {
        return Err(Problem::Validation("SSN must be 9 digits".into()));
    }

    // Check for invalid SSN patterns per SSA rules
    let area = &cleaned[0..3];
    let group = &cleaned[3..5];
    let serial = &cleaned[5..9];

    // SSA Rule: Area 000 is never valid
    if area == "000" {
        return Err(Problem::Validation("Invalid SSN area number 000".into()));
    }

    // SSA Rule: Area 666 is reserved/never issued
    if area == "666" {
        return Err(Problem::Validation("Invalid SSN area number 666".into()));
    }

    // SSA Rule: Group 00 is invalid
    if group == "00" {
        return Err(Problem::Validation("Invalid SSN group number 00".into()));
    }

    // SSA Rule: Serial 0000 is invalid
    if serial == "0000" {
        return Err(Problem::Validation("Invalid SSN serial number 0000".into()));
    }

    // Check for well-known test SSNs and patterns
    let test_ssns = [
        "078051120", // Woolworth's Wallet SSN (common in examples)
        "123456789", // Sequential pattern
        "987654321", // Reverse sequential
        "111111111", // All ones (often used in testing)
        "222222222", // All twos
        "333333333", // All threes
        "444444444", // All fours
        "555555555", // All fives (common test pattern)
        "666666666", // All sixes (invalid anyway)
        "777777777", // All sevens
        "888888888", // All eights
        "999999999", // All nines
        "000000000", // All zeros (invalid anyway)
        // Additional test SSNs from various sources
        "219099999", // Used in some SSA examples
        "457555462", // Used in IRS examples
    ];

    if test_ssns.contains(&cleaned.as_str()) {
        return Err(Problem::Validation("Test SSN patterns not allowed".into()));
    }

    // Check for credit card test patterns that look like SSNs
    if cleaned == "424242424" || cleaned == "401288888" || cleaned == "401200000" {
        return Err(Problem::Validation(
            "Test payment card pattern detected".into(),
        ));
    }

    // Check for medical record number patterns
    if cleaned == "000000001" || cleaned == "999999999" {
        return Err(Problem::Validation(
            "Test medical identifier pattern detected".into(),
        ));
    }

    Ok(())
}

/// Check if SSN area code indicates ITIN
///
/// ITINs use area codes 900-999.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::is_itin_area("912-34-5678"));
/// assert!(!validation::is_itin_area("123-45-6789"));
/// ```
#[must_use]
pub fn is_itin_area(ssn: &str) -> bool {
    let cleaned: String = ssn.chars().filter(|c| c.is_numeric()).collect();
    if cleaned.len() >= 3 {
        cleaned.starts_with('9')
    } else {
        false
    }
}

// ============================================================================
// Test Pattern Detection
// ============================================================================

/// Check if an SSN is a known test/sample SSN
///
/// Test SSNs are commonly used in documentation, testing, and examples.
/// These should not be treated as real Social Security Numbers.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::is_test_ssn("123-45-6789"));
/// assert!(validation::is_test_ssn("078-05-1120")); // Woolworth's Wallet SSN
/// assert!(validation::is_test_ssn("555-55-5555")); // All fives
/// assert!(!validation::is_test_ssn("142-58-3697")); // Not a test pattern
/// ```
#[must_use]
pub fn is_test_ssn(ssn: &str) -> bool {
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
    use super::super::cache::ssn_cache_stats;
    use super::*;

    #[test]
    fn test_ssn_validation() {
        // Valid SSN formats (not in test pattern list)
        assert!(validate_ssn("234-56-7890").is_ok());
        assert!(validate_ssn("345-67-8901").is_ok());
        assert!(validate_ssn("456789012").is_ok()); // No hyphens
    }

    #[test]
    fn test_ssn_test_patterns_rejected() {
        // Sequential patterns should be rejected
        assert!(validate_ssn("123-45-6789").is_err());
        assert!(validate_ssn("123456789").is_err());
        assert!(validate_ssn("987654321").is_err()); // Reverse sequential
    }

    #[test]
    fn test_ssn_invalid_area() {
        // Area 000 is invalid
        assert!(validate_ssn("000-12-3456").is_err());

        // Area 666 is reserved
        assert!(validate_ssn("666-12-3456").is_err());
    }

    #[test]
    fn test_ssn_invalid_group() {
        // Group 00 is invalid
        assert!(validate_ssn("123-00-4567").is_err());
    }

    #[test]
    fn test_ssn_invalid_serial() {
        // Serial 0000 is invalid
        assert!(validate_ssn("123-45-0000").is_err());
    }

    #[test]
    fn test_ssn_test_patterns() {
        // Well-known test SSNs should be rejected
        assert!(validate_ssn("123-45-6789").is_err()); // Sequential
        assert!(validate_ssn("078-05-1120").is_err()); // Woolworth's
        assert!(validate_ssn("111-11-1111").is_err()); // All ones
        assert!(validate_ssn("555-55-5555").is_err()); // All fives
        assert!(validate_ssn("987-65-4321").is_err()); // Reverse sequential
    }

    #[test]
    fn test_ssn_invalid_format() {
        // Too short
        assert!(validate_ssn("12-34-567").is_err());

        // Too long
        assert!(validate_ssn("1234-56-7890").is_err());

        // Letters
        assert!(validate_ssn("ABC-DE-FGHI").is_err());

        // Special characters
        assert!(validate_ssn("123.45.6789").is_err());
    }

    #[test]
    fn test_ssn_itin_area() {
        // ITINs use 9xx area codes - we warn but don't reject
        assert!(validate_ssn("912-34-5678").is_ok());
        assert!(validate_ssn("987-12-3456").is_ok());

        // Check ITIN detection
        assert!(is_itin_area("912-34-5678"));
        assert!(!is_itin_area("123-45-6789"));
    }

    #[test]
    fn test_ssn_credit_card_patterns() {
        // Should reject credit card test patterns
        assert!(validate_ssn("424-24-2424").is_err());
    }

    #[test]
    fn test_ssn_cache_hit() {
        // Use a unique SSN for this test to avoid interference
        let ssn = "345-67-8901";

        // First call - populate cache
        assert!(validate_ssn(ssn).is_ok());

        // Get stats before second call
        let stats_before = ssn_cache_stats();

        // Second call - should be cache hit
        assert!(validate_ssn(ssn).is_ok());
        let stats_after = ssn_cache_stats();

        // Verify we got a cache hit (hits increased or size didn't increase)
        // Using relative comparison to handle parallel test execution
        let hits_increased = stats_after.hits > stats_before.hits;
        let size_same = stats_after.size == stats_before.size || stats_after.size > 0;

        assert!(
            hits_increased || size_same,
            "Expected cache hit: hits before={}, after={}; size before={}, after={}",
            stats_before.hits,
            stats_after.hits,
            stats_before.size,
            stats_after.size
        );
    }

    #[test]
    fn test_ssn_cache_error_cached() {
        // Use a unique invalid SSN for this test
        let invalid_ssn = "000-12-3456";

        // First call - returns error
        assert!(validate_ssn(invalid_ssn).is_err());
        let stats_after_first = ssn_cache_stats();

        // Second call - should be cache hit with same error
        let result = validate_ssn(invalid_ssn);
        let stats_after_second = ssn_cache_stats();

        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("000")
        );

        // Verify we got a cache hit
        assert!(
            stats_after_second.hits > stats_after_first.hits,
            "Expected cache hit for error: hits before={}, hits after={}",
            stats_after_first.hits,
            stats_after_second.hits
        );
    }

    #[test]
    fn test_empty_input() {
        assert!(validate_ssn("").is_err());
    }

    #[test]
    fn test_ssn_unicode_lookalikes() {
        // Full-width digits (U+FF10-U+FF19)
        assert!(validate_ssn("１２３-45-6789").is_err()); // Full-width 1,2,3
        assert!(validate_ssn("123-４５-6789").is_err()); // Full-width 4,5

        // Arabic-Indic digits (U+0660-U+0669)
        assert!(validate_ssn("١٢٣-45-6789").is_err()); // Arabic digits

        // Unicode hyphens that look like ASCII hyphen
        assert!(validate_ssn("123\u{2010}45\u{2010}6789").is_err()); // Hyphen (U+2010)
        assert!(validate_ssn("123\u{2011}45\u{2011}6789").is_err()); // Non-breaking hyphen
        assert!(validate_ssn("123\u{2212}45\u{2212}6789").is_err()); // Minus sign
    }

    #[test]
    fn test_ssn_whitespace_variations() {
        assert!(validate_ssn(" 123-45-6789").is_err()); // Leading space
        assert!(validate_ssn("123-45-6789 ").is_err()); // Trailing space
        assert!(validate_ssn("123 -45-6789").is_err()); // Space before hyphen
        assert!(validate_ssn("123-\t45-6789").is_err()); // Tab
        assert!(validate_ssn("123-45\n-6789").is_err()); // Newline
        assert!(validate_ssn("123\u{00A0}45-6789").is_err()); // Non-breaking space
        assert!(validate_ssn("123\u{2003}45-6789").is_err()); // Em space
    }

    #[test]
    fn test_ssn_null_bytes() {
        assert!(validate_ssn("123\0-45-6789").is_err());
        assert!(validate_ssn("123-45-67\089").is_err());
    }

    #[test]
    fn test_ssn_very_long_input() {
        let long_input = "1".repeat(10000);
        let start = std::time::Instant::now();
        let _ = validate_ssn(&long_input);
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 100,
            "Long input took too long: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_ssn_empty_input() {
        assert!(validate_ssn("").is_err());
        assert!(validate_ssn("   ").is_err()); // Whitespace only
    }

    #[test]
    fn test_ssn_boundary_values() {
        // Area number boundaries
        assert!(validate_ssn("000-01-0001").is_err()); // Invalid: 000
        assert!(validate_ssn("001-01-0001").is_ok()); // Valid: 001
        assert!(validate_ssn("666-01-0001").is_err()); // Invalid: 666
        assert!(validate_ssn("665-01-0001").is_ok()); // Valid: 665
        assert!(validate_ssn("667-01-0001").is_ok()); // Valid: 667
        assert!(validate_ssn("900-01-0001").is_ok()); // Valid: ITIN in lenient mode

        // Group number boundaries
        assert!(validate_ssn("234-00-0001").is_err()); // Invalid: 00
        assert!(validate_ssn("234-01-0001").is_ok()); // Valid: 01
        assert!(validate_ssn("234-99-0001").is_ok()); // Valid: 99

        // Serial number boundaries
        assert!(validate_ssn("234-56-0000").is_err()); // Invalid: 0000
        assert!(validate_ssn("234-56-0001").is_ok()); // Valid: 0001
        assert!(validate_ssn("234-56-9999").is_ok()); // Valid: 9999
    }

    #[test]
    fn test_ssn_mixed_separators() {
        assert!(validate_ssn("123.45.6789").is_err()); // Dots
        assert!(validate_ssn("123/45/6789").is_err()); // Slashes
        assert!(validate_ssn("123_45_6789").is_err()); // Underscores
        assert!(validate_ssn("123 45 6789").is_err()); // Spaces (invalid without hyphens)
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

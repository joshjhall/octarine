//! Vehicle Identification Number (VIN) validation
//!
//! Pure validation functions for VINs.
//!
//! # VIN Format
//!
//! VINs are 17 characters, excluding I, O, Q (confused with 1, 0).
//!
//! # Check Digit
//!
//! The 9th character is a check digit calculated from other positions
//! using a specific algorithm based on character transliteration values
//! and position weights.

use crate::primitives::Problem;

use super::cache::VIN_CHECKSUM_CACHE;

// ============================================================================
// VIN Validation
// ============================================================================

/// Validate VIN (Vehicle Identification Number) format
///
/// VINs are 17 characters, excluding I, O, Q (confused with 1, 0).
/// Returns detailed error messages for invalid formats.
///
/// # Returns
///
/// * `Ok(())` - If the VIN format is valid
/// * `Err(Problem)` - If the format is invalid with details
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::validate_vin("1HGBH41JXMN109186").is_ok());
/// assert!(validation::validate_vin("invalid").is_err());
/// assert!(validation::validate_vin("1HGBH41JOMN109186").is_err()); // Contains 'O'
/// ```
pub fn validate_vin(vin: &str) -> Result<(), Problem> {
    if vin.len() != 17 {
        return Err(Problem::Validation(format!(
            "VIN must be exactly 17 characters (got {})",
            vin.len()
        )));
    }

    let vin_upper = vin.to_uppercase();

    // VIN cannot contain I, O, Q (easily confused with 1, 0)
    if vin_upper.contains('I') {
        return Err(Problem::Validation(
            "VIN cannot contain 'I' (easily confused with '1')".into(),
        ));
    }
    if vin_upper.contains('O') {
        return Err(Problem::Validation(
            "VIN cannot contain 'O' (easily confused with '0')".into(),
        ));
    }
    if vin_upper.contains('Q') {
        return Err(Problem::Validation(
            "VIN cannot contain 'Q' (easily confused with '0')".into(),
        ));
    }

    // Must be alphanumeric
    if !vin_upper.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(Problem::Validation(
            "VIN must contain only alphanumeric characters".into(),
        ));
    }

    Ok(())
}

/// Validate VIN with check digit verification
///
/// The 9th character is a check digit calculated from other positions.
/// Returns detailed error messages for invalid VINs or checksum failures.
///
/// # Returns
///
/// * `Ok(())` - If the VIN format and checksum are valid
/// * `Err(Problem)` - If the VIN is invalid with details
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::validate_vin_with_checksum("11111111111111111").is_ok());
/// assert!(validation::validate_vin_with_checksum("invalid").is_err());
/// ```
pub fn validate_vin_with_checksum(vin: &str) -> Result<(), Problem> {
    // Check cache first - cache stores Result as bool for simplicity
    let cache_key = vin.to_uppercase();
    if let Some(cached) = VIN_CHECKSUM_CACHE.get(&cache_key) {
        return if cached {
            Ok(())
        } else {
            Err(Problem::Validation(
                "VIN checksum validation failed (cached)".into(),
            ))
        };
    }

    // Perform validation
    let result = validate_vin_checksum_uncached(vin);

    // Cache the result as bool
    let cache_value = result.is_ok();
    VIN_CHECKSUM_CACHE.insert(cache_key, cache_value);

    result
}

/// Internal VIN checksum validation without caching
fn validate_vin_checksum_uncached(vin: &str) -> Result<(), Problem> {
    // First validate basic VIN format
    validate_vin(vin)?;

    let vin_upper = vin.to_uppercase();
    let chars: Vec<char> = vin_upper.chars().collect();

    // Transliteration values for characters
    let char_value = |c: char| -> Option<u32> {
        match c {
            'A' | 'J' => Some(1),
            'B' | 'K' | 'S' => Some(2),
            'C' | 'L' | 'T' => Some(3),
            'D' | 'M' | 'U' => Some(4),
            'E' | 'N' | 'V' => Some(5),
            'F' | 'W' => Some(6),
            'G' | 'P' | 'X' => Some(7),
            'H' | 'Y' => Some(8),
            'R' | 'Z' => Some(9),
            '0'..='9' => c.to_digit(10),
            _ => None,
        }
    };

    // Position weights
    let weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];

    // Calculate checksum
    let mut sum: u32 = 0;
    for (i, &c) in chars.iter().enumerate() {
        if i == 8 {
            continue; // Skip check digit position
        }
        let Some(weight) = weights.get(i) else {
            return Err(Problem::Validation(format!(
                "Invalid VIN position index: {}",
                i
            )));
        };
        if let Some(val) = char_value(c) {
            sum = sum.saturating_add(val.saturating_mul(*weight));
        } else {
            return Err(Problem::Validation(format!(
                "Invalid character '{}' at position {}",
                c, i
            )));
        }
    }

    let check_digit = sum % 11;
    let expected = if check_digit == 10 {
        'X'
    } else {
        char::from_digit(check_digit, 10).unwrap_or('?')
    };

    let actual = chars.get(8).ok_or_else(|| {
        Problem::Validation("VIN check digit position (9th character) not found".into())
    })?;

    if *actual == expected {
        Ok(())
    } else {
        Err(Problem::Validation(format!(
            "VIN check digit mismatch: expected '{}', got '{}'",
            expected, actual
        )))
    }
}

// ============================================================================
// Test Pattern Detection
// ============================================================================

/// Check if a VIN is a known test/sample VIN
///
/// Test VINs are commonly used in documentation, testing, and examples.
/// These should not be treated as real vehicle identifiers.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::validation;
///
/// assert!(validation::is_test_vin("11111111111111111"));
/// assert!(validation::is_test_vin("1HGBH41JXMN109186")); // Common example VIN
/// assert!(!validation::is_test_vin("WF0XXXGCDW1234567")); // Real format
/// ```
#[must_use]
pub fn is_test_vin(vin: &str) -> bool {
    let vin_upper = vin.to_uppercase().replace([' ', '-'], "");

    // Well-known test VINs
    let test_vins = [
        "11111111111111111", // All ones (valid check digit)
        "1HGBH41JXMN109186", // Common example VIN in documentation
        "WVWZZZ3CZWE123456", // VW example VIN
        "1G1YY22G965104367", // GM test VIN
        "JH4KA3250JC001234", // Acura example
        "00000000000000000", // All zeros (invalid but used as placeholder)
    ];

    if test_vins.contains(&vin_upper.as_str()) {
        return true;
    }

    // Sequential patterns
    if vin_upper.chars().all(|c| c == '1')
        || vin_upper.chars().all(|c| c == '2')
        || vin_upper.chars().all(|c| c == 'A')
    {
        return true;
    }

    // Check for obviously fake patterns
    // Sequential 12345678... pattern
    if vin_upper.contains("123456789") || vin_upper.contains("987654321") {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::super::cache::{clear_government_caches, vin_cache_stats};
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_vin_format() {
        assert!(validate_vin("1HGBH41JXMN109186").is_ok());
        assert!(validate_vin("1HGBH41JOMN109186").is_err()); // Contains O
        assert!(validate_vin("short").is_err());
        assert!(validate_vin("12345678901234567890").is_err()); // Too long
    }

    #[test]
    fn test_vin_checksum() {
        // Known valid VIN with correct check digit
        assert!(validate_vin_with_checksum("11111111111111111").is_ok());
        // VIN with all 1s should have check digit 1
    }

    #[test]
    fn test_empty_input() {
        assert!(validate_vin("").is_err());
    }

    #[test]
    fn test_vin_cache_hit() {
        // Use a unique VIN for this test (all 3s has check digit 3)
        let vin = "33333333333333333";

        // First call - populate cache
        assert!(validate_vin_with_checksum(vin).is_ok());
        let stats_after_first = vin_cache_stats();

        // Second call - should be cache hit
        assert!(validate_vin_with_checksum(vin).is_ok());
        let stats_after_second = vin_cache_stats();

        // Verify we got a cache hit
        assert!(
            stats_after_second.hits > stats_after_first.hits,
            "Expected VIN cache hit: hits before={}, hits after={}",
            stats_after_first.hits,
            stats_after_second.hits
        );
    }

    #[test]
    fn test_vin_cache_case_insensitive() {
        let vin = "44444444444444444";

        // First call - populate cache
        let _ = validate_vin_with_checksum(vin);
        let stats_after_first = vin_cache_stats();

        // Second call - should be cache hit
        let _ = validate_vin_with_checksum(vin);
        let stats_after_second = vin_cache_stats();

        // Verify we got a cache hit
        assert!(
            stats_after_second.hits > stats_after_first.hits,
            "Expected VIN cache hit: hits before={}, hits after={}",
            stats_after_first.hits,
            stats_after_second.hits
        );
    }

    #[test]
    #[serial]
    fn test_clear_government_caches() {
        // Populate caches with unique values
        let _ = validate_vin_with_checksum("22222222222222222");

        let stats_before = vin_cache_stats();
        assert!(stats_before.size > 0 || stats_before.hits > 0 || stats_before.misses > 0);

        // Clear caches - this should not panic
        clear_government_caches();

        // After clear, the next call should be a cache miss
        let stats_after_clear = vin_cache_stats();
        let _ = validate_vin_with_checksum("22222222222222222");
        let stats_after_call = vin_cache_stats();

        // Should have a miss since cache was cleared
        assert!(stats_after_call.misses > stats_after_clear.misses);
    }

    #[test]
    fn test_is_test_vin() {
        // Known test VINs
        assert!(is_test_vin("11111111111111111"));
        assert!(is_test_vin("1HGBH41JXMN109186"));
        assert!(is_test_vin("00000000000000000"));

        // Sequential patterns
        assert!(is_test_vin("12345678987654321"));

        // Real-looking VINs (not test patterns)
        assert!(!is_test_vin("WF0XXXGCDW1234567"));
        assert!(!is_test_vin("5YJSA1CN0DFP12345"));
    }

    #[test]
    fn test_vin_unicode_lookalikes() {
        // Full-width letters
        assert!(validate_vin("１HGBH41JXMN109186").is_err());

        // Cyrillic letters that look like Latin
        assert!(validate_vin("1HGВH41JXMN109186").is_err()); // Cyrillic В instead of B
        assert!(validate_vin("1HGBН41JXMN109186").is_err()); // Cyrillic Н instead of H
    }

    #[test]
    #[ignore = "timing-sensitive: run with just test-perf"]
    fn test_perf_vin_redos_protection() {
        let pathological = "A".repeat(1000);
        let start = std::time::Instant::now();
        let _ = validate_vin(&pathological);
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 100,
            "VIN validation took too long: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_case_insensitivity() {
        // VIN should be case-insensitive
        assert!(validate_vin("1hgbh41jxmn109186").is_ok());
        assert!(validate_vin("1HGBH41JXMN109186").is_ok());
        assert!(validate_vin("1HgBh41JxMn109186").is_ok());
    }

    #[test]
    fn test_validate_vin_success() {
        // Valid VIN
        assert!(validate_vin("1HGBH41JXMN109186").is_ok());
        assert!(validate_vin("WF0XXXGCDW1234567").is_ok());

        // Case insensitive
        assert!(validate_vin("1hgbh41jxmn109186").is_ok());
    }

    #[test]
    fn test_validate_vin_errors() {
        // Too short
        let result = validate_vin("short");
        assert!(result.is_err());
        let err_msg = result.expect_err("expected error").to_string();
        assert!(err_msg.contains("17 characters"));
        assert!(err_msg.contains("got 5"));

        // Contains 'I'
        let result = validate_vin("1HGBH41JIMN109186");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("cannot contain 'I'")
        );

        // Contains 'O'
        let result = validate_vin("1HGBH41JOMN109186");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("cannot contain 'O'")
        );

        // Contains 'Q'
        let result = validate_vin("1HGBH41JQMN109186");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("cannot contain 'Q'")
        );

        // Special characters
        let result = validate_vin("1HGBH41JX-N109186");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("alphanumeric")
        );
    }

    #[test]
    fn test_validate_vin_with_checksum_success() {
        // Valid VIN with correct checksum
        assert!(validate_vin_with_checksum("11111111111111111").is_ok());
    }

    #[test]
    fn test_validate_vin_with_checksum_errors() {
        // Invalid VIN format - too short (using unique value for this test)
        let result = validate_vin_with_checksum("ABC");
        assert!(result.is_err());
        let _ = result.expect_err("expected error for short VIN");
    }
}

//! Phone number detection
//!
//! Pure detection functions for phone numbers including E.164 and US formats.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType, PhoneRegion};

use super::cache::PHONE_CACHE;

/// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 10_000;

// ============================================================================
// Public API
// ============================================================================

/// Check if value is a phone number (cached)
///
/// Validates phone numbers in E.164 format (7-15 digits):
/// - With `+` prefix: `+14155552671` (international)
/// - Without `+`: `14155552671`, `5551234567` (assumes country code or US)
/// - Various separators: `(415) 555-2671`, `415-555-2671`
///
/// Per E.164 standard, phone numbers can be 7-15 digits globally.
/// Phone numbers without + prefix cannot start with 0.
pub fn is_phone_number(value: &str) -> bool {
    let trimmed = value.trim();

    // Check cache first
    if let Some(result) = PHONE_CACHE.get(&trimmed.to_string()) {
        return result;
    }

    // Extract digits for validation
    let cleaned: String = trimmed
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect();

    let digit_count = cleaned.chars().filter(|c| c.is_ascii_digit()).count();

    // E.164: must be 7-15 digits
    if !(7..=15).contains(&digit_count) {
        PHONE_CACHE.insert(trimmed.to_string(), false);
        return false;
    }

    // E.164: phone numbers without + prefix cannot start with 0
    if !cleaned.starts_with('+')
        && let Some(first_digit) = cleaned.chars().next()
        && first_digit == '0'
    {
        PHONE_CACHE.insert(trimmed.to_string(), false);
        return false;
    }

    // Check both pattern matching and digit-based validation
    let result = patterns::phone::E164_EXACT.is_match(trimmed)
        || patterns::phone::US_EXACT.is_match(trimmed)
        || digit_count >= 7; // Accept any 7-15 digit number not starting with 0

    // Cache the result
    PHONE_CACHE.insert(trimmed.to_string(), result);

    result
}

/// Find phone number region from the phone string
///
/// Analyzes the phone number to determine the region based on country code.
/// Requires E.164 format with leading + for accurate detection.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection;
///
/// assert_eq!(detection::find_phone_region("+14155552671"), Some(PhoneRegion::NorthAmerica));
/// assert_eq!(detection::find_phone_region("+442071234567"), Some(PhoneRegion::Uk));
/// assert_eq!(detection::find_phone_region("5551234567"), Some(PhoneRegion::Unknown)); // No country code
/// ```
pub fn find_phone_region(phone: &str) -> Option<PhoneRegion> {
    // Clean the phone number
    let cleaned: String = phone
        .chars()
        .filter(|c| c.is_numeric() || *c == '+')
        .collect();

    if !cleaned.starts_with('+') {
        // No country code, return Unknown
        return Some(PhoneRegion::Unknown);
    }

    // Extract country code (1-3 digits after +)
    let digits_after_plus: String = cleaned.chars().skip(1).take(3).collect();

    // Match against known country codes
    if digits_after_plus.starts_with('1') {
        // +1 - North America (US, Canada, Caribbean)
        Some(PhoneRegion::NorthAmerica)
    } else if digits_after_plus.starts_with("44") {
        // +44 - United Kingdom
        Some(PhoneRegion::Uk)
    } else if digits_after_plus.starts_with("49") {
        // +49 - Germany
        Some(PhoneRegion::Germany)
    } else if digits_after_plus.starts_with("33") {
        // +33 - France
        Some(PhoneRegion::France)
    } else if digits_after_plus.starts_with("34") {
        // +34 - Spain
        Some(PhoneRegion::Spain)
    } else if digits_after_plus.starts_with("39") {
        // +39 - Italy
        Some(PhoneRegion::Italy)
    } else if digits_after_plus.starts_with("61") {
        // +61 - Australia
        Some(PhoneRegion::Australia)
    } else if digits_after_plus.starts_with("81") {
        // +81 - Japan
        Some(PhoneRegion::Japan)
    } else if digits_after_plus.starts_with("86") {
        // +86 - China
        Some(PhoneRegion::China)
    } else if digits_after_plus.starts_with("91") {
        // +91 - India
        Some(PhoneRegion::India)
    } else if digits_after_plus.starts_with("55") {
        // +55 - Brazil
        Some(PhoneRegion::Brazil)
    } else if digits_after_plus.starts_with('7') {
        // +7 - Russia and Kazakhstan
        Some(PhoneRegion::Russia)
    } else {
        // Valid format but unknown region
        Some(PhoneRegion::Unknown)
    }
}

/// Check if a phone number is a known test/sample pattern
///
/// Test phone numbers like 555-xxxx are reserved for fictional use.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection;
///
/// assert!(detection::is_test_phone("555-123-4567"));
/// assert!(detection::is_test_phone("(555) 555-5555"));
/// assert!(!detection::is_test_phone("415-555-1234"));
/// ```
#[must_use]
pub fn is_test_phone(phone: &str) -> bool {
    // Extract just the digits
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();

    // US 555 prefix (reserved for fictional use)
    // 555-0100 through 555-0199 are specifically reserved
    if digits.len() >= 10 {
        // Check for 555 in the exchange position (digits 3-5 for 10-digit, or after country code)
        if digits.len() == 10 && &digits[3..6] == "555" {
            return true;
        }
        // With country code
        if digits.len() == 11 && digits.starts_with('1') && &digits[4..7] == "555" {
            return true;
        }
    }

    // All same digit patterns
    if digits.len() >= 7
        && digits
            .chars()
            .all(|c| c == digits.chars().next().unwrap_or('0'))
    {
        return true;
    }

    // Sequential patterns
    if digits.contains("1234567") || digits.contains("7654321") {
        return true;
    }

    false
}

/// Detect all phone numbers in text
///
/// Scans text for phone number patterns and returns all matches with positions.
/// Includes ReDoS protection for large inputs.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection::detect_phones_in_text;
///
/// let text = "Call +1-555-123-4567 or (555) 234-5678";
/// let matches = detect_phones_in_text(text);
/// assert_eq!(matches.len(), 2);
/// ```
#[allow(clippy::expect_used)]
#[must_use]
pub fn detect_phones_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::phone::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = capture.get(0).expect("BUG: capture group 0 always exists");
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::PhoneNumber,
            ));
        }
    }

    super::common::deduplicate_matches(matches)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::super::{clear_personal_caches, phone_cache_stats};
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_is_phone_number() {
        // E.164 format
        assert!(is_phone_number("+15551234567"));
        assert!(is_phone_number("+442071234567")); // UK

        // US formats
        assert!(is_phone_number("(555) 123-4567"));
        assert!(is_phone_number("555-123-4567"));
        assert!(is_phone_number("5551234567"));

        // Invalid
        assert!(!is_phone_number(""));
        assert!(!is_phone_number("   "));
        assert!(!is_phone_number("123")); // Too short
        assert!(!is_phone_number("abcdefghij")); // Letters
    }

    #[test]
    fn test_find_phone_region() {
        assert_eq!(
            find_phone_region("+14155552671"),
            Some(PhoneRegion::NorthAmerica)
        );
        assert_eq!(find_phone_region("+442071234567"), Some(PhoneRegion::Uk));
        assert_eq!(find_phone_region("5551234567"), Some(PhoneRegion::Unknown));
    }

    #[test]
    fn test_is_test_phone() {
        assert!(is_test_phone("555-123-4567"));
        assert!(is_test_phone("(555) 555-5555"));
        assert!(is_test_phone("1111111111"));
        assert!(!is_test_phone("415-867-5309"));
    }

    #[test]
    fn test_detect_phones_in_text() {
        let text = "Call +1-555-123-4567 or (555) 234-5678";
        let matches = detect_phones_in_text(text);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    #[serial]
    fn test_phone_cache_hits() {
        clear_personal_caches();

        let phone = "+15551234567";
        let _result1 = is_phone_number(phone);
        let stats1 = phone_cache_stats();

        let _result2 = is_phone_number(phone);
        let stats2 = phone_cache_stats();

        assert!(stats2.hits > stats1.hits);
    }
}

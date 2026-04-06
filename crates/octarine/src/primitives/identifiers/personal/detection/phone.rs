//! Phone number detection
//!
//! Pure detection functions for phone numbers including E.164 and US formats.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType, PhoneRegion};

use super::cache::PHONE_CACHE;

/// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 10_000;

// ============================================================================
// False Positive Filters
// ============================================================================

/// Check if a digit string is likely a false positive phone match
///
/// Rejects sequential numbers, repeated digits, date-like patterns, and
/// SSN-like patterns that are commonly misidentified as phone numbers.
fn is_likely_false_positive(digits: &str) -> bool {
    let len = digits.len();
    if len < 7 {
        return false;
    }

    // All same digit (e.g., 1111111111)
    if let Some(first) = digits.chars().next()
        && digits.chars().all(|c| c == first)
    {
        return true;
    }

    // Entire number is ascending/descending sequential (e.g., 1234567890, 9876543210)
    if is_fully_sequential(digits) {
        return true;
    }

    // Date-like: 8 digits matching MMDDYYYY or YYYYMMDD
    if len == 8 && is_date_like(digits) {
        return true;
    }

    // SSN-like: exactly 9 digits matching XXX-XX-XXXX pattern ranges
    if len == 9 && is_ssn_like(digits) {
        return true;
    }

    false
}

/// Check if the entire digit string is a sequential run (ascending or descending)
/// with wrapping allowed (e.g., "1234567890" wraps 9->0, "9876543210" wraps 1->0)
///
/// Only flags fully sequential numbers to avoid false-flagging legitimate phones
/// that happen to contain short sequential subsequences like "+15551234567".
fn is_fully_sequential(digits: &str) -> bool {
    if digits.len() < 7 {
        return false;
    }

    let bytes = digits.as_bytes();

    let all_ascending = bytes
        .windows(2)
        .all(|pair| match (pair.first(), pair.get(1)) {
            (Some(&a), Some(&b)) => {
                // Allow normal ascending or wrapping 9->0
                b == a.saturating_add(1) || (a == b'9' && b == b'0')
            }
            _ => false,
        });

    if all_ascending {
        return true;
    }

    bytes
        .windows(2)
        .all(|pair| match (pair.first(), pair.get(1)) {
            (Some(&a), Some(&b)) => {
                // Allow normal descending or wrapping 0->9
                a == b.saturating_add(1) || (a == b'0' && b == b'9')
            }
            _ => false,
        })
}

/// Check if 8-digit string looks like a date (MMDDYYYY or YYYYMMDD)
fn is_date_like(digits: &str) -> bool {
    if digits.len() != 8 {
        return false;
    }

    // Try MMDDYYYY
    if let (Some(mm), Some(dd), Some(yyyy)) = (
        digits.get(0..2).and_then(|s| s.parse::<u32>().ok()),
        digits.get(2..4).and_then(|s| s.parse::<u32>().ok()),
        digits.get(4..8).and_then(|s| s.parse::<u32>().ok()),
    ) && (1..=12).contains(&mm)
        && (1..=31).contains(&dd)
        && (1900..=2100).contains(&yyyy)
    {
        return true;
    }

    // Try YYYYMMDD
    if let (Some(yyyy), Some(mm), Some(dd)) = (
        digits.get(0..4).and_then(|s| s.parse::<u32>().ok()),
        digits.get(4..6).and_then(|s| s.parse::<u32>().ok()),
        digits.get(6..8).and_then(|s| s.parse::<u32>().ok()),
    ) && (1900..=2100).contains(&yyyy)
        && (1..=12).contains(&mm)
        && (1..=31).contains(&dd)
    {
        return true;
    }

    false
}

/// Check if 9-digit string looks like a US SSN (area 001-899, group 01-99, serial 0001-9999)
fn is_ssn_like(digits: &str) -> bool {
    if digits.len() != 9 {
        return false;
    }

    matches!(
        (
            digits.get(0..3).and_then(|s| s.parse::<u32>().ok()),
            digits.get(3..5).and_then(|s| s.parse::<u32>().ok()),
            digits.get(5..9).and_then(|s| s.parse::<u32>().ok()),
        ),
        (Some(area), Some(group), Some(serial))
            if (1..=899).contains(&area)
                && area != 666
                && (1..=99).contains(&group)
                && (1..=9999).contains(&serial)
    )
}

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
            let matched_text = full_match.as_str();

            // Extract digits and filter false positives
            let digits: String = matched_text
                .chars()
                .filter(|c| c.is_ascii_digit())
                .collect();
            if digits.len() < 7 || is_likely_false_positive(&digits) {
                continue;
            }

            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                matched_text.to_string(),
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

    // ── International format tests ─────────────────────────────────────

    #[test]
    fn test_is_phone_international_formats() {
        // UK
        assert!(is_phone_number("+447911123456"));
        assert!(is_phone_number("+442071234567"));

        // Germany
        assert!(is_phone_number("+493012345678"));
        assert!(is_phone_number("+4917012345678"));

        // France
        assert!(is_phone_number("+33123456789"));

        // Australia
        assert!(is_phone_number("+61412345678"));

        // India
        assert!(is_phone_number("+919876543210"));

        // Japan
        assert!(is_phone_number("+81312345678"));

        // Brazil
        assert!(is_phone_number("+5511987654321"));

        // China
        assert!(is_phone_number("+8613812345678"));
    }

    #[test]
    fn test_detect_international_phones_in_text() {
        let text = "UK: +44 7911 123456, DE: +49 30 12345678, FR: +33 1 23 45 67 89";
        let matches = detect_phones_in_text(text);
        assert!(
            matches.len() >= 3,
            "expected at least 3 matches, got {}",
            matches.len()
        );

        // Verify UK number was found
        assert!(
            matches.iter().any(|m| m.matched_text.contains("44")),
            "UK number not found in matches: {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detect_e164_in_text() {
        let text = "Contact +5511987654321 for Brazil or +8613812345678 for China";
        let matches = detect_phones_in_text(text);
        assert!(
            matches.len() >= 2,
            "expected at least 2 E.164 matches, got {}",
            matches.len()
        );
    }

    // ── False positive filter tests ────────────────────────────────────

    #[test]
    fn test_text_false_positive_sequential() {
        // Sequential numbers in text should not be detected as phones
        let text = "Order 1234567890 confirmed. Ref: 9876543210";
        let matches = detect_phones_in_text(text);
        assert!(
            matches.is_empty(),
            "sequential numbers should not match as phones: {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_text_false_positive_repeated() {
        let text = "Code: 1111111111 or 5555555555";
        let matches = detect_phones_in_text(text);
        assert!(
            matches.is_empty(),
            "repeated digits should not match as phones: {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_text_false_positive_date_like() {
        // MMDDYYYY and YYYYMMDD formats should not be detected as phones
        let text = "Date: 01152023 or 20230115";
        let matches = detect_phones_in_text(text);
        assert!(
            matches.is_empty(),
            "date-like numbers should not match as phones: {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_text_false_positive_ssn_like() {
        // 9-digit SSN-like numbers should not be detected as phones
        let text = "SSN: 219099999";
        let matches = detect_phones_in_text(text);
        assert!(
            matches.is_empty(),
            "SSN-like numbers should not match as phones: {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_legitimate_phones_in_text() {
        // These should still be detected in text
        let text = "Call +14155552671 or +442071234567 or +919876543210";
        let matches = detect_phones_in_text(text);
        assert!(
            matches.len() >= 3,
            "legitimate phones should be detected, got {}",
            matches.len()
        );
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

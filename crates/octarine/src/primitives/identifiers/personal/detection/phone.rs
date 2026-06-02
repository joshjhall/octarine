//! Phone number detection
//!
//! Phone number detection backed by the `phonenumber` crate (the Rust port of
//! Google's libphonenumber). Validity, region, and possible-length checks come
//! from libphonenumber's bundled per-region metadata rather than hand-rolled
//! regexes, which drives false positives on arbitrary digit strings (order
//! numbers, IDs, hashes) to near-zero and adds full international coverage.
//!
//! In-text scanning keeps a loose candidate regex (libphonenumber has no text
//! matcher) and validates each candidate, so only genuinely-valid numbers are
//! reported.

use phonenumber::country;

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType, PhoneRegion};

use super::cache::PHONE_CACHE;

/// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 10_000;

/// Default region for numbers without an explicit `+` country code.
///
/// Bare numbers like `4158675309` are interpreted as US numbers (matching the
/// `+1` default used elsewhere, e.g. `normalize_phone_e164`).
const DEFAULT_REGION: country::Id = country::US;

/// Parse and validate a single phone string with libphonenumber.
///
/// Numbers already carrying an explicit `+` country code are parsed with **no**
/// default region — passing one (e.g. `US`) makes libphonenumber wrongly reject
/// otherwise-valid international numbers such as `+33142685300`. Numbers without
/// a `+` fall back to the [`DEFAULT_REGION`] so bare US numbers still validate.
fn parse_and_validate(value: &str) -> bool {
    let region = if value.trim_start().starts_with('+') {
        None
    } else {
        Some(DEFAULT_REGION)
    };

    phonenumber::parse(region, value)
        .map(|number| phonenumber::is_valid(&number))
        .unwrap_or(false)
}

// ============================================================================
// Public API
// ============================================================================

/// Check if value is a valid phone number (cached)
///
/// Validates phone numbers using libphonenumber. Numbers may be in E.164 form
/// (`+14155552671`), national form with separators (`(415) 867-5309`,
/// `415-867-5309`), or bare digits. Numbers without a `+` country code are
/// interpreted using the US default region.
///
/// Validity reflects real numbering plans: invalid carrier prefixes (e.g. the
/// US `555` exchange) and impossible lengths (e.g. `+44 1`) are rejected.
pub fn is_phone_number(value: &str) -> bool {
    let trimmed = value.trim();

    // Check cache first
    if let Some(result) = PHONE_CACHE.get(&trimmed.to_string()) {
        return result;
    }

    let result = parse_and_validate(trimmed);

    // Cache the result
    PHONE_CACHE.insert(trimmed.to_string(), result);

    result
}

/// Find phone number region from the phone string
///
/// Determines the region from the parsed country calling code. Requires an
/// explicit `+` country code for an accurate result; numbers without one (or
/// that fail to parse) return [`PhoneRegion::Unknown`].
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection;
/// use crate::primitives::identifiers::PhoneRegion;
///
/// assert_eq!(detection::find_phone_region("+14155552671"), Some(PhoneRegion::NorthAmerica));
/// assert_eq!(detection::find_phone_region("+442071234567"), Some(PhoneRegion::Uk));
/// assert_eq!(detection::find_phone_region("5551234567"), Some(PhoneRegion::Unknown)); // No country code
/// ```
pub fn find_phone_region(phone: &str) -> Option<PhoneRegion> {
    // Parse with no default region so numbers lacking a `+` country code do not
    // get silently attributed to the US — they should resolve to Unknown.
    let Ok(number) = phonenumber::parse(None, phone.trim()) else {
        return Some(PhoneRegion::Unknown);
    };

    let code = number.code().value();
    let iso = number.country().id().map(|id| id.as_ref().to_string());
    Some(PhoneRegion::from_country(code, iso.as_deref()))
}

/// Check if a phone number is a known test/sample pattern
///
/// Test phone numbers like 555-xxxx are reserved for fictional use. This is a
/// pure digit-pattern heuristic independent of whether the number is a valid
/// dialable number — libphonenumber rejects most of these as invalid, so this
/// remains the way to recognise test data.
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
        if digits.len() == 10 && digits.get(3..6) == Some("555") {
            return true;
        }
        // With country code
        if digits.len() == 11 && digits.starts_with('1') && digits.get(4..7) == Some("555") {
            return true;
        }
    }

    // All same digit patterns
    if digits.len() >= 7
        && let Some(first) = digits.chars().next()
        && digits.chars().all(|c| c == first)
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
/// Scans text for candidate phone numbers with a loose regex, then validates
/// each candidate with libphonenumber so only genuinely-valid numbers are
/// returned. Includes ReDoS protection for large inputs.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::personal::detection::detect_phones_in_text;
///
/// let text = "Call +1 415 867 5309 or (212) 555-0100";
/// let matches = detect_phones_in_text(text);
/// assert_eq!(matches.len(), 2);
/// ```
#[must_use]
pub fn detect_phones_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for candidate in patterns::phone::CANDIDATE.find_iter(text) {
        let matched_text = candidate.as_str();

        // Validate the candidate with libphonenumber; only keep real numbers.
        if !parse_and_validate(matched_text) {
            continue;
        }

        matches.push(IdentifierMatch::high_confidence(
            candidate.start(),
            candidate.end(),
            matched_text.to_string(),
            IdentifierType::PhoneNumber,
        ));
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
        assert!(is_phone_number("+14155552671"));
        assert!(is_phone_number("+442071234567")); // UK

        // US national formats (genuinely-valid numbers)
        assert!(is_phone_number("(415) 867-5309"));
        assert!(is_phone_number("415-867-5309"));
        assert!(is_phone_number("4158675309"));

        // Invalid
        assert!(!is_phone_number(""));
        assert!(!is_phone_number("   "));
        assert!(!is_phone_number("123")); // Too short
        assert!(!is_phone_number("abcdefghij")); // Letters

        // libphonenumber rejects the reserved US 555 exchange and invalid
        // carrier prefixes that the old regex accepted.
        assert!(!is_phone_number("+15551234567"));
        assert!(!is_phone_number("555-123-4567"));
        assert!(!is_phone_number("+1 555 023 4567")); // invalid US carrier
        assert!(!is_phone_number("+44 1")); // too short for UK
    }

    #[test]
    fn test_is_phone_number_new_regions() {
        // Regions added by the libphonenumber migration (issue #430).
        assert!(is_phone_number("+972502111111")); // Israel mobile
        assert!(is_phone_number("+82 10 1234 5678")); // South Korea mobile
        assert!(is_phone_number("+52 55 1234 5678")); // Mexico City
        assert!(is_phone_number("+90 212 345 6789")); // Turkey
    }

    #[test]
    fn test_find_phone_region() {
        assert_eq!(
            find_phone_region("+14155552671"),
            Some(PhoneRegion::NorthAmerica)
        );
        assert_eq!(find_phone_region("+442071234567"), Some(PhoneRegion::Uk));
        // No country code → Unknown (bare numbers are not attributed to US here)
        assert_eq!(find_phone_region("4158675309"), Some(PhoneRegion::Unknown));
    }

    #[test]
    fn test_find_phone_region_new_regions() {
        assert_eq!(
            find_phone_region("+972502111111"),
            Some(PhoneRegion::Israel)
        );
        assert_eq!(
            find_phone_region("+82 10 1234 5678"),
            Some(PhoneRegion::SouthKorea)
        );
        assert_eq!(
            find_phone_region("+52 55 1234 5678"),
            Some(PhoneRegion::Mexico)
        );
        assert_eq!(
            find_phone_region("+90 212 345 6789"),
            Some(PhoneRegion::Turkey)
        );
    }

    #[test]
    fn test_is_test_phone() {
        assert!(is_test_phone("555-123-4567"));
        assert!(is_test_phone("(555) 555-5555"));
        assert!(is_test_phone("1111111111"));
        assert!(is_test_phone("(212) 555-0100")); // reserved fictional range
        assert!(!is_test_phone("415-867-5309"));
    }

    #[test]
    fn test_detect_phones_in_text() {
        let text = "Call +1 415 867 5309 or (212) 234-5678";
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
        assert!(is_phone_number("+33142685300"));

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
        let text = "UK: +44 7911 123456, DE: +49 30 12345678, IN: +91 98765 43210";
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
    //
    // libphonenumber's possible-length and carrier-prefix tables reject these
    // non-phone digit strings without the bespoke heuristics the old
    // implementation needed.

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

        let phone = "+14155552671";
        let _result1 = is_phone_number(phone);
        let stats1 = phone_cache_stats();

        let _result2 = is_phone_number(phone);
        let stats2 = phone_cache_stats();

        assert!(stats2.hits > stats1.hits);
    }
}

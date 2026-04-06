//! Credit card detection and validation
//!
//! Pure detection functions for credit cards including:
//! - Luhn checksum validation
//! - BIN (Bank Identification Number) validation
//! - Card brand detection
//! - Test card pattern detection
//!
//! # Supported Card Brands
//!
//! - **Visa**: 13, 16, or 19 digits starting with 4
//! - **MasterCard**: 16 digits, 51-55 or 2221-2720 prefix
//! - **American Express**: 15 digits, 34 or 37 prefix
//! - **Discover**: 16 digits, 6011, 644-649, or 65 prefix
//! - **Diners Club**: 14 digits, 300-305, 36, or 38 prefix
//! - **JCB**: 16 digits, 3528-3589 prefix

use super::super::super::common::{luhn, patterns};
use super::super::super::types::{
    CreditCardType, DetectionConfidence, DetectionResult, IdentifierMatch, IdentifierType,
};
use once_cell::sync::Lazy;
use std::collections::HashMap;

use super::cache::LUHN_CACHE;

// ============================================================================
// Constants
// ============================================================================

/// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 10_000;

// ============================================================================
// Test Card Patterns
// ============================================================================

/// Known test card numbers (should not trigger alerts)
static TEST_CARDS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("4111111111111111", "Visa Test");
    m.insert("5555555555554444", "MasterCard Test");
    m.insert("340000000000009", "Amex Test");
    m.insert("6011000000000004", "Discover Test");
    m.insert("4242424242424242", "Stripe Test");
    m.insert("4000000000000002", "Stripe Declined Test");
    m
});

// ============================================================================
// BIN Range Definitions
// ============================================================================

/// BIN ranges for major card brands (first 6 digits)
static CARD_BIN_RANGES: Lazy<Vec<(CreditCardType, Vec<BinRange>)>> = Lazy::new(|| {
    vec![
        (CreditCardType::Visa, vec![BinRange::Single(4)]),
        (
            CreditCardType::Mastercard,
            vec![BinRange::Range(51, 55), BinRange::Range(2221, 2720)],
        ),
        (
            CreditCardType::AmericanExpress,
            vec![BinRange::Exact(34), BinRange::Exact(37)],
        ),
        (
            CreditCardType::Discover,
            vec![
                BinRange::Exact(6011),
                BinRange::Range(644, 649),
                BinRange::Exact(65),
            ],
        ),
        (
            CreditCardType::DinersClub,
            vec![
                BinRange::Range(300, 305),
                BinRange::Exact(36),
                BinRange::Exact(38),
            ],
        ),
        (CreditCardType::Jcb, vec![BinRange::Range(3528, 3589)]),
        // Verve must come before UnionPay/Discover (6-digit BINs are more specific)
        (
            CreditCardType::Verve,
            vec![
                BinRange::Range(506099, 506198),
                BinRange::Range(650002, 650027),
            ],
        ),
        (CreditCardType::UnionPay, vec![BinRange::Exact(62)]),
        (
            CreditCardType::Maestro,
            vec![
                BinRange::Exact(5018),
                BinRange::Exact(5020),
                BinRange::Exact(5038),
                BinRange::Exact(5893),
                BinRange::Exact(6304),
                BinRange::Exact(6759),
                BinRange::Range(6761, 6763),
            ],
        ),
        // RuPay last — overlaps with Discover (60/65) and UnionPay (81/82)
        (
            CreditCardType::RuPay,
            vec![
                BinRange::Exact(60),
                BinRange::Exact(82),
                BinRange::Exact(508),
            ],
        ),
    ]
});

#[derive(Debug)]
enum BinRange {
    Single(u32),
    Exact(u32),
    Range(u32, u32),
}

impl BinRange {
    fn matches(&self, prefix: u32, length: usize) -> bool {
        match self {
            BinRange::Single(n) => {
                let divisor = 10_u32.pow(length.saturating_sub(1) as u32);
                prefix.checked_div(divisor).unwrap_or(0) == *n
            }
            BinRange::Exact(n) => prefix == *n,
            BinRange::Range(start, end) => prefix >= *start && prefix <= *end,
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Check if credit card number is a known test/sample pattern
///
/// Detects common test card numbers used by payment processors:
/// - Stripe test cards (4242424242424242, 4000000000000002)
/// - Generic test cards (4111111111111111, 5555555555554444)
/// - Processor-specific test cards
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::financial::detection;
///
/// assert!(detection::is_test_credit_card("4242424242424242"));
/// assert!(detection::is_test_credit_card("4111-1111-1111-1111"));
/// assert!(!detection::is_test_credit_card("4532015112830366"));
/// ```
#[must_use]
pub fn is_test_credit_card(card: &str) -> bool {
    let digits_only: String = card.chars().filter(|c| c.is_ascii_digit()).collect();
    is_test_card(&digits_only)
}

/// Check if value is a credit card
#[must_use]
pub fn is_credit_card(value: &str) -> bool {
    if let Some(result) = detect_credit_card_with_context(value, None) {
        result.confidence != DetectionConfidence::Low
    } else {
        false
    }
}

/// Check if text matches credit card pattern (simpler pattern-based check)
///
/// This is a lightweight check that validates:
/// - Digits only (after filtering)
/// - Length between 13-19 digits
/// - Valid Luhn checksum
///
/// Use this for basic pattern matching. For more sophisticated detection with
/// context awareness, use `is_credit_card()` instead.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::detection;
///
/// assert!(detection::is_credit_card_pattern("4111111111111111"));
/// assert!(detection::is_credit_card_pattern("4111 1111 1111 1111"));
/// assert!(!detection::is_credit_card_pattern("4111111111111112")); // Invalid Luhn
/// assert!(!detection::is_credit_card_pattern("123456789012")); // Too short
/// ```
#[must_use]
pub fn is_credit_card_pattern(text: &str) -> bool {
    let digits: String = text.chars().filter(|c| c.is_numeric()).collect();
    digits.len() >= 13 && digits.len() <= 19 && luhn::is_valid(&digits)
}

/// Enhanced credit card detection with multiple validation layers
///
/// Performs sophisticated credit card detection using an 8-stage validation pipeline
/// that combines pattern matching, cryptographic checksums, BIN validation, context
/// analysis, and entropy checking. Returns a confidence-scored result.
///
/// # Arguments
///
/// * `value` - The string to check for credit card patterns (can include spaces/dashes)
/// * `context` - Optional surrounding text for context analysis (e.g., field labels)
///
/// # Returns
///
/// * `Some(DetectionResult)` with confidence level, or `None` if insufficient evidence
#[must_use]
pub fn detect_credit_card_with_context(
    value: &str,
    context: Option<&str>,
) -> Option<DetectionResult> {
    let mut confidence_score = 0.0;

    // Clean the input
    let digits_only = value
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>();

    // Step 1: Basic length check (required)
    if digits_only.len() < 13 || digits_only.len() > 19 {
        return None;
    }

    // Step 2: Pattern matching (low confidence)
    if patterns::credit_card::DIGITS_ONLY.is_match(&digits_only)
        || patterns::credit_card::FORMATTED_VALIDATION.is_match(value)
    {
        confidence_score += 0.2;
    }

    // Step 3: Luhn algorithm validation (medium confidence)
    if is_luhn_checksum_valid(&digits_only) {
        confidence_score += 0.3;
    } else {
        // Invalid Luhn is a strong negative signal
        confidence_score -= 0.5;
    }

    // Step 4: BIN validation (medium confidence)
    if let Some(brand) = validate_bin(&digits_only) {
        confidence_score += 0.2;

        // Check expected length for brand
        if is_length_valid_for_brand(&digits_only, brand) {
            confidence_score += 0.1;
        }
    }

    // Step 5: Check if it's a known test card (negative signal)
    if is_test_card(&digits_only) {
        confidence_score -= 0.3;
    }

    // Step 6: Context analysis (high confidence boost)
    if let Some(ctx) = context
        && patterns::credit_card::CONTEXT_KEYWORDS.is_match(ctx)
    {
        confidence_score += 0.2;
    }

    // Step 7: Entropy check (cards shouldn't be sequential)
    if !is_suspicious_pattern_present(&digits_only) {
        confidence_score += 0.1;
    } else {
        confidence_score -= 0.2;
    }

    // Determine final confidence level
    let confidence = if confidence_score >= 0.7 {
        DetectionConfidence::High
    } else if confidence_score >= 0.4 {
        DetectionConfidence::Medium
    } else if confidence_score >= 0.2 {
        DetectionConfidence::Low
    } else {
        return None; // Too low confidence to report
    };

    Some(DetectionResult {
        identifier_type: IdentifierType::CreditCard,
        confidence,
        is_sensitive: true,
    })
}

/// Detect credit card brand from card number
///
/// Returns the detected card type (Visa, Mastercard, etc.) based on BIN analysis.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::detection;
/// use crate::primitives::identifiers::types::CreditCardType;
///
/// let brand = detection::detect_card_brand("4111111111111111");
/// assert_eq!(brand, Some(CreditCardType::Visa));
///
/// let brand = detection::detect_card_brand("5555555555554444");
/// assert_eq!(brand, Some(CreditCardType::Mastercard));
/// ```
#[must_use]
pub fn detect_card_brand(card_number: &str) -> Option<CreditCardType> {
    let digits_only = card_number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>();

    validate_bin(&digits_only)
}

/// Check if value is likely a credit card (less strict, for filtering)
#[must_use]
pub fn is_credit_card_likely(value: &str) -> bool {
    let digits_only = value
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>();

    // Basic length check and pattern
    digits_only.len() >= 13
        && digits_only.len() <= 19
        && !is_suspicious_pattern_present(&digits_only)
}

/// Detect all credit card numbers in text
///
/// Scans text for credit card patterns and returns all matches with positions.
/// Validates each match using Luhn checksum.
/// Includes ReDoS protection for large inputs.
#[must_use]
pub fn detect_credit_cards_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::credit_card::all() {
        for capture in pattern.captures_iter(text) {
            if let Some(full_match) = capture.get(0) {
                let matched_text = full_match.as_str();

                // Validate using Luhn checksum
                let digits_only = matched_text
                    .chars()
                    .filter(|c| c.is_ascii_digit())
                    .collect::<String>();

                if digits_only.len() >= 13
                    && digits_only.len() <= 19
                    && is_luhn_checksum_valid(&digits_only)
                    && !is_isbn13_pattern(&digits_only)
                {
                    matches.push(IdentifierMatch::high_confidence(
                        full_match.start(),
                        full_match.end(),
                        matched_text.to_string(),
                        IdentifierType::CreditCard,
                    ));
                }
            }
        }
    }

    super::common::deduplicate_matches(matches)
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Check if Luhn checksum is valid (with caching)
pub(super) fn is_luhn_checksum_valid(number: &str) -> bool {
    // Check cache first
    if let Some(result) = LUHN_CACHE.get(&number.to_string()) {
        return result;
    }

    // Compute fresh - credit cards must be at least 13 digits
    let result = luhn::is_valid_with_min_length(number, 13);

    // Cache the result
    LUHN_CACHE.insert(number.to_string(), result);

    result
}

/// Validate BIN (Bank Identification Number) and return card brand
fn validate_bin(card_number: &str) -> Option<CreditCardType> {
    if card_number.len() < 6 {
        return None;
    }

    // Check different prefix lengths
    for (brand, ranges) in CARD_BIN_RANGES.iter() {
        for range in ranges {
            // Try different prefix lengths (1-6 digits for Verve 6-digit BINs)
            for len in 1..=6 {
                if card_number.len() >= len
                    && let Ok(prefix) = card_number[..len].parse::<u32>()
                    && range.matches(prefix, len)
                {
                    return Some(*brand);
                }
            }
        }
    }

    None
}

/// Check if length is valid for card brand
fn is_length_valid_for_brand(card_number: &str, brand: CreditCardType) -> bool {
    let len = card_number.len();

    match brand {
        CreditCardType::Visa => len == 13 || len == 16 || len == 19,
        CreditCardType::Mastercard => len == 16,
        CreditCardType::AmericanExpress => len == 15,
        CreditCardType::Discover => len == 16,
        CreditCardType::DinersClub => len == 14,
        CreditCardType::Jcb => len == 16,
        CreditCardType::UnionPay => (16..=19).contains(&len),
        CreditCardType::Maestro => (12..=19).contains(&len),
        CreditCardType::Verve => (16..=19).contains(&len),
        CreditCardType::RuPay => len == 16,
        CreditCardType::Unknown => true, // Unknown brand, can't validate
    }
}

/// Check if the card number is a known test card
fn is_test_card(card_number: &str) -> bool {
    TEST_CARDS.contains_key(card_number)
}

/// Check if a digit string looks like an ISBN-13 (starts with 978 or 979, 13 digits)
fn is_isbn13_pattern(digits: &str) -> bool {
    digits.len() == 13 && (digits.starts_with("978") || digits.starts_with("979"))
}

/// Check if suspicious patterns are present (sequential, repeated digits)
pub(super) fn is_suspicious_pattern_present(number: &str) -> bool {
    // Check for sequential digits
    let mut sequential_count: u32 = 0;
    let digits: Vec<char> = number.chars().collect();

    for i in 1..digits.len() {
        let prev_idx = i.saturating_sub(1);
        if let (Some(&prev_char), Some(&curr_char)) = (digits.get(prev_idx), digits.get(i))
            && let (Some(prev), Some(curr)) = (prev_char.to_digit(10), curr_char.to_digit(10))
        {
            if curr == prev.saturating_add(1) || curr == prev {
                sequential_count = sequential_count.saturating_add(1);
                if sequential_count > 4 {
                    return true; // Too many sequential/repeated digits
                }
            } else {
                sequential_count = 0;
            }
        }
    }

    // Check if all digits are the same
    if let Some(&first_digit) = digits.first()
        && digits.iter().all(|&d| d == first_digit)
    {
        return true;
    }

    // Check for patterns like 1234567890123456
    let pattern = "01234567890";
    if number.contains(pattern) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::super::{clear_financial_caches, luhn_cache_stats};
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_credit_card_detection() {
        // Valid card with high confidence
        let result = detect_credit_card_with_context(
            "4242424242424242",
            Some("Enter your credit card number"),
        );
        match result {
            Some(r) => assert_eq!(r.confidence, DetectionConfidence::High),
            None => panic!("Expected credit card to be detected with high confidence"),
        }

        // Test card should have lower confidence
        let result = detect_credit_card_with_context("4111111111111111", None);
        assert!(result.is_some());

        // Invalid Luhn should fail or have very low confidence
        let result = detect_credit_card_with_context("4532015112830367", None);
        if let Some(r) = result {
            assert_eq!(r.confidence, DetectionConfidence::Low);
        }
    }

    #[test]
    fn test_is_credit_card() {
        assert!(is_credit_card("4242424242424242")); // Stripe test card
        assert!(!is_credit_card("1234567890")); // Too short
        assert!(!is_credit_card("not a card"));
    }

    #[test]
    fn test_is_credit_card_pattern() {
        // Valid cards (Luhn valid, correct length)
        assert!(is_credit_card_pattern("4111111111111111"));
        assert!(is_credit_card_pattern("4111 1111 1111 1111"));

        // Invalid Luhn checksum
        assert!(!is_credit_card_pattern("4111111111111112"));

        // Too short (12 digits)
        assert!(!is_credit_card_pattern("123456789012"));

        // Empty string
        assert!(!is_credit_card_pattern(""));
    }

    #[test]
    fn test_suspicious_patterns() {
        assert!(is_suspicious_pattern_present("1234567890123456"));
        assert!(is_suspicious_pattern_present("1111111111111111"));
        assert!(!is_suspicious_pattern_present("4242424242424242"));
    }

    #[test]
    fn test_card_brand_detection() {
        assert_eq!(
            detect_card_brand("4242424242424242"),
            Some(CreditCardType::Visa)
        );
        assert_eq!(
            detect_card_brand("5555555555554444"),
            Some(CreditCardType::Mastercard)
        );
        assert_eq!(
            detect_card_brand("340000000000009"),
            Some(CreditCardType::AmericanExpress)
        );
    }

    #[test]
    fn test_detect_credit_cards_in_text() {
        let text = "Cards: 4242-4242-4242-4242 and 5555-5555-5555-4444";
        let matches = detect_credit_cards_in_text(text);
        assert!(!matches.is_empty());
        let first = matches.first().expect("Should detect credit card patterns");
        assert_eq!(first.identifier_type, IdentifierType::CreditCard);
    }

    #[test]
    fn test_detect_credit_cards_no_matches() {
        let text = "No credit cards here just text";
        let matches = detect_credit_cards_in_text(text);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_detect_credit_cards_invalid_luhn() {
        let text = "Invalid: 4532015112830367";
        let matches = detect_credit_cards_in_text(text);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_formatted_credit_cards() {
        let result = detect_credit_card_with_context("4242 4242 4242 4242", None);
        assert!(result.is_some());

        let result = detect_credit_card_with_context("4242-4242-4242-4242", None);
        assert!(result.is_some());
    }

    #[test]
    fn test_credit_card_edge_cases() {
        assert!(!is_credit_card("123456789012")); // 12 digits - too short
        assert!(!is_credit_card_likely("123456789012")); // 12 digits - too short
        assert!(!is_credit_card_likely("1234567890123456789")); // Sequential = suspicious
        assert!(!is_credit_card_likely("12345678901234567890")); // 20 digits - too long
        assert!(is_credit_card_likely("4242424242424242")); // Valid pattern
    }

    #[test]
    fn test_empty_input() {
        assert!(!is_credit_card(""));
        assert_eq!(detect_credit_cards_in_text("").len(), 0);
    }

    // ── New card brand tests ────────────────────────────────────────

    #[test]
    fn test_detect_unionpay_brand() {
        assert_eq!(
            detect_card_brand("6200000000000005"),
            Some(CreditCardType::UnionPay)
        );
    }

    #[test]
    fn test_detect_maestro_brand() {
        assert_eq!(
            detect_card_brand("5018000000000009"),
            Some(CreditCardType::Maestro)
        );
        assert_eq!(
            detect_card_brand("6304000000000000"),
            Some(CreditCardType::Maestro)
        );
    }

    #[test]
    fn test_detect_verve_brand() {
        assert_eq!(
            detect_card_brand("5060990000000008"),
            Some(CreditCardType::Verve)
        );
    }

    #[test]
    fn test_detect_rupay_brand() {
        assert_eq!(
            detect_card_brand("6000000000000007"),
            Some(CreditCardType::RuPay)
        );
        assert_eq!(
            detect_card_brand("5080000000000002"),
            Some(CreditCardType::RuPay)
        );
    }

    #[test]
    fn test_new_brands_valid_length() {
        // UnionPay: 16-19 digits
        assert!(is_length_valid_for_brand(
            "6200000000000005",
            CreditCardType::UnionPay
        ));
        // Maestro: 12-19 digits
        assert!(is_length_valid_for_brand(
            "5018000000000009",
            CreditCardType::Maestro
        ));
        // Verve: 16-19 digits
        assert!(is_length_valid_for_brand(
            "5060990000000008",
            CreditCardType::Verve
        ));
        // RuPay: 16 digits
        assert!(is_length_valid_for_brand(
            "6000000000000007",
            CreditCardType::RuPay
        ));
    }

    // ── ISBN-13 false positive filter tests ────────────────────────────

    #[test]
    fn test_isbn13_not_detected_as_credit_card() {
        // ISBN-13 with valid Luhn (978 prefix)
        let text = "Book ISBN: 9780306406156";
        let matches = detect_credit_cards_in_text(text);
        assert!(
            matches.is_empty(),
            "ISBN-13 should not be detected as credit card: {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_isbn13_979_not_detected() {
        let text = "ISBN: 9790000000007";
        let matches = detect_credit_cards_in_text(text);
        assert!(
            matches.is_empty(),
            "ISBN-13 (979) should not be detected as credit card: {:?}",
            matches.iter().map(|m| &m.matched_text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_real_cards_still_detected() {
        // Visa card should still be detected
        let text = "Pay with 4242 4242 4242 4242";
        let matches = detect_credit_cards_in_text(text);
        assert!(!matches.is_empty(), "real credit cards should still match");
    }

    #[test]
    #[serial]
    fn test_luhn_cache_hits() {
        clear_financial_caches();

        let card = "4242424242424242";

        // First call - cache miss
        let _result1 = is_credit_card(card);
        let stats1 = luhn_cache_stats();

        // Second call - cache hit
        let _result2 = is_credit_card(card);
        let stats2 = luhn_cache_stats();

        assert!(
            stats2.hits > stats1.hits,
            "Cache should have recorded a hit"
        );
    }
}

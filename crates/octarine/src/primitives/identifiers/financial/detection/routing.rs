//! ABA Routing Number detection and validation
//!
//! Pure detection functions for US routing numbers including:
//! - ABA checksum validation
//! - Federal Reserve district checking

use super::super::super::common::patterns;
use super::super::super::types::{
    DetectionConfidence, DetectionResult, IdentifierMatch, IdentifierType,
};

use super::cache::ABA_CACHE;

// ============================================================================
// Constants
// ============================================================================

/// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 10_000;

// ============================================================================
// Public API
// ============================================================================

/// Check if value is a routing number
#[must_use]
pub fn is_routing_number(value: &str) -> bool {
    detect_routing_number(value).is_some()
}

/// Detect routing number with ABA checksum validation
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::detection;
///
/// let result = detection::detect_routing_number("121000358");
/// assert!(result.is_some());
/// ```
#[must_use]
pub fn detect_routing_number(value: &str) -> Option<DetectionResult> {
    let trimmed = value.trim();

    // Must be exactly 9 digits
    if trimmed.len() != 9 || !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    // Use cached ABA checksum validation
    if !is_aba_checksum_valid(trimmed) {
        return None;
    }

    // Additional validation: First two digits indicate Federal Reserve district
    let digits: Vec<u32> = trimmed.chars().filter_map(|c| c.to_digit(10)).collect();
    let first_two = match (digits.first(), digits.get(1)) {
        (Some(&d0), Some(&d1)) => d0.saturating_mul(10).saturating_add(d1),
        _ => return None,
    };

    // Valid Federal Reserve routing number ranges
    let valid_ranges = [
        (1, 12),  // Federal Reserve Banks
        (21, 32), // Thrift institutions
        (61, 72), // Electronic transactions
        (80, 80), // Traveler's cheques
    ];

    let is_valid_range = valid_ranges
        .iter()
        .any(|&(start, end)| first_two >= start && first_two <= end);

    if is_valid_range {
        Some(DetectionResult {
            identifier_type: IdentifierType::RoutingNumber,
            confidence: DetectionConfidence::High,
            is_sensitive: true,
        })
    } else {
        None
    }
}

/// Find all routing numbers in text
///
/// Scans text for ABA routing numbers (9 digits).
/// Validates each match using the ABA checksum algorithm.
/// Includes ReDoS protection for large inputs.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::financial::detection;
///
/// let text = "Wire to routing 021000021 account 1234567890";
/// let matches = detection::detect_routing_numbers_in_text(text);
/// assert!(!matches.is_empty());
/// ```
#[must_use]
pub fn detect_routing_numbers_in_text(text: &str) -> Vec<IdentifierMatch> {
    // ReDoS protection
    if text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::routing_number::all() {
        for capture in pattern.captures_iter(text) {
            // Get the routing number digits (group 1 for labeled, group 0 for standalone)
            let routing_str = capture.get(1).or_else(|| capture.get(0));

            if let Some(routing_match) = routing_str {
                let routing_digits = routing_match.as_str();

                // Validate it's exactly 9 digits
                if routing_digits.len() == 9 && routing_digits.chars().all(|c| c.is_ascii_digit()) {
                    // Validate ABA checksum
                    if is_aba_checksum_valid(routing_digits) {
                        matches.push(IdentifierMatch::high_confidence(
                            routing_match.start(),
                            routing_match.end(),
                            routing_digits.to_string(),
                            IdentifierType::RoutingNumber,
                        ));
                    }
                }
            }
        }
    }

    super::common::deduplicate_matches(matches)
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Check if ABA routing number checksum is valid (with caching)
pub(super) fn is_aba_checksum_valid(routing: &str) -> bool {
    if routing.len() != 9 {
        return false;
    }

    // Check cache first
    if let Some(result) = ABA_CACHE.get(&routing.to_string()) {
        return result;
    }

    let digits: Vec<u32> = routing.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 9 {
        return false;
    }

    let [d0, d1, d2, d3, d4, d5, d6, d7, d8] = digits.as_slice() else {
        return false;
    };

    let checksum = (3_u32
        .saturating_mul(d0.saturating_add(*d3).saturating_add(*d6))
        .saturating_add(7_u32.saturating_mul(d1.saturating_add(*d4).saturating_add(*d7)))
        .saturating_add(d2.saturating_add(*d5).saturating_add(*d8)))
        % 10;

    let result = checksum == 0;

    // Cache the result
    ABA_CACHE.insert(routing.to_string(), result);

    result
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::super::{aba_cache_stats, clear_financial_caches};
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_routing_number_validation() {
        // Valid routing number
        let result = detect_routing_number("121000358");
        assert!(result.is_some());

        // Invalid checksum
        let result = detect_routing_number("000000001");
        assert!(result.is_none());
    }

    #[test]
    fn test_is_routing_number() {
        assert!(is_routing_number("121000358"));
        assert!(!is_routing_number("000000001"));
        assert!(!is_routing_number("12345")); // Too short
    }

    #[test]
    fn test_detect_routing_numbers_in_text() {
        let text = "Wire to routing 021000021 account 1234567890";
        let matches = detect_routing_numbers_in_text(text);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("Should detect routing number");
        assert_eq!(first.identifier_type, IdentifierType::RoutingNumber);
        assert_eq!(first.matched_text, "021000021");
    }

    #[test]
    fn test_detect_routing_numbers_multiple() {
        let text = "Routing: 021000021 and ABA: 011000015";
        let matches = detect_routing_numbers_in_text(text);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_detect_routing_numbers_no_matches() {
        let text = "No routing numbers here, just text 123456";
        let matches = detect_routing_numbers_in_text(text);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_detect_routing_numbers_invalid_checksum() {
        let text = "Invalid routing: 000000001";
        let matches = detect_routing_numbers_in_text(text);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_detect_routing_numbers_labeled() {
        let test_cases = [
            "Routing: 021000021",
            "ABA: 021000021",
            "RTN: 021000021",
            "routing number: 021000021",
        ];

        for text in &test_cases {
            let matches = detect_routing_numbers_in_text(text);
            assert_eq!(matches.len(), 1, "Should find routing number in: {}", text);
        }
    }

    #[test]
    fn test_empty_input() {
        assert!(!is_routing_number(""));
    }

    #[test]
    #[serial]
    fn test_aba_cache_hits() {
        clear_financial_caches();

        let routing = "021000021";

        // First call - cache miss
        let _result1 = is_routing_number(routing);
        let stats1 = aba_cache_stats();

        // Second call - cache hit
        let _result2 = is_routing_number(routing);
        let stats2 = aba_cache_stats();

        assert!(
            stats2.hits > stats1.hits,
            "Cache should have recorded a hit"
        );
    }
}

//! Common detection utilities and aggregate functions
//!
//! Provides shared helpers and functions that span multiple network identifier types.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};

use super::{
    api_keys::{is_api_key, is_jwt},
    domain::{is_domain, is_hostname, is_port},
    ip::is_ip_address,
    mac::is_mac_address,
    phone::is_phone_international,
    url::is_url,
    uuid::is_uuid,
};

// ============================================================================
// Constants for ReDoS Protection
// ============================================================================

/// Maximum text length for scanning operations (10KB)
pub(super) const MAX_INPUT_LENGTH: usize = 10_000;

/// Maximum identifier length for single-value checks
pub(super) const MAX_IDENTIFIER_LENGTH: usize = 1_000;

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if input exceeds safe length for regex processing
#[inline]
pub(super) fn exceeds_safe_length(input: &str, max_len: usize) -> bool {
    input.len() > max_len
}

/// Extract full match from capture group
#[allow(clippy::expect_used)]
pub(super) fn get_full_match<'a>(capture: &'a regex::Captures<'a>) -> regex::Match<'a> {
    capture
        .get(0)
        .expect("BUG: capture group 0 always exists per regex spec")
}

/// Deduplicate overlapping matches (keep longest/highest confidence)
pub(super) fn deduplicate_matches(mut matches: Vec<IdentifierMatch>) -> Vec<IdentifierMatch> {
    if matches.is_empty() {
        return matches;
    }

    // Sort by position, then length (descending), then confidence
    matches.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| b.len().cmp(&a.len()))
            .then_with(|| b.confidence.cmp(&a.confidence))
    });

    let mut deduped = Vec::new();
    let mut last_end = 0;

    for m in matches {
        if m.start >= last_end {
            last_end = m.end;
            deduped.push(m);
        }
    }

    deduped
}

// ============================================================================
// Aggregate Detection Functions
// ============================================================================

/// Check if value is any network identifier
#[must_use]
pub fn is_network_identifier(value: &str) -> bool {
    is_uuid(value)
        || is_ip_address(value)
        || is_mac_address(value)
        || is_url(value)
        || is_domain(value)
        || is_hostname(value)
        || is_port(value)
        || is_phone_international(value)
        || is_jwt(value)
        || is_api_key(value)
}

/// Check if text contains any network identifier
#[must_use]
pub fn is_network_present(text: &str) -> bool {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return false;
    }
    patterns::network::all().iter().any(|p| p.is_match(text))
}

/// Detect the type of network identifier
///
/// # Detection Order
/// Detection is ordered from most specific to least specific:
/// 1. UUID (strict format)
/// 2. MAC address (strict format)
/// 3. IP address (strict format)
/// 4. URL (includes protocol) - checked before domain
/// 5. API key (with prefixes)
/// 6. Domain (without protocol)
/// 7. Port (port number)
/// 8. Hostname (internal name) - most ambiguous, last
#[must_use]
pub fn detect_network_identifier(value: &str) -> Option<IdentifierType> {
    if is_uuid(value) {
        Some(IdentifierType::Uuid)
    } else if is_mac_address(value) {
        Some(IdentifierType::MacAddress)
    } else if is_ip_address(value) {
        Some(IdentifierType::IpAddress)
    } else if is_url(value) {
        // Check URL before domain since URLs contain domains
        Some(IdentifierType::Url)
    } else if is_api_key(value) {
        Some(IdentifierType::ApiKey)
    } else if is_domain(value) {
        Some(IdentifierType::Domain)
    } else if is_port(value) {
        Some(IdentifierType::Port)
    } else if is_hostname(value) {
        // Hostname is last because it's most ambiguous
        Some(IdentifierType::Hostname)
    } else {
        None
    }
}

/// Find all network identifiers in text
#[must_use]
pub fn find_all_network_in_text(text: &str) -> Vec<IdentifierMatch> {
    use super::{
        api_keys::find_api_keys_in_text, ip::find_ip_addresses_in_text,
        mac::find_mac_addresses_in_text, url::find_urls_in_text, uuid::find_uuids_in_text,
    };

    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut all_matches = Vec::new();
    all_matches.extend(find_uuids_in_text(text));
    all_matches.extend(find_ip_addresses_in_text(text));
    all_matches.extend(find_mac_addresses_in_text(text));
    all_matches.extend(find_urls_in_text(text));
    all_matches.extend(find_api_keys_in_text(text));

    deduplicate_matches(all_matches)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_is_network_identifier() {
        assert!(is_network_identifier(
            "550e8400-e29b-41d4-a716-446655440000"
        ));
        assert!(is_network_identifier("192.168.1.1"));
        assert!(is_network_identifier("https://example.com"));
        assert!(!is_network_identifier(""));
    }

    #[test]
    fn test_detect_network_identifier() {
        assert_eq!(
            detect_network_identifier("550e8400-e29b-41d4-a716-446655440000"),
            Some(IdentifierType::Uuid)
        );
        assert_eq!(
            detect_network_identifier("192.168.1.1"),
            Some(IdentifierType::IpAddress)
        );
        assert_eq!(
            detect_network_identifier("00:11:22:33:44:55"),
            Some(IdentifierType::MacAddress)
        );
        assert_eq!(
            detect_network_identifier("https://example.com"),
            Some(IdentifierType::Url)
        );
    }

    #[test]
    fn test_is_network_present() {
        assert!(is_network_present("Server IP is 192.168.1.1 on port 8080"));
        assert!(is_network_present(
            "UUID: 550e8400-e29b-41d4-a716-446655440000"
        ));
        assert!(!is_network_present("Just some plain text"));
    }

    #[test]
    fn test_find_all_network_in_text() {
        let text = "Server 192.168.1.1 with MAC 00:11:22:33:44:55";
        let matches = find_all_network_in_text(text);
        assert!(matches.len() >= 2);
    }
}

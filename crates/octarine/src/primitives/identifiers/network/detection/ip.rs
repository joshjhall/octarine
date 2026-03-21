//! IP address detection functions
//!
//! Detection for IPv4 and IPv6 addresses.

use super::super::super::common::patterns;
use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};

use super::common::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

// ============================================================================
// Single-Value Detection
// ============================================================================

/// Check if value is an IP address (IPv4 or IPv6)
#[must_use]
pub fn is_ip_address(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::IPV4.is_match(trimmed) || patterns::network::IPV6.is_match(trimmed)
}

/// Check if value is an IPv4 address
#[must_use]
pub fn is_ipv4(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::IPV4.is_match(trimmed)
}

/// Check if value is an IPv6 address
#[must_use]
pub fn is_ipv6(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::IPV6.is_match(trimmed)
}

// ============================================================================
// Text Scanning
// ============================================================================

/// Find all IP addresses in text
#[must_use]
pub fn find_ip_addresses_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for pattern in patterns::network::ips() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::IpAddress,
                DetectionConfidence::High,
            ));
        }
    }
    deduplicate_matches(matches)
}

// ============================================================================
// Test Data Detection
// ============================================================================

/// Check if IP address is a known test/development address
///
/// Detects:
/// - Loopback addresses (127.x.x.x, ::1)
/// - Private network ranges (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
/// - Link-local addresses (169.254.x.x, fe80::/10)
/// - Documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x)
/// - TEST-NET addresses from RFC 5737
/// - Example domains from RFC 2606
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::detection::is_test_ip;
///
/// assert!(is_test_ip("127.0.0.1"));      // Loopback
/// assert!(is_test_ip("192.168.1.1"));    // Private
/// assert!(is_test_ip("::1"));             // IPv6 loopback
/// assert!(!is_test_ip("8.8.8.8"));        // Public IP (Google DNS)
/// ```
#[must_use]
pub fn is_test_ip(ip: &str) -> bool {
    let trimmed = ip.trim();

    // IPv6 loopback
    if trimmed == "::1" || trimmed == "0:0:0:0:0:0:0:1" {
        return true;
    }

    // IPv6 link-local (fe80::/10)
    let lower = trimmed.to_lowercase();
    if lower.starts_with("fe80:") {
        return true;
    }

    // IPv6 unique local (fc00::/7)
    if lower.starts_with("fc") || lower.starts_with("fd") {
        return true;
    }

    // IPv4 parsing
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() != 4 {
        return false; // Not a standard IPv4
    }

    // Parse octets
    let octets: Vec<u8> = parts.iter().filter_map(|p| p.parse::<u8>().ok()).collect();

    // Destructure to avoid clippy indexing warnings (we know len == 4)
    let [o0, o1, o2, _o3] = match octets.as_slice() {
        [a, b, c, d] => [*a, *b, *c, *d],
        _ => return false,
    };

    // Loopback (127.0.0.0/8)
    if o0 == 127 {
        return true;
    }

    // Private networks (RFC 1918)
    // 10.0.0.0/8
    if o0 == 10 {
        return true;
    }
    // 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
    if o0 == 172 && (16..=31).contains(&o1) {
        return true;
    }
    // 192.168.0.0/16
    if o0 == 192 && o1 == 168 {
        return true;
    }

    // Link-local (169.254.0.0/16)
    if o0 == 169 && o1 == 254 {
        return true;
    }

    // Documentation/TEST-NET ranges (RFC 5737)
    // TEST-NET-1: 192.0.2.0/24
    if o0 == 192 && o1 == 0 && o2 == 2 {
        return true;
    }
    // TEST-NET-2: 198.51.100.0/24
    if o0 == 198 && o1 == 51 && o2 == 100 {
        return true;
    }
    // TEST-NET-3: 203.0.113.0/24
    if o0 == 203 && o1 == 0 && o2 == 113 {
        return true;
    }

    // Broadcast
    if octets.iter().all(|&o| o == 255) {
        return true;
    }

    // Null/unspecified
    if octets.iter().all(|&o| o == 0) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_is_ip_address() {
        // IPv4
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("8.8.8.8"));
        // IPv6
        assert!(is_ip_address("::1"));
        assert!(is_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        // Invalid
        assert!(!is_ip_address("not-an-ip"));
        assert!(!is_ip_address("256.1.1.1")); // out of range
    }

    #[test]
    fn test_is_ipv4() {
        assert!(is_ipv4("192.168.1.1"));
        assert!(is_ipv4("8.8.8.8"));
        assert!(!is_ipv4("::1"));
    }

    #[test]
    fn test_is_ipv6() {
        assert!(is_ipv6("::1"));
        assert!(is_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        assert!(!is_ipv6("192.168.1.1"));
    }

    #[test]
    fn test_find_ip_addresses_in_text() {
        let text = "Server at 192.168.1.1 and backup at 10.0.0.1";
        let matches = find_ip_addresses_in_text(text);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_is_test_ip() {
        // Loopback
        assert!(is_test_ip("127.0.0.1"));
        assert!(is_test_ip("127.255.255.255"));
        // Private
        assert!(is_test_ip("10.0.0.1"));
        assert!(is_test_ip("172.16.0.1"));
        assert!(is_test_ip("192.168.1.1"));
        // IPv6 loopback
        assert!(is_test_ip("::1"));
        // Link-local
        assert!(is_test_ip("169.254.1.1"));
        // Documentation
        assert!(is_test_ip("192.0.2.1"));
        assert!(is_test_ip("198.51.100.1"));
        assert!(is_test_ip("203.0.113.1"));
        // Broadcast
        assert!(is_test_ip("255.255.255.255"));
        // Null
        assert!(is_test_ip("0.0.0.0"));
        // Public - NOT test
        assert!(!is_test_ip("8.8.8.8"));
        assert!(!is_test_ip("1.1.1.1"));
    }
}

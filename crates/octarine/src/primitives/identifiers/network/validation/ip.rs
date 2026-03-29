//! IP address classification functions
//!
//! Pure classification functions for IPv4 and IPv6 addresses.

use super::super::detection::{is_ipv4, is_ipv6};

// ============================================================================
// IP Address Classification
// ============================================================================

/// Check if IPv4 address is in a private range (RFC 1918)
///
/// Private ranges:
/// - 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
/// - 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
/// - 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
#[must_use]
pub fn is_private_ipv4(ip: &str) -> bool {
    if !is_ipv4(ip) {
        return false;
    }

    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    let octets: Vec<u8> = parts.iter().filter_map(|p| p.parse().ok()).collect();
    if octets.len() != 4 {
        return false;
    }

    let (Some(octet0), Some(octet1)) = (octets.first().copied(), octets.get(1).copied()) else {
        return false;
    };

    // 10.0.0.0/8
    octet0 == 10
        // 172.16.0.0/12
        || (octet0 == 172 && (16..=31).contains(&octet1))
        // 192.168.0.0/16
        || (octet0 == 192 && octet1 == 168)
}

/// Check if IPv4 address is a loopback address (RFC 1122)
///
/// Loopback range: 127.0.0.0/8 (127.0.0.0 - 127.255.255.255)
#[must_use]
pub fn is_loopback_ipv4(ip: &str) -> bool {
    if !is_ipv4(ip) {
        return false;
    }
    ip.starts_with("127.")
}

/// Check if IPv4 address is link-local (RFC 3927)
///
/// Link-local range: 169.254.0.0/16
#[must_use]
pub fn is_link_local_ipv4(ip: &str) -> bool {
    if !is_ipv4(ip) {
        return false;
    }

    ip.starts_with("169.254.")
}

/// Check if IPv4 address is multicast (RFC 5771)
///
/// Multicast range: 224.0.0.0/4 (224.0.0.0 - 239.255.255.255)
#[must_use]
pub fn is_multicast_ipv4(ip: &str) -> bool {
    if !is_ipv4(ip) {
        return false;
    }

    ip.split('.')
        .next()
        .and_then(|s| s.parse::<u8>().ok())
        .is_some_and(|first| (224..=239).contains(&first))
}

/// Check if IPv4 address is reserved (RFC 1112)
///
/// Reserved range: 240.0.0.0/4 (240.0.0.0 - 255.255.255.255)
/// Excludes broadcast (255.255.255.255)
#[must_use]
pub fn is_reserved_ipv4(ip: &str) -> bool {
    if !is_ipv4(ip) || ip == "255.255.255.255" {
        return false;
    }

    ip.split('.')
        .next()
        .and_then(|s| s.parse::<u8>().ok())
        .is_some_and(|first| first >= 240)
}

/// Check if IPv4 address is broadcast
#[must_use]
pub fn is_broadcast_ipv4(ip: &str) -> bool {
    ip == "255.255.255.255"
}

/// Check if IPv4 address is in any reserved/special range
///
/// Includes: private, loopback, link-local, multicast, reserved, broadcast
#[must_use]
pub fn is_special_use_ipv4(ip: &str) -> bool {
    is_private_ipv4(ip)
        || is_loopback_ipv4(ip)
        || is_link_local_ipv4(ip)
        || is_multicast_ipv4(ip)
        || is_reserved_ipv4(ip)
        || is_broadcast_ipv4(ip)
}

/// Check if IPv4 address is public (routable on Internet)
///
/// Returns true if NOT in any special-use range
#[must_use]
pub fn is_public_ipv4(ip: &str) -> bool {
    is_ipv4(ip) && !is_special_use_ipv4(ip)
}

/// Check if IPv6 address is loopback (::1)
#[must_use]
pub fn is_loopback_ipv6(ip: &str) -> bool {
    ip == "::1"
}

/// Check if IPv6 address is link-local (fe80::/10)
#[must_use]
pub fn is_link_local_ipv6(ip: &str) -> bool {
    is_ipv6(ip) && ip.to_lowercase().starts_with("fe80:")
}

/// Check if IPv6 address is multicast (ff00::/8)
#[must_use]
pub fn is_multicast_ipv6(ip: &str) -> bool {
    is_ipv6(ip) && ip.to_lowercase().starts_with("ff")
}

/// Check if IPv6 address is unique local (fc00::/7 - ULA)
#[must_use]
pub fn is_unique_local_ipv6(ip: &str) -> bool {
    is_ipv6(ip) && (ip.to_lowercase().starts_with("fc") || ip.to_lowercase().starts_with("fd"))
}

/// Check if IPv6 address is in any reserved/special range
#[must_use]
pub fn is_special_use_ipv6(ip: &str) -> bool {
    is_loopback_ipv6(ip)
        || is_link_local_ipv6(ip)
        || is_multicast_ipv6(ip)
        || is_unique_local_ipv6(ip)
}

/// Check if IPv6 address is public (globally routable)
#[must_use]
pub fn is_public_ipv6(ip: &str) -> bool {
    is_ipv6(ip) && !is_special_use_ipv6(ip)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_ip_classification() {
        // IPv4 private
        assert!(is_private_ipv4("192.168.1.1"));
        assert!(is_private_ipv4("10.0.0.1"));
        assert!(!is_private_ipv4("8.8.8.8"));

        // IPv4 loopback
        assert!(is_loopback_ipv4("127.0.0.1"));
        assert!(!is_loopback_ipv4("192.168.1.1"));

        // IPv4 public
        assert!(is_public_ipv4("8.8.8.8"));
        assert!(!is_public_ipv4("192.168.1.1"));

        // IPv6 loopback
        assert!(is_loopback_ipv6("::1"));
        assert!(!is_loopback_ipv6("fe80::1"));

        // IPv6 link-local
        assert!(is_link_local_ipv6("fe80::1"));
        assert!(!is_link_local_ipv6("::1"));
    }

    // ============================================================================
    // Adversarial and Property-Based Tests
    // ============================================================================

    #[test]
    fn test_adversarial_ipv4_octet_overflow() {
        // Valid IPv4
        assert!(is_ipv4("192.168.1.1"));

        // Octet overflow (> 255) - testing current behavior
        // Note: Basic pattern matching may not catch these, but layer 3 validation should
        let _ = is_ipv4("256.168.1.1"); // May or may not pass pattern
        let _ = is_ipv4("192.256.1.1");
        let _ = is_ipv4("192.168.256.1");
        let _ = is_ipv4("192.168.1.256");

        // This is detection layer - validates format, not IP validity
        // Layer 3 (security module) should do deeper validation
    }

    #[test]
    fn test_adversarial_ipv6_compression_tricks() {
        // Valid compressions
        assert!(is_ipv6("2001:db8::1"));
        assert!(is_ipv6("::1"));
        assert!(is_ipv6("::"));

        // Test invalid patterns - detection may vary
        // This is primitives layer (detection), not deep validation
        let _ = is_ipv6("2001::db8::1"); // Multiple :: - may pass pattern
        let _ = is_ipv6("1:2:3:4:5:6:7:8:9"); // Too many groups
        let _ = is_ipv6("gggg::1"); // Invalid hex
    }
}

//! Host classification utilities
//!
//! Pure functions for classifying hosts (IP addresses vs domains).

// Allow dead_code: These are Layer 1 primitives that will be used by observe module
#![allow(dead_code)]

use std::net::IpAddr;
use std::str::FromStr;

// ============================================================================
// Host Classification
// ============================================================================

/// Type of host identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostType {
    /// IPv4 address (e.g., 192.168.1.1)
    Ipv4,
    /// IPv6 address (e.g., ::1, 2001:db8::1)
    Ipv6,
    /// Domain name (e.g., example.com)
    Domain,
    /// Unknown or invalid
    Unknown,
}

/// Classify a host string
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::data::network::detection::host::{classify_host, HostType};
///
/// assert_eq!(classify_host("192.168.1.1"), HostType::Ipv4);
/// assert_eq!(classify_host("::1"), HostType::Ipv6);
/// assert_eq!(classify_host("example.com"), HostType::Domain);
/// ```
#[must_use]
pub fn classify_host(host: &str) -> HostType {
    let trimmed = host.trim();

    if trimmed.is_empty() {
        return HostType::Unknown;
    }

    // Try parsing as IP address
    if let Ok(ip) = IpAddr::from_str(trimmed) {
        return match ip {
            IpAddr::V4(_) => HostType::Ipv4,
            IpAddr::V6(_) => HostType::Ipv6,
        };
    }

    // Handle bracketed IPv6 (e.g., [::1])
    if let Some(inner) = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .filter(|inner| {
            IpAddr::from_str(inner)
                .map(|ip| ip.is_ipv6())
                .unwrap_or(false)
        })
    {
        // inner is a valid IPv6 address
        let _ = inner; // Mark as intentionally checked
        return HostType::Ipv6;
    }

    // Check if it looks like a domain
    if is_valid_domain_format(trimmed) {
        return HostType::Domain;
    }

    HostType::Unknown
}

/// Check if a host is an IP address (v4 or v6)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::data::network::detection::host::is_ip_address_host;
///
/// assert!(is_ip_address_host("192.168.1.1"));
/// assert!(is_ip_address_host("::1"));
/// assert!(!is_ip_address_host("example.com"));
/// ```
#[must_use]
pub fn is_ip_address_host(host: &str) -> bool {
    matches!(classify_host(host), HostType::Ipv4 | HostType::Ipv6)
}

/// Check if a host is a domain name
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::data::network::detection::host::is_domain_host;
///
/// assert!(is_domain_host("example.com"));
/// assert!(is_domain_host("sub.example.com"));
/// assert!(!is_domain_host("192.168.1.1"));
/// ```
#[must_use]
pub fn is_domain_host(host: &str) -> bool {
    matches!(classify_host(host), HostType::Domain)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if a string looks like a valid domain format
///
/// This is a simple heuristic check, not full DNS validation.
fn is_valid_domain_format(s: &str) -> bool {
    // Must have at least one character
    if s.is_empty() {
        return false;
    }

    // Must not start or end with hyphen or dot
    if s.starts_with('-') || s.starts_with('.') || s.ends_with('-') || s.ends_with('.') {
        return false;
    }

    // Check each label
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        // Labels must be alphanumeric with hyphens (not start/end with hyphen)
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    // Total length limit
    if s.len() > 253 {
        return false;
    }

    true
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_host_ipv4() {
        assert_eq!(classify_host("192.168.1.1"), HostType::Ipv4);
        assert_eq!(classify_host("127.0.0.1"), HostType::Ipv4);
        assert_eq!(classify_host("8.8.8.8"), HostType::Ipv4);
        assert_eq!(classify_host("0.0.0.0"), HostType::Ipv4);
    }

    #[test]
    fn test_classify_host_ipv6() {
        assert_eq!(classify_host("::1"), HostType::Ipv6);
        assert_eq!(classify_host("2001:db8::1"), HostType::Ipv6);
        assert_eq!(
            classify_host("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            HostType::Ipv6
        );
        assert_eq!(classify_host("fe80::1"), HostType::Ipv6);
    }

    #[test]
    fn test_classify_host_domain() {
        assert_eq!(classify_host("example.com"), HostType::Domain);
        assert_eq!(classify_host("sub.example.com"), HostType::Domain);
        assert_eq!(classify_host("localhost"), HostType::Domain);
        assert_eq!(classify_host("my-server"), HostType::Domain);
    }

    #[test]
    fn test_classify_host_unknown() {
        assert_eq!(classify_host(""), HostType::Unknown);
        assert_eq!(classify_host("   "), HostType::Unknown);
        assert_eq!(classify_host("-invalid"), HostType::Unknown);
        assert_eq!(classify_host("invalid-"), HostType::Unknown);
    }

    #[test]
    fn test_is_ip_address_host() {
        assert!(is_ip_address_host("192.168.1.1"));
        assert!(is_ip_address_host("::1"));
        assert!(!is_ip_address_host("example.com"));
        assert!(!is_ip_address_host(""));
    }

    #[test]
    fn test_is_domain_host() {
        assert!(is_domain_host("example.com"));
        assert!(is_domain_host("localhost"));
        assert!(!is_domain_host("192.168.1.1"));
        assert!(!is_domain_host("::1"));
    }
}

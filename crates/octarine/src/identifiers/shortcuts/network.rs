//! Network identifier shortcuts (IP, MAC, URL, domain, hostname, UUID).
//!
//! Convenience functions over [`NetworkBuilder`](super::super::NetworkBuilder).

use crate::observe::Problem;
use crate::primitives::identifiers::IpRedactionStrategy;

use super::super::NetworkBuilder;
use super::super::types::{IdentifierMatch, UuidVersion};

// ============================================================
// IP ADDRESS SHORTCUTS
// ============================================================

/// Check if value is an IP address
#[must_use]
pub fn is_ip_address(value: &str) -> bool {
    NetworkBuilder::new().is_ip_address(value)
}

/// Check if value is an IPv4 address
#[must_use]
pub fn is_ipv4(value: &str) -> bool {
    NetworkBuilder::new().is_ipv4(value)
}

/// Check if value is an IPv6 address
#[must_use]
pub fn is_ipv6(value: &str) -> bool {
    NetworkBuilder::new().is_ipv6(value)
}

/// Redact an IP address
#[must_use]
pub fn redact_ip(ip: &str) -> String {
    NetworkBuilder::new().redact_ip(ip, IpRedactionStrategy::Token)
}

// ============================================================
// MAC ADDRESS SHORTCUTS
// ============================================================

/// Check if value is a MAC address
#[must_use]
pub fn is_mac_address(value: &str) -> bool {
    NetworkBuilder::new().is_mac_address(value)
}

/// Validate a MAC address format
///
/// Validates format and rejects special addresses (broadcast, null).
pub fn validate_mac_address(mac: &str) -> Result<(), Problem> {
    NetworkBuilder::new().validate_mac_address(mac)
}

// ============================================================
// URL SHORTCUTS
// ============================================================

/// Check if value is a URL
#[must_use]
pub fn is_url(value: &str) -> bool {
    NetworkBuilder::new().is_url(value)
}

/// Find all URLs in text
#[must_use]
pub fn find_urls(text: &str) -> Vec<IdentifierMatch> {
    NetworkBuilder::new().find_urls_in_text(text)
}

// ============================================================
// DOMAIN / HOSTNAME SHORTCUTS
// ============================================================

/// Check if value is a domain name
#[must_use]
pub fn is_domain(value: &str) -> bool {
    NetworkBuilder::new().is_domain(value)
}

/// Check if value is a hostname
#[must_use]
pub fn is_hostname(value: &str) -> bool {
    NetworkBuilder::new().is_hostname(value)
}

/// Find all hostname-like tokens in text
///
/// Conservative filter skips plain English words.
#[must_use]
pub fn find_hostnames(text: &str) -> Vec<IdentifierMatch> {
    NetworkBuilder::new().find_hostnames_in_text(text)
}

/// Find all port tokens (`:N`) in text
#[must_use]
pub fn find_ports(text: &str) -> Vec<IdentifierMatch> {
    NetworkBuilder::new().find_ports_in_text(text)
}

// ============================================================
// UUID SHORTCUTS
// ============================================================

/// Check if value is a UUID
#[must_use]
pub fn is_uuid(value: &str) -> bool {
    NetworkBuilder::new().is_uuid(value)
}

/// Validate a UUID v4
///
/// For bool check, use `validate_uuid_v4(..).is_ok()`.
pub fn validate_uuid_v4(uuid: &str) -> Result<(), Problem> {
    NetworkBuilder::new().validate_uuid_v4(uuid).map(|_| ())
}

/// Validate a UUID (any version)
///
/// Returns the detected UUID version on success.
pub fn validate_uuid(uuid: &str) -> Result<UuidVersion, Problem> {
    NetworkBuilder::new().validate_uuid(uuid)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_mac_address_shortcut() {
        assert!(is_mac_address("00:1A:2B:3C:4D:5E"));
        assert!(is_mac_address("00-1A-2B-3C-4D-5E"));
        assert!(!is_mac_address("not-a-mac"));
    }

    #[test]
    fn test_validate_mac_address_shortcut() {
        assert!(validate_mac_address("00:1A:2B:3C:4D:5E").is_ok());
        assert!(validate_mac_address("not-a-mac").is_err());
    }

    #[test]
    fn test_domain_shortcut() {
        assert!(is_domain("example.com"));
        assert!(is_domain("sub.example.co.uk"));
        assert!(!is_domain("not a domain"));
    }

    #[test]
    fn test_hostname_shortcut() {
        assert!(is_hostname("server01.example.com"));
        assert!(!is_hostname("!!!"));
    }

    #[test]
    fn test_validate_uuid_shortcut() {
        assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_uuid("not-a-uuid").is_err());
    }
}

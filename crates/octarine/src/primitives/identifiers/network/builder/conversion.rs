//! Network identifier conversion methods
//!
//! Builder methods for converting network identifiers between formats.

use super::super::conversion;
use super::NetworkIdentifierBuilder;
use crate::primitives::Problem;

impl NetworkIdentifierBuilder {
    // =========================================================================
    // URL and Domain Conversion
    // =========================================================================

    /// Normalize URL to canonical form
    pub fn normalize_url(&self, url: &str) -> Result<String, Problem> {
        conversion::normalize_url(url)
    }

    /// Canonicalize domain name (lowercase, remove trailing dot)
    #[must_use]
    pub fn canonicalize_domain(&self, domain: &str) -> String {
        conversion::canonicalize_domain(domain)
    }

    // =========================================================================
    // IPv6 Conversion
    // =========================================================================

    /// Compress IPv6 address
    #[must_use]
    pub fn compress_ipv6(&self, ip: &str) -> String {
        conversion::compress_ipv6(ip)
    }

    /// Expand IPv6 address to full form
    pub fn expand_ipv6(&self, ip: &str) -> Result<String, Problem> {
        conversion::expand_ipv6(ip)
    }

    /// Convert IPv4 to IPv4-mapped IPv6
    pub fn ipv4_to_ipv6_mapped(&self, ipv4: &str) -> Result<String, Problem> {
        conversion::ipv4_to_ipv6_mapped(ipv4)
    }

    // =========================================================================
    // MAC Address Conversion
    // =========================================================================

    /// Convert MAC address to colon format
    pub fn mac_to_colon(&self, mac: &str) -> Result<String, Problem> {
        conversion::mac_to_colon(mac)
    }

    /// Convert MAC address to hyphen format
    pub fn mac_to_hyphen(&self, mac: &str) -> Result<String, Problem> {
        conversion::mac_to_hyphen(mac)
    }

    /// Convert MAC address to Cisco dot format
    pub fn mac_to_cisco_dot(&self, mac: &str) -> Result<String, Problem> {
        conversion::mac_to_cisco_dot(mac)
    }

    /// Normalize MAC address to canonical format
    pub fn normalize_mac(&self, mac: &str) -> Result<String, Problem> {
        conversion::normalize_mac(mac)
    }

    // =========================================================================
    // Phone Number Conversion
    // =========================================================================

    /// Convert phone number to E.164 format
    #[must_use]
    pub fn phone_to_e164(&self, phone: &str) -> String {
        conversion::to_phone_e164(phone)
    }

    /// Convert phone number to RFC 3966 tel URI
    #[must_use]
    pub fn phone_to_tel_uri(&self, phone: &str) -> String {
        conversion::to_phone_tel_uri(phone)
    }

    /// Convert phone number to national format
    #[must_use]
    pub fn phone_to_national(&self, phone: &str) -> String {
        conversion::to_phone_national(phone)
    }
}

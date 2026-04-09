//! Network identifier detection methods
//!
//! Builder methods for detecting network identifiers.

use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::super::detection;
use super::NetworkIdentifierBuilder;

impl NetworkIdentifierBuilder {
    // =========================================================================
    // Core Detection Methods
    // =========================================================================

    /// Detect the type of network identifier
    #[must_use]
    pub fn detect(&self, value: &str) -> Option<IdentifierType> {
        detection::detect_network_identifier(value)
    }

    /// Check if value is any network identifier
    #[must_use]
    pub fn is_network(&self, value: &str) -> bool {
        detection::is_network_identifier(value)
    }

    // =========================================================================
    // UUID Detection
    // =========================================================================

    /// Check if value is a UUID (any version)
    #[must_use]
    pub fn is_uuid(&self, value: &str) -> bool {
        detection::is_uuid(value)
    }

    /// Check if value is a UUID v4
    #[must_use]
    pub fn is_uuid_v4(&self, value: &str) -> bool {
        detection::is_uuid_v4(value)
    }

    /// Check if value is a UUID v5
    #[must_use]
    pub fn is_uuid_v5(&self, value: &str) -> bool {
        detection::is_uuid_v5(value)
    }

    // =========================================================================
    // IP Address Detection
    // =========================================================================

    /// Check if value is an IP address
    #[must_use]
    pub fn is_ip_address(&self, value: &str) -> bool {
        detection::is_ip_address(value)
    }

    /// Check if value is an IPv4 address
    #[must_use]
    pub fn is_ipv4(&self, value: &str) -> bool {
        detection::is_ipv4(value)
    }

    /// Check if value is an IPv6 address
    #[must_use]
    pub fn is_ipv6(&self, value: &str) -> bool {
        detection::is_ipv6(value)
    }

    // =========================================================================
    // Network Address Detection
    // =========================================================================

    /// Check if value is a MAC address
    #[must_use]
    pub fn is_mac_address(&self, value: &str) -> bool {
        detection::is_mac_address(value)
    }

    /// Check if value is a URL
    #[must_use]
    pub fn is_url(&self, value: &str) -> bool {
        detection::is_url(value)
    }

    /// Check if value is a domain name (without protocol)
    #[must_use]
    pub fn is_domain(&self, value: &str) -> bool {
        detection::is_domain(value)
    }

    /// Check if value is a hostname
    #[must_use]
    pub fn is_hostname(&self, value: &str) -> bool {
        detection::is_hostname(value)
    }

    /// Check if value is a port number
    #[must_use]
    pub fn is_port(&self, value: &str) -> bool {
        detection::is_port(value)
    }

    // =========================================================================
    // Contact Detection
    // =========================================================================

    /// Check if value is an international phone number
    #[must_use]
    pub fn is_phone_international(&self, value: &str) -> bool {
        detection::is_phone_international(value)
    }

    // =========================================================================
    // Token Detection
    // =========================================================================

    /// Check if value is a JWT token
    #[must_use]
    pub fn is_jwt(&self, value: &str) -> bool {
        detection::is_jwt(value)
    }

    /// Check if value is an API key
    #[must_use]
    pub fn is_api_key(&self, value: &str) -> bool {
        detection::is_api_key(value)
    }

    /// Check if value is an AWS Access Key ID
    #[must_use]
    pub fn is_aws_access_key(&self, value: &str) -> bool {
        detection::is_aws_access_key(value)
    }

    /// Check if value is an AWS Secret Access Key
    #[must_use]
    pub fn is_aws_secret_key(&self, value: &str) -> bool {
        detection::is_aws_secret_key(value)
    }

    /// Check if value is a Google Cloud Platform API key
    #[must_use]
    pub fn is_gcp_api_key(&self, value: &str) -> bool {
        detection::is_gcp_api_key(value)
    }

    /// Check if value is a GitHub Personal Access Token
    #[must_use]
    pub fn is_github_token(&self, value: &str) -> bool {
        detection::is_github_token(value)
    }

    /// Check if value is an Azure Storage Account Key
    #[must_use]
    pub fn is_azure_key(&self, value: &str) -> bool {
        detection::is_azure_key(value)
    }

    /// Check if value is a Stripe API key
    #[must_use]
    pub fn is_stripe_key(&self, value: &str) -> bool {
        detection::is_stripe_key(value)
    }

    // =========================================================================
    // Text Detection Methods
    // =========================================================================

    /// Check if text contains any network identifier
    #[must_use]
    pub fn is_network_present(&self, text: &str) -> bool {
        detection::is_network_present(text)
    }

    // =========================================================================
    // Batch Detection Methods
    // =========================================================================

    /// Detect multiple identifiers in batch
    ///
    /// Returns a vector of tuples containing the input value and its detected type.
    /// Non-identifiers return None for the type.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::network::NetworkIdentifierBuilder;
    ///
    /// let builder = NetworkIdentifierBuilder::new();
    /// let inputs = vec![
    ///     "550e8400-e29b-41d4-a716-446655440000",
    ///     "192.168.1.1",
    ///     "not-an-identifier",
    /// ];
    ///
    /// let results = builder.detect_batch(&inputs);
    /// assert_eq!(results.len(), 3);
    /// assert!(results[0].1.is_some()); // UUID detected
    /// assert!(results[1].1.is_some()); // IP detected
    /// assert!(results[2].1.is_none());  // Not detected
    /// ```
    #[must_use]
    pub fn detect_batch<'a>(&self, values: &'a [&str]) -> Vec<(&'a str, Option<IdentifierType>)> {
        values
            .iter()
            .map(|&value| (value, self.detect(value)))
            .collect()
    }

    // =========================================================================
    // Text Scanning Methods
    // =========================================================================

    /// Find all UUIDs in text
    #[must_use]
    pub fn find_uuids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_uuids_in_text(text)
    }

    /// Find all IP addresses in text
    #[must_use]
    pub fn find_ip_addresses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_ip_addresses_in_text(text)
    }

    /// Find all MAC addresses in text
    #[must_use]
    pub fn find_mac_addresses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_mac_addresses_in_text(text)
    }

    /// Find all domain names in text
    #[must_use]
    pub fn find_domains_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_domains_in_text(text)
    }

    /// Find all URLs in text
    #[must_use]
    pub fn find_urls_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_urls_in_text(text)
    }

    /// Find all API keys in text
    #[must_use]
    pub fn find_api_keys_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_api_keys_in_text(text)
    }

    /// Find all network identifiers in text
    #[must_use]
    pub fn find_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_all_network_in_text(text)
    }

    // =========================================================================
    // Test Data Detection Methods
    // =========================================================================

    /// Check if IP address is a known test/development address
    ///
    /// Detects loopback, private, link-local, documentation, broadcast, and null IPs.
    #[must_use]
    pub fn is_test_ip(&self, ip: &str) -> bool {
        detection::is_test_ip(ip)
    }

    /// Check if MAC address is a known test/special address
    ///
    /// Detects broadcast, null, multicast, locally administered, and VM MACs.
    #[must_use]
    pub fn is_test_mac(&self, mac: &str) -> bool {
        detection::is_test_mac(mac)
    }

    /// Check if URL is a test/development URL
    ///
    /// Detects localhost, reserved domains/TLDs, and development subdomains.
    #[must_use]
    pub fn is_test_url(&self, url: &str) -> bool {
        detection::is_test_url(url)
    }

    /// Check if UUID is a known test/special UUID
    ///
    /// Detects nil, max, and common test pattern UUIDs.
    #[must_use]
    pub fn is_test_uuid(&self, uuid: &str) -> bool {
        detection::is_test_uuid(uuid)
    }

    /// Check if domain is a test/reserved domain
    ///
    /// Detects RFC 2606 reserved domains/TLDs and localhost.
    #[must_use]
    pub fn is_test_domain(&self, domain: &str) -> bool {
        detection::is_test_domain(domain)
    }

    /// Check if hostname is a test/development hostname
    ///
    /// Detects localhost and common test prefixes/suffixes.
    #[must_use]
    pub fn is_test_hostname(&self, hostname: &str) -> bool {
        detection::is_test_hostname(hostname)
    }
}

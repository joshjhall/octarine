//! Network identifier builder with observability
//!
//! Wraps `primitives::identifiers::NetworkIdentifierBuilder` with observe instrumentation.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.

use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Instant;

use crate::observe::Problem;
use crate::observe::metrics::{MetricName, increment_by, record};
use crate::primitives::identifiers::{
    IpRedactionStrategy, MacRedactionStrategy, NetworkApiKeyRedactionStrategy,
    NetworkIdentifierBuilder, NetworkTextPolicy, UrlRedactionStrategy, UuidRedactionStrategy,
};

use super::super::types::{ApiKeyProvider, IdentifierMatch, IdentifierType, UuidVersion};

// Pre-validated metric names
#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn detect_ms() -> MetricName {
        MetricName::new("data.identifiers.network.detect_ms").expect("valid metric name")
    }

    pub fn detected() -> MetricName {
        MetricName::new("data.identifiers.network.detected").expect("valid metric name")
    }
}

/// Network identifier builder with observability
///
/// Provides detection, validation, and sanitization for network identifiers
/// (IPs, MACs, URLs, UUIDs, hostnames) with full audit trail.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkBuilder {
    inner: NetworkIdentifierBuilder,
    emit_events: bool,
}

impl NetworkBuilder {
    /// Create a new NetworkBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: NetworkIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: NetworkIdentifierBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // Detection Methods
    // ========================================================================

    /// Detect network identifier type from value
    #[must_use]
    pub fn detect(&self, value: &str) -> Option<IdentifierType> {
        let start = Instant::now();
        let result = self.inner.detect(value);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if result.is_some() {
                increment_by(metric_names::detected(), 1);
            }
        }

        result
    }

    /// Check if value is any network identifier
    #[must_use]
    pub fn is_network(&self, value: &str) -> bool {
        self.inner.is_network(value)
    }

    /// Check if value is an IP address
    #[must_use]
    pub fn is_ip_address(&self, value: &str) -> bool {
        self.inner.is_ip_address(value)
    }

    /// Check if value is an IPv4 address
    #[must_use]
    pub fn is_ipv4(&self, value: &str) -> bool {
        self.inner.is_ipv4(value)
    }

    /// Check if value is an IPv6 address
    #[must_use]
    pub fn is_ipv6(&self, value: &str) -> bool {
        self.inner.is_ipv6(value)
    }

    /// Check if value is a MAC address
    #[must_use]
    pub fn is_mac_address(&self, value: &str) -> bool {
        self.inner.is_mac_address(value)
    }

    /// Check if value is a UUID (any version)
    #[must_use]
    pub fn is_uuid(&self, value: &str) -> bool {
        self.inner.is_uuid(value)
    }

    /// Check if value is a UUID v4
    #[must_use]
    pub fn is_uuid_v4(&self, value: &str) -> bool {
        self.inner.is_uuid_v4(value)
    }

    /// Check if value is a UUID v5
    #[must_use]
    pub fn is_uuid_v5(&self, value: &str) -> bool {
        self.inner.is_uuid_v5(value)
    }

    /// Check if value is a URL
    #[must_use]
    pub fn is_url(&self, value: &str) -> bool {
        self.inner.is_url(value)
    }

    /// Check if value is a hostname
    #[must_use]
    pub fn is_hostname(&self, value: &str) -> bool {
        self.inner.is_hostname(value)
    }

    /// Check if value is a domain
    #[must_use]
    pub fn is_domain(&self, value: &str) -> bool {
        self.inner.is_domain(value)
    }

    /// Check if value is a port number
    #[must_use]
    pub fn is_port(&self, value: &str) -> bool {
        self.inner.is_port(value)
    }

    /// Check if value is an API key
    #[must_use]
    pub fn is_api_key(&self, value: &str) -> bool {
        self.inner.is_api_key(value)
    }

    /// Check if value is a JWT
    #[must_use]
    pub fn is_jwt(&self, value: &str) -> bool {
        self.inner.is_jwt(value)
    }

    /// Check if value is an international phone number
    #[must_use]
    pub fn is_phone_international(&self, value: &str) -> bool {
        self.inner.is_phone_international(value)
    }

    /// Check if text contains any network identifier
    #[must_use]
    pub fn is_network_identifier_present(&self, text: &str) -> bool {
        self.inner.is_network_present(text)
    }

    // ========================================================================
    // Text Scanning Methods
    // ========================================================================

    /// Find all UUIDs in text
    #[must_use]
    pub fn find_uuids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_uuids_in_text(text)
    }

    /// Find all IP addresses in text
    #[must_use]
    pub fn find_ip_addresses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_ip_addresses_in_text(text)
    }

    /// Find all MAC addresses in text
    #[must_use]
    pub fn find_mac_addresses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_mac_addresses_in_text(text)
    }

    /// Find all URLs in text
    #[must_use]
    pub fn find_urls_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_urls_in_text(text)
    }

    /// Find all API keys in text
    #[must_use]
    pub fn find_api_keys_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_api_keys_in_text(text)
    }

    /// Find all network identifiers in text
    #[must_use]
    pub fn find_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let matches = self.inner.find_all_in_text(text);

        if self.emit_events && !matches.is_empty() {
            increment_by(metric_names::detected(), matches.len() as u64);
        }

        matches
    }

    // ========================================================================
    // Validation Methods
    //
    // All validate_* methods return Result<T, E>. For bool checks, use
    // the detection methods (is_*) or call validate_*.is_ok()
    // ========================================================================

    /// Validate UUID v4 format
    ///
    /// Returns the UUID version on success. For bool check, use `.is_ok()`.
    pub fn validate_uuid_v4(&self, uuid: &str) -> Result<UuidVersion, Problem> {
        self.inner.validate_uuid_v4(uuid)
    }

    /// Validate UUID v5 format
    pub fn validate_uuid_v5(&self, uuid: &str) -> Result<UuidVersion, Problem> {
        self.inner.validate_uuid_v5(uuid)
    }

    /// Validate UUID any format
    pub fn validate_uuid(&self, uuid: &str) -> Result<UuidVersion, Problem> {
        self.inner.validate_uuid(uuid)
    }

    /// Validate MAC address format
    ///
    /// Validates format and rejects special addresses (broadcast, null).
    pub fn validate_mac_address(&self, mac: &str) -> Result<(), Problem> {
        self.inner.validate_mac_address(mac)
    }

    /// Validate international phone number
    pub fn validate_phone_international(&self, phone: &str) -> Result<(), Problem> {
        self.inner.validate_phone_international(phone)
    }

    /// Validate JWT token format
    pub fn validate_jwt(&self, token: &str) -> Result<(), Problem> {
        self.inner.validate_jwt(token)
    }

    // ========================================================================
    // IPv4 Classification Methods
    // ========================================================================

    /// Check if IPv4 address is private (RFC 1918)
    #[must_use]
    pub fn is_private_ipv4(&self, ip: &str) -> bool {
        self.inner.is_private_ipv4(ip)
    }

    /// Check if IPv4 address is loopback
    #[must_use]
    pub fn is_loopback_ipv4(&self, ip: &str) -> bool {
        self.inner.is_loopback_ipv4(ip)
    }

    /// Check if IPv4 address is link-local
    #[must_use]
    pub fn is_link_local_ipv4(&self, ip: &str) -> bool {
        self.inner.is_link_local_ipv4(ip)
    }

    /// Check if IPv4 address is multicast
    #[must_use]
    pub fn is_multicast_ipv4(&self, ip: &str) -> bool {
        self.inner.is_multicast_ipv4(ip)
    }

    /// Check if IPv4 address is reserved
    #[must_use]
    pub fn is_reserved_ipv4(&self, ip: &str) -> bool {
        self.inner.is_reserved_ipv4(ip)
    }

    /// Check if IPv4 address is broadcast
    #[must_use]
    pub fn is_broadcast_ipv4(&self, ip: &str) -> bool {
        self.inner.is_broadcast_ipv4(ip)
    }

    /// Check if IPv4 address is public
    #[must_use]
    pub fn is_public_ipv4(&self, ip: &str) -> bool {
        self.inner.is_public_ipv4(ip)
    }

    // ========================================================================
    // IPv6 Classification Methods
    // ========================================================================

    /// Check if IPv6 address is loopback
    #[must_use]
    pub fn is_loopback_ipv6(&self, ip: &str) -> bool {
        self.inner.is_loopback_ipv6(ip)
    }

    /// Check if IPv6 address is link-local
    #[must_use]
    pub fn is_link_local_ipv6(&self, ip: &str) -> bool {
        self.inner.is_link_local_ipv6(ip)
    }

    /// Check if IPv6 address is multicast
    #[must_use]
    pub fn is_multicast_ipv6(&self, ip: &str) -> bool {
        self.inner.is_multicast_ipv6(ip)
    }

    /// Check if IPv6 address is unique local
    #[must_use]
    pub fn is_unique_local_ipv6(&self, ip: &str) -> bool {
        self.inner.is_unique_local_ipv6(ip)
    }

    /// Check if IPv6 address is public
    #[must_use]
    pub fn is_public_ipv6(&self, ip: &str) -> bool {
        self.inner.is_public_ipv6(ip)
    }

    // ========================================================================
    // Single Value Redaction Methods (with strategy)
    // ========================================================================

    /// Redact a single UUID with strategy
    #[must_use]
    pub fn redact_uuid(&self, uuid: &str, strategy: UuidRedactionStrategy) -> String {
        self.inner.redact_uuid(uuid, strategy)
    }

    /// Redact a single IP address with strategy
    #[must_use]
    pub fn redact_ip(&self, ip: &str, strategy: IpRedactionStrategy) -> String {
        self.inner.redact_ip(ip, strategy)
    }

    /// Redact a single MAC address with strategy
    #[must_use]
    pub fn redact_mac(&self, mac: &str, strategy: MacRedactionStrategy) -> String {
        self.inner.redact_mac(mac, strategy)
    }

    /// Redact a single URL with strategy
    #[must_use]
    pub fn redact_url(&self, url: &str, strategy: UrlRedactionStrategy) -> String {
        self.inner.redact_url(url, strategy)
    }

    /// Redact a single API key with strategy
    #[must_use]
    pub fn redact_api_key(&self, key: &str, strategy: NetworkApiKeyRedactionStrategy) -> String {
        self.inner.redact_api_key(key, strategy)
    }

    // ========================================================================
    // Text Redaction Methods (with policy)
    // ========================================================================

    /// Redact UUIDs in text (uses Partial policy by default)
    #[must_use]
    pub fn redact_uuids_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.inner.redact_uuids_in_text(text)
    }

    /// Redact UUIDs in text with custom policy
    #[must_use]
    pub fn redact_uuids_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: NetworkTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_uuids_in_text_with_policy(text, policy)
    }

    /// Redact IP addresses in text (uses Partial policy by default)
    #[must_use]
    pub fn redact_ips_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.inner.redact_ips_in_text(text)
    }

    /// Redact IP addresses in text with custom policy
    #[must_use]
    pub fn redact_ips_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: NetworkTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_ips_in_text_with_policy(text, policy)
    }

    /// Redact MAC addresses in text (uses Partial policy by default)
    #[must_use]
    pub fn redact_macs_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.inner.redact_macs_in_text(text)
    }

    /// Redact MAC addresses in text with custom policy
    #[must_use]
    pub fn redact_macs_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: NetworkTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_macs_in_text_with_policy(text, policy)
    }

    /// Redact URLs in text (uses Partial policy by default)
    #[must_use]
    pub fn redact_urls_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.inner.redact_urls_in_text(text)
    }

    /// Redact URLs in text with custom policy
    #[must_use]
    pub fn redact_urls_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: NetworkTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_urls_in_text_with_policy(text, policy)
    }

    /// Redact API keys in text (uses Partial policy by default)
    #[must_use]
    pub fn redact_api_keys_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.inner.redact_api_keys_in_text(text)
    }

    /// Redact API keys in text with custom policy
    #[must_use]
    pub fn redact_api_keys_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: NetworkTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_api_keys_in_text_with_policy(text, policy)
    }

    /// Redact all network identifiers in text using Complete policy
    #[must_use]
    pub fn redact_all_in_text(&self, text: &str) -> String {
        self.inner.redact_all_in_text(text)
    }

    /// Redact all network identifiers in text with custom policy
    #[must_use]
    pub fn redact_all_in_text_with_policy(&self, text: &str, policy: NetworkTextPolicy) -> String {
        self.inner.redact_all_in_text_with_policy(text, policy)
    }

    // ========================================================================
    // Test Pattern Detection
    // ========================================================================

    /// Check if IP is a test pattern
    #[must_use]
    pub fn is_test_ip(&self, ip: &str) -> bool {
        self.inner.is_test_ip(ip)
    }

    /// Check if MAC is a test pattern
    #[must_use]
    pub fn is_test_mac(&self, mac: &str) -> bool {
        self.inner.is_test_mac(mac)
    }

    /// Check if UUID is a test pattern
    #[must_use]
    pub fn is_test_uuid(&self, uuid: &str) -> bool {
        self.inner.is_test_uuid(uuid)
    }

    /// Check if URL is a test pattern
    #[must_use]
    pub fn is_test_url(&self, url: &str) -> bool {
        self.inner.is_test_url(url)
    }

    /// Check if hostname is a test pattern
    #[must_use]
    pub fn is_test_hostname(&self, hostname: &str) -> bool {
        self.inner.is_test_hostname(hostname)
    }

    /// Check if domain is a test pattern
    #[must_use]
    pub fn is_test_domain(&self, domain: &str) -> bool {
        self.inner.is_test_domain(domain)
    }

    /// Check if text contains any network identifier
    #[must_use]
    pub fn is_network_present(&self, text: &str) -> bool {
        self.inner.is_network_present(text)
    }

    // ========================================================================
    // Provider-Specific API Key Detection
    // ========================================================================

    /// Check if value is an AWS Access Key ID
    #[must_use]
    pub fn is_aws_access_key(&self, value: &str) -> bool {
        self.inner.is_aws_access_key(value)
    }

    /// Check if value is an AWS Secret Access Key
    #[must_use]
    pub fn is_aws_secret_key(&self, value: &str) -> bool {
        self.inner.is_aws_secret_key(value)
    }

    /// Check if value is a Google Cloud Platform API key
    #[must_use]
    pub fn is_gcp_api_key(&self, value: &str) -> bool {
        self.inner.is_gcp_api_key(value)
    }

    /// Check if value is a GitHub Personal Access Token
    #[must_use]
    pub fn is_github_token(&self, value: &str) -> bool {
        self.inner.is_github_token(value)
    }

    /// Check if value is an Azure Storage Account Key
    #[must_use]
    pub fn is_azure_key(&self, value: &str) -> bool {
        self.inner.is_azure_key(value)
    }

    /// Check if value is a Stripe API key
    #[must_use]
    pub fn is_stripe_key(&self, value: &str) -> bool {
        self.inner.is_stripe_key(value)
    }

    // ========================================================================
    // Additional Validation Methods
    // ========================================================================

    /// Validate API key format (returns Result with provider)
    pub fn validate_api_key(
        &self,
        key: &str,
        min_length: usize,
        max_length: usize,
    ) -> Result<ApiKeyProvider, Problem> {
        self.inner.validate_api_key(key, min_length, max_length)
    }

    /// Validate session ID format (returns Result)
    pub fn validate_session_id(
        &self,
        session_id: &str,
        min_length: usize,
        max_length: usize,
    ) -> Result<(), Problem> {
        self.inner
            .validate_session_id(session_id, min_length, max_length)
    }

    // ========================================================================
    // Conversion Methods
    // ========================================================================

    /// Normalize URL to canonical form
    pub fn normalize_url(&self, url: &str) -> Result<String, Problem> {
        self.inner.normalize_url(url)
    }

    /// Canonicalize domain name (lowercase, remove trailing dot)
    #[must_use]
    pub fn canonicalize_domain(&self, domain: &str) -> String {
        self.inner.canonicalize_domain(domain)
    }

    /// Compress IPv6 address to shortest form
    #[must_use]
    pub fn compress_ipv6(&self, ip: &str) -> String {
        self.inner.compress_ipv6(ip)
    }

    /// Expand IPv6 address to full form
    pub fn expand_ipv6(&self, ip: &str) -> Result<String, Problem> {
        self.inner.expand_ipv6(ip)
    }

    /// Convert IPv4 to IPv4-mapped IPv6
    pub fn ipv4_to_ipv6_mapped(&self, ipv4: &str) -> Result<String, Problem> {
        self.inner.ipv4_to_ipv6_mapped(ipv4)
    }

    /// Convert MAC address to colon format (AA:BB:CC:DD:EE:FF)
    pub fn mac_to_colon(&self, mac: &str) -> Result<String, Problem> {
        self.inner.mac_to_colon(mac)
    }

    /// Convert MAC address to hyphen format (AA-BB-CC-DD-EE-FF)
    pub fn mac_to_hyphen(&self, mac: &str) -> Result<String, Problem> {
        self.inner.mac_to_hyphen(mac)
    }

    /// Convert MAC address to Cisco dot format (AABB.CCDD.EEFF)
    pub fn mac_to_cisco_dot(&self, mac: &str) -> Result<String, Problem> {
        self.inner.mac_to_cisco_dot(mac)
    }

    /// Normalize MAC address to canonical format (lowercase colon)
    pub fn normalize_mac(&self, mac: &str) -> Result<String, Problem> {
        self.inner.normalize_mac(mac)
    }

    /// Convert phone number to E.164 format
    #[must_use]
    pub fn phone_to_e164(&self, phone: &str) -> String {
        self.inner.phone_to_e164(phone)
    }

    /// Convert phone number to RFC 3966 tel URI
    #[must_use]
    pub fn phone_to_tel_uri(&self, phone: &str) -> String {
        self.inner.phone_to_tel_uri(phone)
    }

    /// Convert phone number to national format
    #[must_use]
    pub fn phone_to_national(&self, phone: &str) -> String {
        self.inner.phone_to_national(phone)
    }

    // ========================================================================
    // Batch Processing Methods
    // ========================================================================

    /// Detect multiple identifiers in batch
    ///
    /// Returns a vector of tuples containing the input value and its detected type.
    /// Non-identifiers return None for the type.
    #[must_use]
    pub fn detect_batch<'a>(&self, values: &'a [&str]) -> Vec<(&'a str, Option<IdentifierType>)> {
        values
            .iter()
            .map(|&value| (value, self.inner.detect(value)))
            .collect()
    }

    /// Validate a batch of values against an expected type
    ///
    /// Returns a vector of (value, is_valid) tuples indicating whether
    /// each value matches the expected identifier type.
    #[must_use]
    pub fn validate_batch_as<'a>(
        &self,
        values: &'a [&str],
        expected_type: IdentifierType,
    ) -> Vec<(&'a str, bool)> {
        self.inner.validate_batch_as(values, expected_type)
    }

    /// Filter batch to only valid identifiers
    ///
    /// Returns only the values that were successfully detected as valid identifiers.
    #[must_use]
    pub fn filter_valid_identifiers<'a>(&self, values: &'a [&str]) -> Vec<&'a str> {
        self.inner.filter_valid_identifiers(values)
    }

    /// Count identifiers by type in batch
    ///
    /// Returns a count of how many of each identifier type were found.
    #[must_use]
    pub fn count_by_type(&self, values: &[&str]) -> HashMap<IdentifierType, usize> {
        self.inner.count_by_type(values)
    }

    /// Partition batch into valid and invalid identifiers
    ///
    /// Returns two vectors: (valid_identifiers, invalid_values).
    #[must_use]
    pub fn partition_identifiers<'a>(&self, values: &'a [&str]) -> (Vec<&'a str>, Vec<&'a str>) {
        self.inner.partition_identifiers(values)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = NetworkBuilder::new();
        assert!(builder.emit_events);

        let silent = NetworkBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = NetworkBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_ip_detection() {
        let builder = NetworkBuilder::silent();
        assert!(builder.is_ip_address("192.168.1.1"));
    }

    #[test]
    fn test_detect_ip() {
        let builder = NetworkBuilder::silent();
        assert_eq!(
            builder.detect("192.168.1.1"),
            Some(IdentifierType::IpAddress)
        );
    }

    #[test]
    fn test_detect_uuid() {
        let builder = NetworkBuilder::new();
        assert_eq!(
            builder.detect("550e8400-e29b-41d4-a716-446655440000"),
            Some(IdentifierType::Uuid)
        );
    }

    #[test]
    fn test_redact_ip() {
        let builder = NetworkBuilder::new();
        let result = builder.redact_ip("192.168.1.1", IpRedactionStrategy::Token);
        assert!(!result.contains("192.168.1.1"));
    }
}

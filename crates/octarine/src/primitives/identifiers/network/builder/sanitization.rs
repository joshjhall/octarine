//! Network identifier sanitization methods
//!
//! Builder methods for redacting and masking network identifiers.

use super::super::redaction::{
    ApiKeyRedactionStrategy, IpRedactionStrategy, MacRedactionStrategy, TextRedactionPolicy,
    UrlRedactionStrategy, UuidRedactionStrategy,
};
use super::super::sanitization;
use super::NetworkIdentifierBuilder;
use std::borrow::Cow;

impl NetworkIdentifierBuilder {
    // =========================================================================
    // Single Value Redaction Methods (with strategy)
    // =========================================================================

    /// Redact a single UUID with strategy
    #[must_use]
    pub fn redact_uuid(&self, uuid: &str, strategy: UuidRedactionStrategy) -> String {
        sanitization::redact_uuid_with_strategy(uuid, strategy)
    }

    /// Redact a single IP address with strategy
    #[must_use]
    pub fn redact_ip(&self, ip: &str, strategy: IpRedactionStrategy) -> String {
        sanitization::redact_ip_with_strategy(ip, strategy)
    }

    /// Redact a single MAC address with strategy
    #[must_use]
    pub fn redact_mac(&self, mac: &str, strategy: MacRedactionStrategy) -> String {
        sanitization::redact_mac_with_strategy(mac, strategy)
    }

    /// Redact a single URL with strategy
    #[must_use]
    pub fn redact_url(&self, url: &str, strategy: UrlRedactionStrategy) -> String {
        sanitization::redact_url_with_strategy(url, strategy)
    }

    /// Redact a single API key with strategy
    #[must_use]
    pub fn redact_api_key(&self, key: &str, strategy: ApiKeyRedactionStrategy) -> String {
        sanitization::redact_api_key_with_strategy(key, strategy)
    }

    // =========================================================================
    // Text Redaction Methods (with policy)
    // =========================================================================

    /// Redact UUIDs in text (uses Partial policy by default)
    #[must_use]
    pub fn redact_uuids_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        sanitization::redact_uuids_in_text(text, TextRedactionPolicy::Partial)
    }

    /// Redact UUIDs in text with custom policy
    #[must_use]
    pub fn redact_uuids_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_uuids_in_text(text, policy)
    }

    /// Redact IP addresses in text (uses Partial policy by default)
    #[must_use]
    pub fn redact_ips_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        sanitization::redact_ips_in_text(text, TextRedactionPolicy::Partial)
    }

    /// Redact IP addresses in text with custom policy
    #[must_use]
    pub fn redact_ips_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_ips_in_text(text, policy)
    }

    /// Redact MAC addresses in text (uses Partial policy by default)
    #[must_use]
    pub fn redact_macs_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        sanitization::redact_macs_in_text(text, TextRedactionPolicy::Partial)
    }

    /// Redact MAC addresses in text with custom policy
    #[must_use]
    pub fn redact_macs_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_macs_in_text(text, policy)
    }

    /// Redact URLs in text (uses Partial policy by default)
    #[must_use]
    pub fn redact_urls_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        sanitization::redact_urls_in_text(text, TextRedactionPolicy::Partial)
    }

    /// Redact URLs in text with custom policy
    #[must_use]
    pub fn redact_urls_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_urls_in_text(text, policy)
    }

    /// Redact API keys in text (uses Partial policy by default)
    #[must_use]
    pub fn redact_api_keys_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        sanitization::redact_api_keys_in_text(text, TextRedactionPolicy::Partial)
    }

    /// Redact API keys in text with custom policy
    #[must_use]
    pub fn redact_api_keys_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: TextRedactionPolicy,
    ) -> Cow<'a, str> {
        sanitization::redact_api_keys_in_text(text, policy)
    }

    /// Redact all network identifiers in text using Complete policy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use crate::primitives::identifiers::network::NetworkIdentifierBuilder;
    ///
    /// let builder = NetworkIdentifierBuilder::new();
    /// let result = builder.redact_all_in_text("IP: 192.168.1.1");
    /// assert!(result.contains("[IP]"));
    /// ```
    #[must_use]
    pub fn redact_all_in_text(&self, text: &str) -> String {
        sanitization::redact_all_network_in_text(text, TextRedactionPolicy::Complete)
    }

    /// Redact all network identifiers in text with custom policy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use crate::primitives::identifiers::network::{NetworkIdentifierBuilder, TextRedactionPolicy};
    ///
    /// let builder = NetworkIdentifierBuilder::new();
    ///
    /// // Partial - shows first octet
    /// let result = builder.redact_all_in_text_with_policy(
    ///     "IP: 192.168.1.1",
    ///     TextRedactionPolicy::Partial
    /// );
    /// assert!(result.contains("192.***"));
    /// ```
    #[must_use]
    pub fn redact_all_in_text_with_policy(
        &self,
        text: &str,
        policy: TextRedactionPolicy,
    ) -> String {
        sanitization::redact_all_network_in_text(text, policy)
    }
}

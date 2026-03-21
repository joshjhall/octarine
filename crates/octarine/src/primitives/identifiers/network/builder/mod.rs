//! Network identifier builder (primitives layer)
//!
//! Unified API for network identifier detection, validation, and sanitization.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - provides a builder pattern
//! with no observe dependencies.
//!
//! # Why No Caching?
//!
//! Unlike other identifier modules (personal, financial, government), network
//! identifier operations are computationally cheap (simple regex/parsing) and
//! don't benefit significantly from caching. This keeps the module simple and
//! avoids unnecessary memory overhead.

use super::super::types::{IdentifierMatch, IdentifierType};
use crate::primitives::Problem;
use std::borrow::Cow;

mod conversion;
mod detection;
mod sanitization;
mod validation;

/// Builder for network identifier operations
///
/// Provides a unified API for detecting, validating, and sanitizing
/// network identifiers including UUIDs, IP addresses, MAC addresses,
/// URLs, phone numbers, JWT tokens, and API keys.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::NetworkIdentifierBuilder;
///
/// let builder = NetworkIdentifierBuilder::new();
///
/// // Detection
/// assert!(builder.is_uuid("550e8400-e29b-41d4-a716-446655440000"));
///
/// // Validation
/// assert!(builder.validate_uuid_v4("550e8400-e29b-41d4-a716-446655440000"));
///
/// // Sanitization
/// let safe = builder.redact_all_in_text("UUID: 550e8400-e29b-41d4-a716-446655440000");
/// assert!(safe.contains("[UUID]"));
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkIdentifierBuilder;

impl NetworkIdentifierBuilder {
    // =========================================================================
    // Construction
    // =========================================================================

    /// Create a new network identifier builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // =========================================================================
    // Batch Processing Methods (delegate to batch.rs)
    // =========================================================================

    /// Validate a batch of values against an expected type
    ///
    /// Returns a vector of (value, is_valid) tuples indicating whether
    /// each value matches the expected identifier type.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::network::NetworkIdentifierBuilder;
    /// use octarine::primitives::identifiers::types::IdentifierType;
    ///
    /// let builder = NetworkIdentifierBuilder::new();
    /// let ips = vec!["192.168.1.1", "10.0.0.1", "not-an-ip"];
    ///
    /// let results = builder.validate_batch_as(&ips, IdentifierType::IpAddress);
    /// assert_eq!(results[0].1, true);  // Valid IP
    /// assert_eq!(results[1].1, true);  // Valid IP
    /// assert_eq!(results[2].1, false); // Invalid
    /// ```
    #[must_use]
    pub fn validate_batch_as<'a>(
        &self,
        values: &'a [&str],
        expected_type: IdentifierType,
    ) -> Vec<(&'a str, bool)> {
        super::batch::validate_batch_as(values, expected_type)
    }

    /// Filter batch to only valid identifiers
    ///
    /// Returns only the values that were successfully detected as valid identifiers.
    /// Useful for cleaning datasets or extracting identifiers from mixed input.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::network::NetworkIdentifierBuilder;
    ///
    /// let builder = NetworkIdentifierBuilder::new();
    /// let mixed = vec![
    ///     "550e8400-e29b-41d4-a716-446655440000", // UUID
    ///     "invalid",
    ///     "192.168.1.1", // IP
    ///     "junk",
    /// ];
    ///
    /// let valid = builder.filter_valid_identifiers(&mixed);
    /// assert_eq!(valid.len(), 2); // Only UUID and IP
    /// ```
    #[must_use]
    pub fn filter_valid_identifiers<'a>(&self, values: &'a [&str]) -> Vec<&'a str> {
        super::batch::filter_valid_identifiers(values)
    }

    /// Count identifiers by type in batch
    ///
    /// Returns a count of how many of each identifier type were found.
    /// Useful for analyzing datasets or reporting statistics.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::network::NetworkIdentifierBuilder;
    /// use std::collections::HashMap;
    ///
    /// let builder = NetworkIdentifierBuilder::new();
    /// let values = vec![
    ///     "550e8400-e29b-41d4-a716-446655440000", // UUID
    ///     "192.168.1.1", // IP
    ///     "192.168.1.2", // IP
    ///     "not-valid",
    /// ];
    ///
    /// let counts = builder.count_by_type(&values);
    /// assert_eq!(counts.get(&IdentifierType::Uuid), Some(&1));
    /// assert_eq!(counts.get(&IdentifierType::IpAddress), Some(&2));
    /// ```
    #[must_use]
    pub fn count_by_type(
        &self,
        values: &[&str],
    ) -> std::collections::HashMap<IdentifierType, usize> {
        super::batch::count_by_type(values)
    }

    /// Partition batch into valid and invalid identifiers
    ///
    /// Returns two vectors: (valid_identifiers, invalid_values).
    /// Useful for error handling or data cleanup.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::network::NetworkIdentifierBuilder;
    ///
    /// let builder = NetworkIdentifierBuilder::new();
    /// let mixed = vec!["192.168.1.1", "invalid", "10.0.0.1", "junk"];
    ///
    /// let (valid, invalid) = builder.partition_identifiers(&mixed);
    /// assert_eq!(valid.len(), 2);
    /// assert_eq!(invalid.len(), 2);
    /// ```
    #[must_use]
    pub fn partition_identifiers<'a>(&self, values: &'a [&str]) -> (Vec<&'a str>, Vec<&'a str>) {
        super::batch::partition_identifiers(values)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = NetworkIdentifierBuilder::new();
        assert!(!builder.is_network(""));
    }

    #[test]
    fn test_builder_detection() {
        let builder = NetworkIdentifierBuilder::new();

        assert!(builder.is_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(builder.is_ipv4("192.168.1.1"));
        assert!(builder.is_mac_address("00:1B:44:11:3A:B7"));
        assert!(builder.is_url("https://example.com"));
    }

    #[test]
    fn test_builder_validation() {
        let builder = NetworkIdentifierBuilder::new();

        assert!(
            builder
                .validate_uuid_v4("550e8400-e29b-41d4-a716-446655440000")
                .is_ok()
        );
        assert!(builder.validate_mac_address("00:1B:44:11:3A:B7").is_ok());
        assert!(
            builder
                .validate_phone_international("+1-555-123-4567")
                .is_ok()
        );
    }

    #[test]
    fn test_builder_sanitization() {
        let builder = NetworkIdentifierBuilder::new();

        let text = "UUID: 550e8400-e29b-41d4-a716-446655440000";
        let result = builder.redact_all_in_text(text);
        assert!(result.contains("[UUID]"));
    }

    #[test]
    fn test_builder_redaction_with_strategy() {
        use super::super::redaction::{IpRedactionStrategy, UuidRedactionStrategy};

        let builder = NetworkIdentifierBuilder::new();

        let redacted_uuid = builder.redact_uuid(
            "550e8400-e29b-41d4-a716-446655440000",
            UuidRedactionStrategy::Mask,
        );
        assert!(redacted_uuid.starts_with("550e8400"));
        assert!(redacted_uuid.contains("****"));

        let redacted_ip = builder.redact_ip("192.168.1.1", IpRedactionStrategy::Mask);
        assert!(redacted_ip.starts_with("192"));
        assert!(redacted_ip.contains("***"));
    }

    #[test]
    fn test_builder_text_scanning() {
        let builder = NetworkIdentifierBuilder::new();

        let text = "UUID: 550e8400-e29b-41d4-a716-446655440000, IP: 192.168.1.1";
        let matches = builder.find_all_in_text(text);
        assert!(matches.len() >= 2);
    }

    #[test]
    fn test_builder_is_network_present() {
        let builder = NetworkIdentifierBuilder::new();
        let text = "IP: 192.168.1.1";
        assert!(builder.is_network_present(text));
    }

    // ===== Batch Validation Tests =====

    #[test]
    fn test_detect_batch() {
        let builder = NetworkIdentifierBuilder::new();
        let inputs = vec![
            "550e8400-e29b-41d4-a716-446655440000", // UUID
            "192.168.1.1",                          // IP
            "00:1B:44:11:3A:B7",                    // MAC
            "!!!",                                  // Invalid
        ];

        let results = builder.detect_batch(&inputs);

        assert_eq!(results.len(), 4);
        assert_eq!(results[0].1, Some(IdentifierType::Uuid));
        assert_eq!(results[1].1, Some(IdentifierType::IpAddress));
        assert_eq!(results[2].1, Some(IdentifierType::MacAddress));
        assert_eq!(results[3].1, None);
    }

    #[test]
    fn test_validate_batch_as() {
        let builder = NetworkIdentifierBuilder::new();
        let ips = vec!["192.168.1.1", "10.0.0.1", "not-an-ip", "172.16.0.1"];

        let results = builder.validate_batch_as(&ips, IdentifierType::IpAddress);

        assert_eq!(results.len(), 4);
        assert!(results[0].1); // Valid IP
        assert!(results[1].1); // Valid IP
        assert!(!results[2].1); // Invalid
        assert!(results[3].1); // Valid IP
    }

    #[test]
    fn test_validate_batch_as_wrong_type() {
        let builder = NetworkIdentifierBuilder::new();
        let mixed = vec!["192.168.1.1", "550e8400-e29b-41d4-a716-446655440000"];

        // Validate as UUIDs - only second should match
        let results = builder.validate_batch_as(&mixed, IdentifierType::Uuid);

        assert_eq!(results.len(), 2);
        assert!(!results[0].1); // IP, not UUID
        assert!(results[1].1); // UUID
    }

    #[test]
    fn test_filter_valid_identifiers() {
        let builder = NetworkIdentifierBuilder::new();
        let mixed = vec![
            "550e8400-e29b-41d4-a716-446655440000", // UUID
            "!!!",
            "192.168.1.1", // IP
            "@@@",
            "00:1B:44:11:3A:B7", // MAC
        ];

        let valid = builder.filter_valid_identifiers(&mixed);

        assert_eq!(valid.len(), 3);
        assert!(valid.contains(&"550e8400-e29b-41d4-a716-446655440000"));
        assert!(valid.contains(&"192.168.1.1"));
        assert!(valid.contains(&"00:1B:44:11:3A:B7"));
    }

    #[test]
    fn test_filter_valid_identifiers_empty() {
        let builder = NetworkIdentifierBuilder::new();
        let all_invalid = vec!["!!!", "@@@", "###"];

        let valid = builder.filter_valid_identifiers(&all_invalid);

        assert_eq!(valid.len(), 0);
    }

    #[test]
    fn test_count_by_type() {
        let builder = NetworkIdentifierBuilder::new();
        let values = vec![
            "550e8400-e29b-41d4-a716-446655440000", // UUID
            "192.168.1.1",                          // IP
            "192.168.1.2",                          // IP
            "00:1B:44:11:3A:B7",                    // MAC
            "https://example.com",                  // URL
            "https://test.com",                     // URL
            "https://demo.com",                     // URL
            "!!!",                                  // Invalid
        ];

        let counts = builder.count_by_type(&values);

        assert_eq!(counts.get(&IdentifierType::Uuid), Some(&1));
        assert_eq!(counts.get(&IdentifierType::IpAddress), Some(&2));
        assert_eq!(counts.get(&IdentifierType::MacAddress), Some(&1));
        assert_eq!(counts.get(&IdentifierType::Url), Some(&3));
        assert_eq!(counts.len(), 4); // 4 different types
    }

    #[test]
    fn test_count_by_type_empty() {
        let builder = NetworkIdentifierBuilder::new();
        let empty: Vec<&str> = vec![];

        let counts = builder.count_by_type(&empty);

        assert_eq!(counts.len(), 0);
    }

    #[test]
    fn test_partition_identifiers() {
        let builder = NetworkIdentifierBuilder::new();
        let mixed = vec![
            "192.168.1.1",
            "!!!",
            "10.0.0.1",
            "@@@",
            "550e8400-e29b-41d4-a716-446655440000",
        ];

        let (valid, invalid) = builder.partition_identifiers(&mixed);

        assert_eq!(valid.len(), 3);
        assert_eq!(invalid.len(), 2);
        assert!(valid.contains(&"192.168.1.1"));
        assert!(valid.contains(&"10.0.0.1"));
        assert!(valid.contains(&"550e8400-e29b-41d4-a716-446655440000"));
        assert!(invalid.contains(&"!!!"));
        assert!(invalid.contains(&"@@@"));
    }

    #[test]
    fn test_partition_identifiers_all_valid() {
        let builder = NetworkIdentifierBuilder::new();
        let all_valid = vec!["192.168.1.1", "10.0.0.1", "172.16.0.1"];

        let (valid, invalid) = builder.partition_identifiers(&all_valid);

        assert_eq!(valid.len(), 3);
        assert_eq!(invalid.len(), 0);
    }

    #[test]
    fn test_partition_identifiers_all_invalid() {
        let builder = NetworkIdentifierBuilder::new();
        let all_invalid = vec!["!!!", "@@@", "###"];

        let (valid, invalid) = builder.partition_identifiers(&all_invalid);

        assert_eq!(valid.len(), 0);
        assert_eq!(invalid.len(), 3);
    }

    #[test]
    fn test_batch_methods_preserve_order() {
        let builder = NetworkIdentifierBuilder::new();
        let inputs = vec!["!!!", "192.168.1.1", "@@@", "10.0.0.1", "###"];

        let results = builder.detect_batch(&inputs);

        // Results should be in same order as input
        assert_eq!(results[0].0, "!!!");
        assert_eq!(results[1].0, "192.168.1.1");
        assert_eq!(results[2].0, "@@@");
        assert_eq!(results[3].0, "10.0.0.1");
        assert_eq!(results[4].0, "###");
    }

    #[test]
    fn test_batch_large_dataset() {
        let builder = NetworkIdentifierBuilder::new();

        // Create 100 IP addresses
        let ips: Vec<String> = (1..=100).map(|i| format!("192.168.1.{}", i)).collect();
        let ip_refs: Vec<&str> = ips.iter().map(|s| s.as_str()).collect();

        let results = builder.detect_batch(&ip_refs);

        assert_eq!(results.len(), 100);
        assert!(results.iter().all(|(_, r)| r.is_some()));
    }
}

//! Common sanitization utilities and aggregate functions
//!
//! Provides aggregate redaction functions that span multiple network identifier types.

use super::super::redaction::TextRedactionPolicy;

use super::{
    redact_api_keys_in_text, redact_ips_in_text, redact_macs_in_text, redact_urls_in_text,
    redact_uuids_in_text,
};

// ============================================================================
// Aggregate Redaction Functions
// ============================================================================

/// Redact all network identifiers in text
///
/// Applies all network redaction functions sequentially.
///
/// # Arguments
/// * `text` - The text to scan and redact
/// * `policy` - Redaction policy to apply
#[must_use]
pub fn redact_all_network_in_text(text: &str, policy: TextRedactionPolicy) -> String {
    let result = redact_uuids_in_text(text, policy);
    let result = redact_ips_in_text(&result, policy);
    let result = redact_macs_in_text(&result, policy);
    let result = redact_urls_in_text(&result, policy);
    let result = redact_api_keys_in_text(&result, policy);

    result.into_owned()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_redact_all_network() {
        let text = "UUID: 550e8400-e29b-41d4-a716-446655440000, IP: 192.168.1.1";
        let result = redact_all_network_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[UUID]"));
        assert!(result.contains("[IP_ADDRESS]"));
    }

    #[test]
    fn test_no_redaction_in_clean_text() {
        let text = "This text contains no network identifiers";
        let result = redact_all_network_in_text(text, TextRedactionPolicy::Complete);
        assert_eq!(result, text);
    }

    #[test]
    fn test_empty_input() {
        assert_eq!(
            redact_all_network_in_text("", TextRedactionPolicy::Complete),
            ""
        );
    }
}

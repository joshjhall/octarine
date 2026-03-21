//! MAC address redaction functions
//!
//! Redaction for hardware/MAC addresses.

use super::super::detection;
use super::super::redaction::{MacRedactionStrategy, TextRedactionPolicy};
use crate::primitives::data::tokens::RedactionTokenCore;
use std::borrow::Cow;

// ============================================================================
// Individual Redaction
// ============================================================================

/// Redact a single MAC address with explicit strategy
///
/// Uses detection to verify input is a valid MAC address before redacting.
///
/// # Arguments
/// * `mac` - The MAC address to redact
/// * `strategy` - How to redact the MAC address
#[must_use]
pub fn redact_mac_with_strategy(mac: &str, strategy: MacRedactionStrategy) -> String {
    if matches!(strategy, MacRedactionStrategy::Skip) {
        return mac.to_string();
    }

    // For invalid input, still redact but use simplified strategy
    if !detection::is_mac_address(mac) {
        return match strategy {
            MacRedactionStrategy::Skip => mac.to_string(),
            MacRedactionStrategy::ShowVendor
            | MacRedactionStrategy::Mask
            | MacRedactionStrategy::Token => RedactionTokenCore::MacAddress.into(),
            MacRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
            MacRedactionStrategy::Asterisks => "*".repeat(mac.len()),
            MacRedactionStrategy::Hashes => "#".repeat(mac.len()),
        };
    }

    match strategy {
        MacRedactionStrategy::Skip => mac.to_string(),
        MacRedactionStrategy::ShowVendor | MacRedactionStrategy::Mask => {
            // Show vendor ID (OUI - first 3 bytes)
            if mac.contains(':') {
                let parts: Vec<&str> = mac.split(':').collect();
                if parts.len() == 6
                    && let (Some(&p0), Some(&p1), Some(&p2)) =
                        (parts.first(), parts.get(1), parts.get(2))
                {
                    return format!("{}:{}:{}:***:***:***", p0, p1, p2);
                }
            } else if mac.contains('-') {
                let parts: Vec<&str> = mac.split('-').collect();
                if parts.len() == 6
                    && let (Some(&p0), Some(&p1), Some(&p2)) =
                        (parts.first(), parts.get(1), parts.get(2))
                {
                    return format!("{}-{}-{}:***:***:***", p0, p1, p2);
                }
            } else if mac.contains('.') {
                // Cisco format: 001B.4411.3AB7
                let parts: Vec<&str> = mac.split('.').collect();
                if parts.len() == 3
                    && let Some(&first) = parts.first()
                {
                    return format!("{}.****.*****", first);
                }
            }
            RedactionTokenCore::MacAddress.into()
        }
        MacRedactionStrategy::Token => RedactionTokenCore::MacAddress.into(),
        MacRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        MacRedactionStrategy::Asterisks => "*".repeat(mac.len()),
        MacRedactionStrategy::Hashes => "#".repeat(mac.len()),
    }
}

// ============================================================================
// Text Redaction
// ============================================================================

/// Redact all MAC addresses in text
///
/// Uses detection layer for ReDoS protection and accurate matching.
///
/// # Arguments
/// * `text` - The text to scan and redact
/// * `policy` - Redaction policy to apply
#[must_use]
pub fn redact_macs_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_mac_strategy();
    if matches!(strategy, MacRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let matches = detection::find_mac_addresses_in_text(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();
    for m in matches.iter().rev() {
        let redacted = redact_mac_with_strategy(&m.matched_text, strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_redact_mac_with_strategy_token() {
        assert_eq!(
            redact_mac_with_strategy("00:1B:44:11:3A:B7", MacRedactionStrategy::Token),
            "[MAC_ADDRESS]"
        );
    }

    #[test]
    fn test_redact_mac_with_strategy_show_vendor() {
        assert_eq!(
            redact_mac_with_strategy("00:1B:44:11:3A:B7", MacRedactionStrategy::ShowVendor),
            "00:1B:44:***:***:***"
        );
    }

    #[test]
    fn test_redact_mac_with_strategy_mask() {
        assert_eq!(
            redact_mac_with_strategy("00:1B:44:11:3A:B7", MacRedactionStrategy::Mask),
            "00:1B:44:***:***:***"
        );
        assert_eq!(
            redact_mac_with_strategy("00-1B-44-11-3A-B7", MacRedactionStrategy::Mask),
            "00-1B-44:***:***:***"
        );
    }

    #[test]
    fn test_redact_macs_in_text() {
        let text = "MAC: 00:1B:44:11:3A:B7";
        let result = redact_macs_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[MAC_ADDRESS]"));
        assert!(!result.contains("00:1B:44"));
    }
}

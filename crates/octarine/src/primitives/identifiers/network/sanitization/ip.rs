//! IP address redaction functions
//!
//! Redaction for IPv4 and IPv6 addresses.

use super::super::detection;
use super::super::redaction::{IpRedactionStrategy, TextRedactionPolicy};
use crate::primitives::data::tokens::RedactionTokenCore;
use std::borrow::Cow;

// ============================================================================
// Individual Redaction
// ============================================================================

/// Redact a single IP address with explicit strategy
///
/// Uses detection to verify input is a valid IP before redacting.
///
/// # Arguments
/// * `ip` - The IP address to redact
/// * `strategy` - How to redact the IP
#[must_use]
pub fn redact_ip_with_strategy(ip: &str, strategy: IpRedactionStrategy) -> String {
    if matches!(strategy, IpRedactionStrategy::Skip) {
        return ip.to_string();
    }

    // For invalid input, still redact but use simplified strategy
    if !detection::is_ip_address(ip) {
        return match strategy {
            IpRedactionStrategy::Skip => ip.to_string(),
            IpRedactionStrategy::ShowFirstOctet
            | IpRedactionStrategy::ShowSubnet
            | IpRedactionStrategy::ShowType
            | IpRedactionStrategy::Mask
            | IpRedactionStrategy::Token => RedactionTokenCore::IpAddress.into(),
            IpRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
            IpRedactionStrategy::Asterisks => "*".repeat(ip.len()),
            IpRedactionStrategy::Hashes => "#".repeat(ip.len()),
        };
    }

    let is_ipv4 = detection::is_ipv4(ip);
    let is_ipv6 = detection::is_ipv6(ip);

    match strategy {
        IpRedactionStrategy::Skip => ip.to_string(),
        IpRedactionStrategy::ShowFirstOctet => {
            if is_ipv4 {
                let parts: Vec<&str> = ip.split('.').collect();
                if let Some(&first) = parts.first() {
                    format!("{}.***.***.***", first)
                } else {
                    RedactionTokenCore::IpAddress.into()
                }
            } else if is_ipv6 {
                // IPv6: show first segment
                let parts: Vec<&str> = ip.split(':').collect();
                if let Some(&first) = parts.first() {
                    format!("{}:****:****:****:****:****:****:****", first)
                } else {
                    RedactionTokenCore::IpAddress.into()
                }
            } else {
                RedactionTokenCore::IpAddress.into()
            }
        }
        IpRedactionStrategy::ShowSubnet => {
            if is_ipv4 {
                let parts: Vec<&str> = ip.split('.').collect();
                if let (Some(p0), Some(p1)) = (parts.first(), parts.get(1)) {
                    format!("{}.{}.***", p0, p1)
                } else {
                    RedactionTokenCore::IpAddress.into()
                }
            } else if is_ipv6 {
                let parts: Vec<&str> = ip.split(':').collect();
                if let (Some(p0), Some(p1)) = (parts.first(), parts.get(1)) {
                    format!("{}:{}:****:****:****:****:****:****", p0, p1)
                } else {
                    RedactionTokenCore::IpAddress.into()
                }
            } else {
                RedactionTokenCore::IpAddress.into()
            }
        }
        IpRedactionStrategy::ShowType => {
            if is_ipv4 {
                "[IPv4]".to_string()
            } else if is_ipv6 {
                "[IPv6]".to_string()
            } else {
                RedactionTokenCore::IpAddress.into()
            }
        }
        IpRedactionStrategy::Mask => {
            // Delegate to internal mask helpers
            if is_ipv4 {
                mask_ipv4_internal(ip)
            } else if is_ipv6 {
                mask_ipv6_internal(ip)
            } else {
                RedactionTokenCore::IpAddress.into()
            }
        }
        IpRedactionStrategy::Token => RedactionTokenCore::IpAddress.into(),
        IpRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        IpRedactionStrategy::Asterisks => "*".repeat(ip.len()),
        IpRedactionStrategy::Hashes => "#".repeat(ip.len()),
    }
}

// ============================================================================
// Text Redaction
// ============================================================================

/// Redact all IP addresses in text
///
/// Uses detection layer for ReDoS protection and accurate matching.
///
/// # Arguments
/// * `text` - The text to scan and redact
/// * `policy` - Redaction policy to apply
#[must_use]
pub fn redact_ips_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_ip_strategy();
    if matches!(strategy, IpRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let matches = detection::find_ip_addresses_in_text(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();
    for m in matches.iter().rev() {
        let redacted = redact_ip_with_strategy(&m.matched_text, strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

// ============================================================================
// Internal Mask Helpers (used by redact_ip_with_strategy)
// ============================================================================

/// Internal: Mask IPv4 address (show first octet)
fn mask_ipv4_internal(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        if let Some(&first) = parts.first() {
            format!("{}.***.***.***", first)
        } else {
            RedactionTokenCore::IpAddress.into()
        }
    } else {
        RedactionTokenCore::IpAddress.into()
    }
}

/// Internal: Mask IPv6 address (show first segment)
fn mask_ipv6_internal(ip: &str) -> String {
    if ip == "::1" || ip == "::" {
        return ip.to_string(); // Localhost, not sensitive
    }

    let parts: Vec<&str> = ip.split(':').collect();
    if parts.len() >= 2 {
        if let Some(&first) = parts.first() {
            format!("{}:****:****:****:****:****:****:****", first)
        } else {
            RedactionTokenCore::IpAddress.into()
        }
    } else {
        RedactionTokenCore::IpAddress.into()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_redact_ip_with_strategy_token() {
        assert_eq!(
            redact_ip_with_strategy("192.168.1.1", IpRedactionStrategy::Token),
            "[IP_ADDRESS]"
        );
    }

    #[test]
    fn test_redact_ip_with_strategy_show_first_octet() {
        assert_eq!(
            redact_ip_with_strategy("192.168.1.1", IpRedactionStrategy::ShowFirstOctet),
            "192.***.***.***"
        );
    }

    #[test]
    fn test_redact_ip_with_strategy_show_subnet() {
        assert_eq!(
            redact_ip_with_strategy("192.168.1.1", IpRedactionStrategy::ShowSubnet),
            "192.168.***"
        );
    }

    #[test]
    fn test_redact_ip_with_strategy_show_type() {
        assert_eq!(
            redact_ip_with_strategy("192.168.1.1", IpRedactionStrategy::ShowType),
            "[IPv4]"
        );
        assert_eq!(
            redact_ip_with_strategy("2001:0db8::1", IpRedactionStrategy::ShowType),
            "[IPv6]"
        );
    }

    #[test]
    fn test_redact_ip_with_strategy_mask() {
        assert_eq!(
            redact_ip_with_strategy("192.168.1.1", IpRedactionStrategy::Mask),
            "192.***.***.***"
        );
        assert_eq!(
            redact_ip_with_strategy(
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                IpRedactionStrategy::Mask
            ),
            "2001:****:****:****:****:****:****:****"
        );
        assert_eq!(
            redact_ip_with_strategy("::1", IpRedactionStrategy::Mask),
            "::1"
        ); // Localhost not masked
    }

    #[test]
    fn test_redact_ips_in_text() {
        let text = "Server: 192.168.1.1";
        let result = redact_ips_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[IP_ADDRESS]"));
        assert!(!result.contains("192.168.1.1"));
    }
}

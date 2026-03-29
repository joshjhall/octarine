//! MAC address detection functions
//!
//! Detection for hardware/Ethernet MAC addresses in various formats.

use super::super::super::common::patterns;
use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};

use super::common::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

// ============================================================================
// Single-Value Detection
// ============================================================================

/// Check if value is a MAC address (any format)
///
/// Supports:
/// - Colon format: 00:11:22:33:44:55
/// - Hyphen format: 00-11-22-33-44-55
/// - Dot format: 0011.2233.4455
#[must_use]
pub fn is_mac_address(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::MAC_COLON.is_match(trimmed)
        || patterns::network::MAC_HYPHEN.is_match(trimmed)
        || patterns::network::MAC_DOT.is_match(trimmed)
}

// ============================================================================
// Text Scanning
// ============================================================================

/// Find all MAC addresses in text
#[must_use]
pub fn find_mac_addresses_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for pattern in patterns::network::macs() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::MacAddress,
                DetectionConfidence::High,
            ));
        }
    }
    deduplicate_matches(matches)
}

// ============================================================================
// Test Data Detection
// ============================================================================

/// Check if MAC address is a known test/special address
///
/// Detects:
/// - Broadcast address (FF:FF:FF:FF:FF:FF)
/// - Null address (00:00:00:00:00:00)
/// - Multicast addresses (LSB of first octet is 1)
/// - Locally administered addresses (second LSB of first octet is 1)
/// - Common virtualization prefixes (VMware, VirtualBox, Xen, etc.)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::detection::is_test_mac;
///
/// assert!(is_test_mac("FF:FF:FF:FF:FF:FF")); // Broadcast
/// assert!(is_test_mac("00:00:00:00:00:00")); // Null
/// assert!(is_test_mac("08:00:27:12:34:56")); // VirtualBox
/// assert!(!is_test_mac("00:1B:44:11:3A:B7")); // Regular MAC
/// ```
#[must_use]
pub fn is_test_mac(mac: &str) -> bool {
    // Normalize: remove separators, uppercase
    let normalized: String = mac
        .to_uppercase()
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();

    if normalized.len() != 12 {
        return false;
    }

    // Broadcast
    if normalized == "FFFFFFFFFFFF" {
        return true;
    }

    // Null
    if normalized == "000000000000" {
        return true;
    }

    // Parse first octet to check flags
    if let Ok(first_octet) = u8::from_str_radix(&normalized[0..2], 16) {
        // Multicast (LSB of first octet is 1)
        if first_octet & 0x01 != 0 {
            return true;
        }
        // Locally administered (second LSB of first octet is 1)
        if first_octet & 0x02 != 0 {
            return true;
        }
    }

    // Known virtualization OUI prefixes
    let vm_prefixes = [
        "080027", // Oracle VirtualBox
        "000569", // VMware
        "000C29", // VMware
        "005056", // VMware
        "001C14", // VMware
        "00163E", // Xen
        "001DD8", // Microsoft Hyper-V
        "00155D", // Microsoft Hyper-V
        "525400", // QEMU/KVM (locally administered)
        "DEADBE", // Common test pattern
        "CAFEBA", // Common test pattern
        "123456", // Sequential test
        "AABBCC", // Pattern test
    ];

    for prefix in &vm_prefixes {
        if normalized.starts_with(prefix) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_mac_address() {
        // Colon format
        assert!(is_mac_address("00:11:22:33:44:55"));
        assert!(is_mac_address("AA:BB:CC:DD:EE:FF"));
        // Hyphen format
        assert!(is_mac_address("00-11-22-33-44-55"));
        // Dot format
        assert!(is_mac_address("0011.2233.4455"));
        // Invalid
        assert!(!is_mac_address("not-a-mac"));
        assert!(!is_mac_address("00:11:22:33:44")); // incomplete
    }

    #[test]
    fn test_find_mac_addresses_in_text() {
        let text = "Device MAC: 00:11:22:33:44:55 and 66-77-88-99-AA-BB";
        let matches = find_mac_addresses_in_text(text);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_is_test_mac() {
        // Broadcast
        assert!(is_test_mac("FF:FF:FF:FF:FF:FF"));
        // Null
        assert!(is_test_mac("00:00:00:00:00:00"));
        // VirtualBox
        assert!(is_test_mac("08:00:27:12:34:56"));
        // VMware
        assert!(is_test_mac("00:0C:29:12:34:56"));
        // Test patterns
        assert!(is_test_mac("DE:AD:BE:EF:12:34"));
        // Regular MAC - NOT test
        assert!(!is_test_mac("00:1B:44:11:3A:B7"));
    }
}

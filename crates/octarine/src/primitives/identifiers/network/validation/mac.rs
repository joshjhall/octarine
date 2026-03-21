//! MAC address validation functions
//!
//! Pure validation functions for MAC address identifiers.
//!
//! # Usage
//!
//! For bool checks, use detection layer's `is_mac_address()`, or call
//! `validate_mac_address().is_ok()` for validation-level checks.

use super::super::detection::is_mac_address;
use crate::primitives::Problem;

// ============================================================================
// MAC Address Validation
// ============================================================================

/// Validate MAC address format
///
/// Validates format and rejects special addresses (broadcast, null).
///
/// # Examples
///
/// ```ignore
/// // Result-based validation
/// validate_mac_address("00:1B:44:11:3A:B7")?;
///
/// // Bool check using .is_ok()
/// if validate_mac_address("00:1B:44:11:3A:B7").is_ok() {
///     println!("Valid MAC address!");
/// }
/// ```
pub fn validate_mac_address(mac: &str) -> Result<(), Problem> {
    if !is_mac_address(mac) {
        return Err(Problem::Validation("Invalid MAC address format".into()));
    }

    // Check for special MAC addresses
    let normalized = mac.replace([':', '-', '.'], "").to_uppercase();

    // Broadcast MAC
    if normalized == "FFFFFFFFFFFF" {
        return Err(Problem::Validation(
            "Broadcast MAC address not allowed".into(),
        ));
    }

    // Null MAC
    if normalized == "000000000000" {
        return Err(Problem::Validation("Null MAC address not allowed".into()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_validate_mac_address() {
        assert!(validate_mac_address("00:1B:44:11:3A:B7").is_ok());
        assert!(validate_mac_address("00-1B-44-11-3A-B7").is_ok());
        assert!(validate_mac_address("001B.4411.3AB7").is_ok());
        assert!(validate_mac_address("not-a-mac").is_err());
    }

    #[test]
    fn test_validate_mac_address_broadcast() {
        assert!(validate_mac_address("FF:FF:FF:FF:FF:FF").is_err());
        assert!(validate_mac_address("ff-ff-ff-ff-ff-ff").is_err());
    }

    #[test]
    fn test_validate_mac_address_null() {
        assert!(validate_mac_address("00:00:00:00:00:00").is_err());
        assert!(validate_mac_address("00-00-00-00-00-00").is_err());
    }

    // ============================================================================
    // Adversarial and Property-Based Tests
    // ============================================================================

    use proptest::prelude::*;

    #[test]
    fn test_adversarial_mac_separator_confusion() {
        // Valid MAC with colon separator
        assert!(validate_mac_address("00:11:22:33:44:55").is_ok());

        // Valid MAC with hyphen separator
        assert!(validate_mac_address("00-11-22-33-44-55").is_ok());

        // Valid MAC with dot separator (Cisco style)
        assert!(validate_mac_address("0011.2233.4455").is_ok());

        // Test edge cases - detection behavior may vary
        let _ = validate_mac_address("00:11-22:33-44:55"); // Mixed separators
        let _ = validate_mac_address("001122334455"); // No separators
    }

    #[test]
    fn test_adversarial_mac_special_addresses() {
        // Broadcast MAC (should be rejected)
        assert!(validate_mac_address("FF:FF:FF:FF:FF:FF").is_err());
        assert!(validate_mac_address("ff:ff:ff:ff:ff:ff").is_err());

        // Null MAC (should be rejected)
        assert!(validate_mac_address("00:00:00:00:00:00").is_err());

        // Normal MAC (should pass)
        assert!(validate_mac_address("00:11:22:33:44:55").is_ok());
    }

    #[test]
    fn test_adversarial_mac_case_mixing() {
        // All lowercase (valid)
        assert!(validate_mac_address("aa:bb:cc:dd:ee:ff").is_ok());

        // All uppercase (valid)
        assert!(validate_mac_address("AA:BB:CC:DD:EE:FF").is_ok());

        // Mixed case (valid)
        assert!(validate_mac_address("Aa:Bb:Cc:Dd:Ee:Ff").is_ok());
        assert!(validate_mac_address("aA:bB:cC:dD:eE:fF").is_ok());
    }

    proptest! {

        #[test]
        fn prop_no_panic_mac_validation(s in "\\PC*") {
            let _ = validate_mac_address(&s);
        }

        #[test]
        fn prop_mac_format_consistency(
            a in 0u8..=255, b in 0u8..=255, c in 0u8..=255,
            d in 0u8..=255, e in 0u8..=255, f in 0u8..=255
        ) {
            // All three valid MAC formats should validate
            let colon = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", a, b, c, d, e, f);
            let hyphen = format!("{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}", a, b, c, d, e, f);
            let dot = format!("{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}", a, b, c, d, e, f);

            assert!(validate_mac_address(&colon).is_ok(), "Colon format invalid: {}", colon);
            assert!(validate_mac_address(&hyphen).is_ok(), "Hyphen format invalid: {}", hyphen);
            assert!(validate_mac_address(&dot).is_ok(), "Dot format invalid: {}", dot);
        }
    }
}

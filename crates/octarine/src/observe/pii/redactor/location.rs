//! Location data redaction functions
//!
//! Redacts GPS coordinates, addresses, and postal codes.

use super::super::config::RedactionProfile;
use crate::primitives::identifiers::{LocationIdentifierBuilder, LocationTextPolicy};

/// Get location text redaction policy from profile
fn policy_from_profile(profile: RedactionProfile) -> LocationTextPolicy {
    match profile {
        RedactionProfile::ProductionStrict => LocationTextPolicy::Complete,
        RedactionProfile::ProductionLenient => LocationTextPolicy::Partial,
        RedactionProfile::Development => LocationTextPolicy::Partial,
        RedactionProfile::Testing => LocationTextPolicy::Skip,
    }
}

/// Redact GPS coordinates based on profile
pub(super) fn redact_gps_coordinates(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = LocationIdentifierBuilder::new();
            let policy = policy_from_profile(profile);
            builder
                .redact_gps_coordinates_in_text_with_strategy(text, policy)
                .into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact addresses based on profile
pub(super) fn redact_addresses(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = LocationIdentifierBuilder::new();
            let policy = policy_from_profile(profile);
            builder
                .redact_addresses_in_text_with_strategy(text, policy)
                .into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact postal codes based on profile
pub(super) fn redact_postal_codes(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = LocationIdentifierBuilder::new();
            let policy = policy_from_profile(profile);
            builder
                .redact_postal_codes_in_text_with_strategy(text, policy)
                .into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // ===== GPS Coordinates =====

    #[test]
    fn test_redact_gps_coordinates_strict() {
        let text = "Location: 40.7128, -74.0060";
        let result = redact_gps_coordinates(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[GPS_COORDINATE]"));
        assert!(!result.contains("40.7128"));
    }

    #[test]
    fn test_redact_gps_coordinates_testing_unchanged() {
        let text = "Location: 40.7128, -74.0060";
        let result = redact_gps_coordinates(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_gps_coordinates_no_pii() {
        let text = "GPS signal acquired";
        let result = redact_gps_coordinates(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    // ===== Addresses =====

    #[test]
    fn test_redact_addresses_strict() {
        let text = "Ship to: 123 Main Street";
        let result = redact_addresses(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[ADDRESS]"));
        assert!(!result.contains("123 Main Street"));
    }

    #[test]
    fn test_redact_addresses_testing_unchanged() {
        let text = "Ship to: 123 Main Street";
        let result = redact_addresses(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_addresses_no_pii() {
        let text = "Address verification complete";
        let result = redact_addresses(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    // ===== Postal Codes =====

    #[test]
    fn test_redact_postal_codes_strict() {
        let text = "ZIP: 10001";
        let result = redact_postal_codes(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[POSTAL_CODE]"));
        assert!(!result.contains("10001"));
    }

    #[test]
    fn test_redact_postal_codes_testing_unchanged() {
        let text = "ZIP: 10001";
        let result = redact_postal_codes(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_postal_codes_no_pii() {
        let text = "Postal service notification";
        let result = redact_postal_codes(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }
}

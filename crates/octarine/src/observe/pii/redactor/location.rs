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

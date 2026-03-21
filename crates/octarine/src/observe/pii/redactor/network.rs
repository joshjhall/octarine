//! Network identifier redaction functions
//!
//! Redacts MAC addresses, UUIDs, URLs, and domains.

use super::super::config::RedactionProfile;
use crate::primitives::identifiers::NetworkIdentifierBuilder;

/// Redact MAC addresses based on profile
pub(super) fn redact_mac_addresses(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = NetworkIdentifierBuilder::new();
            builder.redact_macs_in_text(text).into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact UUIDs based on profile
pub(super) fn redact_uuids(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = NetworkIdentifierBuilder::new();
            builder.redact_uuids_in_text(text).into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact URLs and domains based on profile
pub(super) fn redact_urls(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = NetworkIdentifierBuilder::new();
            builder.redact_urls_in_text(text).into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

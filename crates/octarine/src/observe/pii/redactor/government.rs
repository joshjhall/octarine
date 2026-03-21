//! Government ID redaction functions
//!
//! Redacts SSNs, driver licenses, passports, VINs, EINs, and Tax IDs.

use super::super::config::RedactionProfile;
use crate::primitives::identifiers::{
    DriverLicenseRedactionStrategy, GovernmentIdentifierBuilder, GovernmentTextPolicy,
    PassportRedactionStrategy,
};

/// Redact SSNs based on profile using primitives
pub(super) fn redact_ssns(text: &str, profile: RedactionProfile) -> String {
    let strategy = profile.ssn_strategy();
    let builder = GovernmentIdentifierBuilder::new();
    builder.redact_ssns_in_text_with_strategy(text, strategy)
}

/// Redact driver licenses based on profile
pub(super) fn redact_driver_licenses(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = GovernmentIdentifierBuilder::new();
            builder.redact_driver_licenses_in_text_with_strategy(
                text,
                DriverLicenseRedactionStrategy::Token,
            )
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact passports based on profile
pub(super) fn redact_passports(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = GovernmentIdentifierBuilder::new();
            builder.redact_passports_in_text_with_strategy(text, PassportRedactionStrategy::Token)
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact generic government IDs (VIN, EIN, Tax IDs) based on profile
pub(super) fn redact_government_ids(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = GovernmentIdentifierBuilder::new();
            // Redact all government IDs in the text using Complete policy
            builder.redact_all_in_text_with_policy(text, GovernmentTextPolicy::Complete)
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

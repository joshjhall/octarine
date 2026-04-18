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
            builder.redact_all_in_text_with_policy(text, GovernmentTextPolicy::Complete)
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    // ===== Driver Licenses =====

    #[test]
    fn test_redact_driver_licenses_strict() {
        let text = "DL# A1234567";
        let result = redact_driver_licenses(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[DRIVER_LICENSE]"));
        assert!(!result.contains("A1234567"));
    }

    #[test]
    fn test_redact_driver_licenses_testing_unchanged() {
        let text = "DL# A1234567";
        let result = redact_driver_licenses(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_driver_licenses_no_pii() {
        let text = "Driver license renewed successfully";
        let result = redact_driver_licenses(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    // ===== Passports =====

    #[test]
    fn test_redact_passports_strict() {
        let text = "Passport: 123456789";
        let result = redact_passports(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[PASSPORT]"));
        assert!(!result.contains("123456789"));
    }

    #[test]
    fn test_redact_passports_testing_unchanged() {
        let text = "Passport: 123456789";
        let result = redact_passports(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_passports_no_pii() {
        let text = "Passport application submitted";
        let result = redact_passports(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    // ===== Government IDs (VIN/EIN) =====

    #[test]
    fn test_redact_government_ids_vin_strict() {
        let text = "VIN: 1HGBH41JXMN109186";
        let result = redact_government_ids(text, RedactionProfile::ProductionStrict);
        assert!(result.contains("[VEHICLE_ID]"));
        assert!(!result.contains("1HGBH41JXMN109186"));
    }

    #[test]
    fn test_redact_government_ids_testing_unchanged() {
        let text = "VIN: 1HGBH41JXMN109186";
        let result = redact_government_ids(text, RedactionProfile::Testing);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_government_ids_no_pii() {
        let text = "Vehicle registration complete";
        let result = redact_government_ids(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }
}

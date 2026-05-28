//! Government-issued identifier detection (primitives layer)
//!
//! Pure detection functions for government identifiers with no observe dependencies.
//! Used by observe/pii and security modules.
//!
//! # Supported Identifiers
//!
//! - **SSN**: US Social Security Numbers (XXX-XX-XXXX format)
//! - **Tax IDs**: EIN, TIN, ITIN (IRS identifiers)
//! - **Driver's License**: State-specific formats (CA, TX, etc.)
//! - **Passport**: Federal/State Department issued
//! - **National IDs**: UK NI, Canadian SIN, etc.
//! - **Vehicle IDs**: VIN (17-character NHTSA/ISO format)
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns data, no side effects
//! - Used by observe/pii and security modules
//!
//! # Module Structure
//!
//! Per-country/domain submodules each own their `is_*` and `find_*_in_text`
//! functions plus their tests. This mirrors the sibling `validation/`
//! per-country layout.
//!
//! - `helpers` — shared regex/dedup helpers
//! - `ssn`, `tax_id`, `driver_license`, `passport`, `national_id`,
//!   `vehicle_id` — US/UK/generic identifier types
//! - `australia`, `brazil`, `europe`, `india`, `korea_rrn`, `mexico`,
//!   `nigeria`, `singapore`, `thailand` — country-specific identifiers
//!
//! Top-level dispatchers (`detect_government_identifier`,
//! `is_government_identifier`, `is_government_present`,
//! `find_all_government_ids_in_text`) live in this module because they
//! aggregate across countries.
//!
//! # Detection Types
//!
//! 1. **Single-value detection** (`is_*`): Validate one identifier format
//! 2. **Text scanning** (`find_*_in_text`): Find all matches in documents

use super::super::types::{IdentifierMatch, IdentifierType};

mod australia;
mod brazil;
mod driver_license;
mod europe;
mod helpers;
mod india;
mod korea_brn;
mod korea_driver_license;
mod korea_frn;
mod korea_passport;
mod korea_rrn;
mod mexico;
mod national_id;
mod nigeria;
mod passport;
mod singapore;
mod ssn;
mod tax_id;
mod thailand;
mod vehicle_id;

pub use australia::{
    find_australia_abns_in_text, find_australia_acns_in_text, find_australia_medicares_in_text,
    find_australia_tfns_in_text, is_australia_abn, is_australia_acn, is_australia_medicare,
    is_australia_tfn,
};
pub use brazil::{
    find_brazil_cnpjs_in_text, find_brazil_cpfs_in_text, is_brazil_cnpj, is_brazil_cpf,
};
pub use driver_license::{find_driver_licenses_in_text, is_driver_license};
pub use europe::{
    find_finland_hetus_in_text, find_italy_driver_licenses_in_text,
    find_italy_fiscal_codes_in_text, find_italy_identity_cards_in_text,
    find_italy_passports_in_text, find_italy_vats_in_text, find_poland_pesels_in_text,
    find_spain_nies_in_text, find_spain_nifs_in_text, find_uk_driving_licences_in_text,
    find_uk_nhs_in_text, find_uk_passports_in_text, is_finland_hetu, is_italy_driver_license,
    is_italy_fiscal_code, is_italy_identity_card, is_italy_passport, is_italy_vat, is_poland_pesel,
    is_spain_nie, is_spain_nif, is_uk_driving_licence, is_uk_nhs, is_uk_passport,
};
pub use india::{
    find_india_aadhaars_in_text, find_india_gstins_in_text, find_india_pans_in_text,
    find_india_passports_in_text, find_india_vehicle_registrations_in_text,
    find_india_voter_ids_in_text, is_india_aadhaar, is_india_gstin, is_india_pan,
    is_india_passport, is_india_vehicle_registration, is_india_voter_id,
};
pub use korea_brn::{find_korea_brns_in_text, is_korea_brn};
pub use korea_driver_license::{find_korea_driver_licenses_in_text, is_korea_driver_license};
pub use korea_frn::{find_korea_frns_in_text, is_korea_frn};
pub use korea_passport::{find_korea_passports_in_text, is_korea_passport};
pub use korea_rrn::{find_korea_rrns_in_text, is_korea_rrn};
pub use mexico::{find_mexico_curps_in_text, is_mexico_curp};
pub use national_id::{find_national_ids_in_text, find_uk_nis_in_text, is_national_id, is_uk_ni};
pub use nigeria::{
    find_nigeria_bvns_in_text, find_nigeria_nins_in_text,
    find_nigeria_vehicle_registrations_in_text, is_nigeria_bvn, is_nigeria_nin,
    is_nigeria_vehicle_registration,
};
pub use passport::{find_passports_in_text, is_passport};
pub use singapore::{
    find_singapore_nrics_in_text, find_singapore_uens_in_text, is_singapore_nric, is_singapore_uen,
};
pub use ssn::{find_ssns_in_text, is_ssn};
pub use tax_id::{find_eins_in_text, find_tax_ids_in_text, is_ein, is_tax_id};
pub use thailand::{find_thailand_tnins_in_text, is_thailand_tnin};
pub use vehicle_id::{find_vehicle_ids_in_text, is_vehicle_id};

/// Detect which type of government identifier a value is
///
/// Returns the specific identifier type if detected, or None if not a government ID.
/// Checks in order: SSN, Tax ID, Driver License, Passport, National ID, Vehicle ID.
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
/// use crate::primitives::identifiers::types::IdentifierType;
///
/// assert_eq!(detection::detect_government_identifier("517-29-8346"), Some(IdentifierType::Ssn));
/// assert_eq!(detection::detect_government_identifier("00-0000001"), Some(IdentifierType::TaxId));
/// assert_eq!(detection::detect_government_identifier("not an id"), None);
/// ```
#[must_use]
#[allow(clippy::cognitive_complexity)]
pub fn detect_government_identifier(value: &str) -> Option<IdentifierType> {
    // Korea-specific checks run BEFORE their generic siblings (driver license,
    // passport) because the generic patterns are looser and would otherwise
    // shadow the dedicated Korean variants. BRN must also come before SSN —
    // BRN's 10-digit shape would otherwise be misclassified as a 9-digit SSN
    // prefix.
    if is_korea_brn(value) {
        Some(IdentifierType::KoreaBrn)
    } else if is_korea_driver_license(value) {
        Some(IdentifierType::KoreaDriverLicense)
    } else if is_korea_passport(value) {
        Some(IdentifierType::KoreaPassport)
    } else if is_korea_rrn(value) {
        Some(IdentifierType::KoreaRrn)
    } else if is_korea_frn(value) {
        Some(IdentifierType::KoreaFrn)
    } else if is_ssn(value) {
        Some(IdentifierType::Ssn)
    } else if is_ein(value) {
        Some(IdentifierType::Ein)
    } else if is_tax_id(value) {
        Some(IdentifierType::TaxId)
    } else if is_driver_license(value) {
        Some(IdentifierType::DriverLicense)
    } else if is_passport(value) {
        Some(IdentifierType::Passport)
    } else if is_australia_tfn(value) {
        Some(IdentifierType::AustraliaTfn)
    } else if is_australia_abn(value) {
        Some(IdentifierType::AustraliaAbn)
    } else if is_australia_acn(value) {
        Some(IdentifierType::AustraliaAcn)
    } else if is_australia_medicare(value) {
        Some(IdentifierType::AustraliaMedicare)
    } else if is_india_aadhaar(value) {
        Some(IdentifierType::IndiaAadhaar)
    } else if is_india_pan(value) {
        Some(IdentifierType::IndiaPan)
    } else if is_brazil_cpf(value) {
        Some(IdentifierType::BrazilCpf)
    } else if is_brazil_cnpj(value) {
        Some(IdentifierType::BrazilCnpj)
    } else if is_mexico_curp(value) {
        Some(IdentifierType::MexicoCurp)
    } else if is_thailand_tnin(value) {
        Some(IdentifierType::ThailandTnin)
    } else if is_nigeria_vehicle_registration(value) {
        Some(IdentifierType::NigeriaVehicleReg)
    } else if is_nigeria_nin(value) {
        // NIN and BVN share the same shape (`\d{11}`). The dispatcher returns
        // NIN for any 11-digit value — callers needing BVN precision should use
        // `find_nigeria_bvns_in_text`, which is label-gated.
        Some(IdentifierType::NigeriaNin)
    } else if is_singapore_nric(value) {
        Some(IdentifierType::SingaporeNric)
    } else if is_singapore_uen(value) {
        Some(IdentifierType::SingaporeUen)
    } else if is_finland_hetu(value) {
        Some(IdentifierType::FinlandHetu)
    } else if is_poland_pesel(value) {
        Some(IdentifierType::PolandPesel)
    } else if is_italy_fiscal_code(value) {
        Some(IdentifierType::ItalyFiscalCode)
    } else if is_spain_nif(value) {
        Some(IdentifierType::SpainNif)
    } else if is_spain_nie(value) {
        Some(IdentifierType::SpainNie)
    } else if is_uk_ni(value) {
        Some(IdentifierType::UkNi)
    } else if is_national_id(value) {
        Some(IdentifierType::NationalId)
    } else if is_vehicle_id(value) {
        Some(IdentifierType::VehicleId)
    } else {
        None
    }
}

/// Check if value is any government identifier
#[must_use]
pub fn is_government_identifier(value: &str) -> bool {
    detect_government_identifier(value).is_some()
}

/// Check if text contains any government identifier
#[must_use]
pub fn is_government_present(text: &str) -> bool {
    !find_all_government_ids_in_text(text).is_empty()
}

/// Find all government-issued ID patterns in text
///
/// Comprehensive scan for all government ID types:
/// - SSN, tax IDs, driver's licenses, passports, national IDs, vehicle IDs
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::detection;
///
/// let text = "SSN: 517-29-8346, VIN: 1HGBH41JXMN109186";
/// let matches = detection::find_all_government_ids_in_text(text);
/// assert!(matches.len() >= 2);
/// ```
#[must_use]
pub fn find_all_government_ids_in_text(text: &str) -> Vec<IdentifierMatch> {
    let mut all_matches = Vec::new();

    all_matches.extend(find_ssns_in_text(text));
    all_matches.extend(find_eins_in_text(text));
    all_matches.extend(find_tax_ids_in_text(text));
    all_matches.extend(find_driver_licenses_in_text(text));
    all_matches.extend(find_passports_in_text(text));
    all_matches.extend(find_korea_rrns_in_text(text));
    all_matches.extend(find_korea_frns_in_text(text));
    all_matches.extend(find_korea_driver_licenses_in_text(text));
    all_matches.extend(find_korea_passports_in_text(text));
    all_matches.extend(find_korea_brns_in_text(text));
    all_matches.extend(find_australia_tfns_in_text(text));
    all_matches.extend(find_australia_abns_in_text(text));
    all_matches.extend(find_australia_acns_in_text(text));
    all_matches.extend(find_australia_medicares_in_text(text));
    all_matches.extend(find_india_aadhaars_in_text(text));
    all_matches.extend(find_india_pans_in_text(text));
    all_matches.extend(find_india_gstins_in_text(text));
    all_matches.extend(find_india_vehicle_registrations_in_text(text));
    all_matches.extend(find_india_voter_ids_in_text(text));
    all_matches.extend(find_india_passports_in_text(text));
    all_matches.extend(find_brazil_cpfs_in_text(text));
    all_matches.extend(find_brazil_cnpjs_in_text(text));
    all_matches.extend(find_mexico_curps_in_text(text));
    all_matches.extend(find_nigeria_nins_in_text(text));
    all_matches.extend(find_nigeria_bvns_in_text(text));
    all_matches.extend(find_nigeria_vehicle_registrations_in_text(text));
    all_matches.extend(find_thailand_tnins_in_text(text));
    all_matches.extend(find_singapore_nrics_in_text(text));
    all_matches.extend(find_singapore_uens_in_text(text));
    all_matches.extend(find_finland_hetus_in_text(text));
    all_matches.extend(find_poland_pesels_in_text(text));
    all_matches.extend(find_italy_fiscal_codes_in_text(text));
    all_matches.extend(find_italy_vats_in_text(text));
    all_matches.extend(find_italy_passports_in_text(text));
    all_matches.extend(find_italy_identity_cards_in_text(text));
    all_matches.extend(find_italy_driver_licenses_in_text(text));
    all_matches.extend(find_spain_nifs_in_text(text));
    all_matches.extend(find_spain_nies_in_text(text));
    all_matches.extend(find_uk_nis_in_text(text));
    all_matches.extend(find_uk_nhs_in_text(text));
    all_matches.extend(find_uk_passports_in_text(text));
    all_matches.extend(find_uk_driving_licences_in_text(text));
    all_matches.extend(find_national_ids_in_text(text));
    all_matches.extend(find_vehicle_ids_in_text(text));

    // Sort by position in text
    all_matches.sort_by_key(|m| m.start);

    all_matches
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_government_identifier() {
        assert!(is_government_identifier("517-29-8346")); // SSN
        assert!(is_government_identifier("00-0000001")); // EIN
        assert!(is_government_identifier("1HGBH41JXMN109186")); // VIN
        assert!(!is_government_identifier("not an id"));
    }

    #[test]
    fn test_detect_government_identifier() {
        assert_eq!(
            detect_government_identifier("517-29-8346"),
            Some(IdentifierType::Ssn)
        );
        assert_eq!(
            detect_government_identifier("00-0000001"),
            Some(IdentifierType::TaxId)
        );
        assert_eq!(
            detect_government_identifier("1HGBH41JXMN109186"),
            Some(IdentifierType::VehicleId)
        );
        assert_eq!(detect_government_identifier("not an id"), None);
    }

    #[test]
    fn test_detect_is_consistency() {
        // Verify: is_government_identifier(x) == detect_government_identifier(x).is_some()
        let test_values = [
            "517-29-8346",       // SSN (valid)
            "00-0000001",        // Tax ID
            "A1234567",          // Driver License
            "C12345678",         // Passport
            "AB123456C",         // National ID
            "1HGBH41JXMN109186", // VIN
            "900115-1234567",    // Korea RRN
            "900115-5234567",    // Korea FRN
            "11-90-123456-78",   // Korea Driver License
            "M12345678",         // Korea Passport
            "123-45-67890",      // Korea BRN
            "not an id",         // Invalid
            "",                  // Empty
        ];

        for value in test_values {
            assert_eq!(
                is_government_identifier(value),
                detect_government_identifier(value).is_some(),
                "Consistency check failed for: {}",
                value
            );
        }
    }

    #[test]
    fn test_detect_korea_extended_identifiers() {
        // Each Korean identifier dispatches to its dedicated variant.
        assert_eq!(
            detect_government_identifier("900115-1234567"),
            Some(IdentifierType::KoreaRrn)
        );
        assert_eq!(
            detect_government_identifier("900115-5234567"),
            Some(IdentifierType::KoreaFrn)
        );
        assert_eq!(
            detect_government_identifier("11-90-123456-78"),
            Some(IdentifierType::KoreaDriverLicense)
        );
        assert_eq!(
            detect_government_identifier("M12345678"),
            Some(IdentifierType::KoreaPassport)
        );
        // BRN must win over SSN because it is checked first in the dispatcher.
        assert_eq!(
            detect_government_identifier("123-45-67890"),
            Some(IdentifierType::KoreaBrn)
        );
    }

    #[test]
    fn test_detect_government_identifier_returns_ein() {
        // Valid EIN goes to Ein, not TaxId
        assert_eq!(
            detect_government_identifier("12-3456789"),
            Some(IdentifierType::Ein)
        );
        // Invalid-prefix tax IDs still fall through to TaxId
        assert_eq!(
            detect_government_identifier("00-0000001"),
            Some(IdentifierType::TaxId)
        );
        // ITINs continue to be TaxId
        assert_eq!(
            detect_government_identifier("912-34-5678"),
            Some(IdentifierType::TaxId)
        );
    }

    #[test]
    fn test_detect_government_identifier_uk_ni() {
        // The dedicated UkNi variant should win over the generic NationalId
        assert_eq!(
            detect_government_identifier("AB123456C"),
            Some(IdentifierType::UkNi)
        );
    }

    #[test]
    fn test_find_all_government_ids() {
        let text = "SSN: 517-29-8346, VIN: 1HGBH41JXMN109186, EIN: 00-0000001";
        let matches = find_all_government_ids_in_text(text);
        assert!(matches.len() >= 3);

        // Verify sorted by position
        for window in matches.windows(2) {
            let [prev, curr] = window else { continue };
            assert!(curr.start >= prev.start);
        }
    }

    #[test]
    fn test_no_matches_in_clean_text() {
        let text = "This text contains no government IDs";
        let matches = find_all_government_ids_in_text(text);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_is_government_present() {
        assert!(is_government_present("SSN: 517-29-8346"));
        assert!(!is_government_present("No government IDs here"));
    }

    #[test]
    fn test_find_all_government_ids_includes_uk_ni() {
        let text = "NI: AB123456C";
        let all = find_all_government_ids_in_text(text);
        assert!(
            all.iter()
                .any(|m| m.identifier_type == IdentifierType::UkNi),
            "expected at least one UkNi match in: {all:?}"
        );
    }
}

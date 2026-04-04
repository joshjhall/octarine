//! Domain-specific PII scanning
//!
//! Uses domain builders from the primitives layer to detect PII.

use super::super::config::PiiScannerConfig;
use super::super::types::PiiType;

// Import domain builders from primitives/identifiers
use crate::primitives::identifiers::{
    BiometricIdentifierBuilder, CredentialIdentifierBuilder, FinancialIdentifierBuilder,
    GovernmentIdentifierBuilder, LocationIdentifierBuilder, MedicalIdentifierBuilder,
    NetworkIdentifierBuilder, OrganizationalIdentifierBuilder, PersonalIdentifierBuilder,
    TokenIdentifierBuilder,
};

/// Scan for personal PII (email, phone, name, birthdate)
pub(super) fn scan_personal(text: &str, pii_types: &mut Vec<PiiType>) {
    let personal = PersonalIdentifierBuilder::new();

    if personal.is_pii_present(text) {
        if !personal.detect_emails_in_text(text).is_empty() {
            pii_types.push(PiiType::Email);
        }
        if !personal.detect_phones_in_text(text).is_empty() {
            pii_types.push(PiiType::Phone);
        }
        if !personal.detect_names_in_text(text).is_empty() {
            pii_types.push(PiiType::Name);
        }
        if !personal.detect_birthdates_in_text(text).is_empty() {
            pii_types.push(PiiType::Birthdate);
        }
    }
}

/// Scan for financial PII (credit card, bank account, routing number)
pub(super) fn scan_financial(text: &str, pii_types: &mut Vec<PiiType>) {
    let financial = FinancialIdentifierBuilder::new();

    if financial.is_financial_present(text) {
        if !financial.detect_credit_cards_in_text(text).is_empty() {
            pii_types.push(PiiType::CreditCard);
        }
        if !financial.detect_bank_accounts_in_text(text).is_empty() {
            pii_types.push(PiiType::BankAccount);
        }
        if !financial.detect_payment_tokens_in_text(text).is_empty() {
            pii_types.push(PiiType::PaymentToken);
        }
    }
}

/// Scan for government IDs (SSN, driver license, passport, tax ID)
pub(super) fn scan_government(text: &str, pii_types: &mut Vec<PiiType>) {
    let government = GovernmentIdentifierBuilder::new();

    if !government.find_ssns_in_text(text).is_empty() {
        pii_types.push(PiiType::Ssn);
    }
    if !government.find_driver_licenses_in_text(text).is_empty() {
        pii_types.push(PiiType::DriverLicense);
    }
    if !government.find_passports_in_text(text).is_empty() {
        pii_types.push(PiiType::Passport);
    }
    if !government.find_tax_ids_in_text(text).is_empty() {
        pii_types.push(PiiType::TaxId);
    }
    if !government.find_national_ids_in_text(text).is_empty() {
        pii_types.push(PiiType::NationalId);
    }
}

/// Scan for medical PII (MRN, NPI, insurance, ICD codes, prescriptions)
pub(super) fn scan_medical(text: &str, pii_types: &mut Vec<PiiType>) {
    let medical = MedicalIdentifierBuilder::new();

    if medical.is_medical_identifier_present(text) {
        if !medical.find_mrns_in_text(text).is_empty() {
            pii_types.push(PiiType::Mrn);
        }
        if !medical.find_provider_ids_in_text(text).is_empty() {
            pii_types.push(PiiType::Npi);
        }
        if !medical.find_insurance_ids_in_text(text).is_empty() {
            pii_types.push(PiiType::InsuranceNumber);
        }
        if !medical.find_medical_codes_in_text(text).is_empty() {
            pii_types.push(PiiType::IcdCode);
        }
        if !medical.find_prescriptions_in_text(text).is_empty() {
            pii_types.push(PiiType::PrescriptionNumber);
        }
    }
}

/// Scan for biometric data (fingerprint, face, voice, iris, DNA)
pub(super) fn scan_biometric(text: &str, pii_types: &mut Vec<PiiType>) {
    let biometric = BiometricIdentifierBuilder::new();

    if biometric.is_biometric_present(text) {
        if !biometric.detect_fingerprints_in_text(text).is_empty() {
            pii_types.push(PiiType::FingerprintId);
        }
        if !biometric.detect_facial_data_in_text(text).is_empty() {
            pii_types.push(PiiType::FaceId);
        }
        if !biometric.detect_voice_prints_in_text(text).is_empty() {
            pii_types.push(PiiType::VoiceId);
        }
        if !biometric.detect_iris_scans_in_text(text).is_empty() {
            pii_types.push(PiiType::IrisId);
        }
        if !biometric.detect_dna_sequences_in_text(text).is_empty() {
            pii_types.push(PiiType::DnaId);
        }
    }
}

/// Scan for location data (GPS, address, postal code)
pub(super) fn scan_location(text: &str, pii_types: &mut Vec<PiiType>) {
    let location = LocationIdentifierBuilder::new();

    if !location.find_gps_coordinates_in_text(text).is_empty() {
        pii_types.push(PiiType::GpsCoordinates);
    }
    if !location.find_addresses_in_text(text).is_empty() {
        pii_types.push(PiiType::Address);
    }
    if !location.find_postal_codes_in_text(text).is_empty() {
        pii_types.push(PiiType::PostalCode);
    }
}

/// Scan for organizational IDs (employee, student, badge)
pub(super) fn scan_organizational(text: &str, pii_types: &mut Vec<PiiType>) {
    let org = OrganizationalIdentifierBuilder::new();

    if !org.find_employee_ids_in_text(text).is_empty() {
        pii_types.push(PiiType::EmployeeId);
    }
    if !org.find_student_ids_in_text(text).is_empty() {
        pii_types.push(PiiType::StudentId);
    }
    if !org.find_badge_numbers_in_text(text).is_empty() {
        pii_types.push(PiiType::BadgeNumber);
    }
}

/// Scan for network identifiers (IP, MAC, UUID, URL)
pub(super) fn scan_network(text: &str, pii_types: &mut Vec<PiiType>) {
    let network = NetworkIdentifierBuilder::new();

    if network.is_network_present(text) {
        if !network.find_ip_addresses_in_text(text).is_empty() {
            pii_types.push(PiiType::IpAddress);
        }
        if !network.find_mac_addresses_in_text(text).is_empty() {
            pii_types.push(PiiType::MacAddress);
        }
        if !network.find_uuids_in_text(text).is_empty() {
            pii_types.push(PiiType::Uuid);
        }
        if !network.find_urls_in_text(text).is_empty() {
            pii_types.push(PiiType::Url);
        }
    }
}

/// Scan for tokens and secrets (API keys, JWT, passwords, etc.)
pub(super) fn scan_tokens(text: &str, pii_types: &mut Vec<PiiType>) {
    let token = TokenIdentifierBuilder::new();

    // API keys
    if token.is_api_key(text) || token.redact_api_keys_in_text(text).as_ref() != text {
        pii_types.push(PiiType::ApiKey);
    }

    // JWT
    if token.is_jwt(text) || token.redact_jwts_in_text(text).as_ref() != text {
        pii_types.push(PiiType::Jwt);
    }

    // Session IDs
    if token.is_likely_session_id(text) {
        pii_types.push(PiiType::SessionId);
    }

    // SSH keys
    if token.is_ssh_key(text) || token.redact_ssh_keys_in_text(text).as_ref() != text {
        pii_types.push(PiiType::SshKey);
    }

    // 1Password tokens
    if token.is_onepassword_token(text) {
        pii_types.push(PiiType::OnePasswordToken);
    }

    // 1Password vault references
    if token.is_onepassword_vault_ref(text) {
        pii_types.push(PiiType::OnePasswordVaultRef);
    }

    // Bearer tokens
    if token.is_bearer_token(text) {
        pii_types.push(PiiType::BearerToken);
    }

    // URLs with credentials
    if token.is_url_with_credentials(text) {
        pii_types.push(PiiType::UrlWithCredentials);
    }

    // Credentials
    let credential = CredentialIdentifierBuilder::new();

    // Connection strings with credentials (MSSQL, JDBC, database URLs)
    if credential.is_connection_string_with_credentials(text) {
        pii_types.push(PiiType::ConnectionString);
    }

    if credential.is_passwords_present(text) {
        pii_types.push(PiiType::Password);
    }
    if credential.is_pins_present(text) {
        pii_types.push(PiiType::Pin);
    }
    if credential.is_security_answers_present(text) {
        pii_types.push(PiiType::SecurityAnswer);
    }
    if credential.is_passphrases_present(text) {
        pii_types.push(PiiType::Passphrase);
    }
}

/// Internal scan function with config (for direct use and cache population)
pub(super) fn scan_for_pii_uncached_with_config(
    text: &str,
    config: &PiiScannerConfig,
) -> Vec<PiiType> {
    let mut pii_types = Vec::new();

    if config.scan_personal {
        scan_personal(text, &mut pii_types);
    }
    if config.scan_financial {
        scan_financial(text, &mut pii_types);
    }
    if config.scan_government {
        scan_government(text, &mut pii_types);
    }
    if config.scan_medical {
        scan_medical(text, &mut pii_types);
    }
    if config.scan_biometric {
        scan_biometric(text, &mut pii_types);
    }
    if config.scan_location {
        scan_location(text, &mut pii_types);
    }
    if config.scan_organizational {
        scan_organizational(text, &mut pii_types);
    }
    if config.scan_network {
        scan_network(text, &mut pii_types);
    }
    if config.scan_tokens {
        scan_tokens(text, &mut pii_types);
    }

    pii_types
}

/// Fast check if text contains any PII using a custom configuration
pub(super) fn is_pii_present_with_config_impl(text: &str, config: &PiiScannerConfig) -> bool {
    // Personal domain
    if config.scan_personal {
        let personal = PersonalIdentifierBuilder::new();
        if personal.is_pii_present(text) {
            return true;
        }
    }

    // Financial domain
    if config.scan_financial {
        let financial = FinancialIdentifierBuilder::new();
        if financial.is_financial_present(text) {
            return true;
        }
    }

    // Government domain
    if config.scan_government {
        let government = GovernmentIdentifierBuilder::new();
        if !government.find_ssns_in_text(text).is_empty()
            || !government.find_driver_licenses_in_text(text).is_empty()
            || !government.find_passports_in_text(text).is_empty()
            || !government.find_tax_ids_in_text(text).is_empty()
            || !government.find_national_ids_in_text(text).is_empty()
        {
            return true;
        }
    }

    // Medical domain
    if config.scan_medical {
        let medical = MedicalIdentifierBuilder::new();
        if medical.is_medical_identifier_present(text) {
            return true;
        }
    }

    // Biometric domain
    if config.scan_biometric {
        let biometric = BiometricIdentifierBuilder::new();
        if biometric.is_biometric_present(text) {
            return true;
        }
    }

    // Location domain
    if config.scan_location {
        let location = LocationIdentifierBuilder::new();
        if location.is_location_identifier(text) || !location.find_all_in_text(text).is_empty() {
            return true;
        }
    }

    // Organizational domain
    if config.scan_organizational {
        let org = OrganizationalIdentifierBuilder::new();
        if !org.find_employee_ids_in_text(text).is_empty()
            || !org.find_student_ids_in_text(text).is_empty()
            || !org.find_badge_numbers_in_text(text).is_empty()
        {
            return true;
        }
    }

    // Network domain
    if config.scan_network {
        let network = NetworkIdentifierBuilder::new();
        if network.is_network_present(text) {
            return true;
        }
    }

    // Token domain
    if config.scan_tokens {
        let token = TokenIdentifierBuilder::new();
        if token.is_token_identifier(text)
            || token.is_jwt(text)
            || token.is_api_key(text)
            || token.is_ssh_key(text)
            || token.is_onepassword_token(text)
            || token.is_onepassword_vault_ref(text)
            || token.is_bearer_token(text)
            || token.is_url_with_credentials(text)
        {
            return true;
        }

        // Password detection
        if text.to_lowercase().contains("password")
            && (text.contains('=') || text.contains(':') || text.contains(' '))
        {
            return true;
        }
    }

    false
}

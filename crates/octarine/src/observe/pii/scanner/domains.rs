//! Domain-specific PII scanning
//!
//! Uses domain builders from the primitives layer to detect PII.

use super::super::config::PiiScannerConfig;
use super::super::types::PiiType;

// Import domain builders from primitives/identifiers
use crate::primitives::identifiers::{
    BiometricIdentifierBuilder, CredentialIdentifierBuilder, FinancialIdentifierBuilder,
    GovernmentIdentifierBuilder, IdentifierMatch, LocationIdentifierBuilder,
    MedicalIdentifierBuilder, NetworkIdentifierBuilder, OrganizationalIdentifierBuilder,
    PersonalIdentifierBuilder, TokenIdentifierBuilder, TokenType,
};

/// Scan for personal PII (email, phone, name, birthdate, username, age, NRP)
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
        if !personal.detect_usernames_in_text(text).is_empty() {
            pii_types.push(PiiType::Username);
        }
    }

    // Age and NRP detectors run unconditionally — `is_pii_present` is
    // a coarse pre-filter built around email/phone/name/etc. and may
    // return `false` for text that contains only an age or nationality
    // reference.
    if !personal.detect_ages_in_text(text).is_empty() {
        pii_types.push(PiiType::Age);
    }
    if !personal.detect_nationalities_in_text(text).is_empty() {
        pii_types.push(PiiType::Nationality);
    }
    if !personal.detect_religions_in_text(text).is_empty() {
        pii_types.push(PiiType::Religion);
    }
    if !personal
        .detect_political_affiliations_in_text(text)
        .is_empty()
    {
        pii_types.push(PiiType::PoliticalAffiliation);
    }
}

/// Scan for financial PII (credit card, bank account, routing number, IBAN, crypto)
pub(super) fn scan_financial(text: &str, pii_types: &mut Vec<PiiType>) {
    let financial = FinancialIdentifierBuilder::new();

    if financial.is_financial_present(text) {
        if !financial.detect_credit_cards_in_text(text).is_empty() {
            pii_types.push(PiiType::CreditCard);
        }
        if !financial.detect_bank_accounts_in_text(text).is_empty() {
            pii_types.push(PiiType::BankAccount);
        }
        if !financial.detect_routing_numbers_in_text(text).is_empty() {
            pii_types.push(PiiType::RoutingNumber);
        }
        if !financial.detect_payment_tokens_in_text(text).is_empty() {
            pii_types.push(PiiType::PaymentToken);
        }
        if !financial.detect_ibans_in_text(text).is_empty() {
            pii_types.push(PiiType::Iban);
        }
        if !financial.detect_crypto_addresses_in_text(text).is_empty() {
            pii_types.push(PiiType::CryptoAddress);
        }
    }
}

/// Scan for government IDs (SSN, driver license, passport, tax ID, plus
/// country-specific national IDs across 18 jurisdictions).
pub(super) fn scan_government(text: &str, pii_types: &mut Vec<PiiType>) {
    type Finder = fn(&GovernmentIdentifierBuilder, &str) -> Vec<IdentifierMatch>;
    const SCANNERS: &[(Finder, PiiType)] = &[
        (GovernmentIdentifierBuilder::find_ssns_in_text, PiiType::Ssn),
        (
            GovernmentIdentifierBuilder::find_driver_licenses_in_text,
            PiiType::DriverLicense,
        ),
        (
            GovernmentIdentifierBuilder::find_passports_in_text,
            PiiType::Passport,
        ),
        (GovernmentIdentifierBuilder::find_eins_in_text, PiiType::Ein),
        (
            GovernmentIdentifierBuilder::find_tax_ids_in_text,
            PiiType::TaxId,
        ),
        (
            GovernmentIdentifierBuilder::find_national_ids_in_text,
            PiiType::NationalId,
        ),
        (
            GovernmentIdentifierBuilder::find_vehicle_ids_in_text,
            PiiType::Vin,
        ),
        (
            GovernmentIdentifierBuilder::find_korea_rrns_in_text,
            PiiType::KoreaRrn,
        ),
        (
            GovernmentIdentifierBuilder::find_korea_frns_in_text,
            PiiType::KoreaFrn,
        ),
        (
            GovernmentIdentifierBuilder::find_korea_driver_licenses_in_text,
            PiiType::KoreaDriverLicense,
        ),
        (
            GovernmentIdentifierBuilder::find_korea_passports_in_text,
            PiiType::KoreaPassport,
        ),
        (
            GovernmentIdentifierBuilder::find_korea_brns_in_text,
            PiiType::KoreaBrn,
        ),
        (
            GovernmentIdentifierBuilder::find_australia_tfns_in_text,
            PiiType::AustraliaTfn,
        ),
        (
            GovernmentIdentifierBuilder::find_australia_abns_in_text,
            PiiType::AustraliaAbn,
        ),
        (
            GovernmentIdentifierBuilder::find_australia_medicares_in_text,
            PiiType::AustraliaMedicare,
        ),
        (
            GovernmentIdentifierBuilder::find_australia_acns_in_text,
            PiiType::AustraliaAcn,
        ),
        (
            GovernmentIdentifierBuilder::find_india_aadhaars_in_text,
            PiiType::IndiaAadhaar,
        ),
        (
            GovernmentIdentifierBuilder::find_india_pans_in_text,
            PiiType::IndiaPan,
        ),
        (
            GovernmentIdentifierBuilder::find_india_gstins_in_text,
            PiiType::IndiaGstin,
        ),
        (
            GovernmentIdentifierBuilder::find_india_vehicle_registrations_in_text,
            PiiType::IndiaVehicleReg,
        ),
        (
            GovernmentIdentifierBuilder::find_india_voter_ids_in_text,
            PiiType::IndiaVoterId,
        ),
        (
            GovernmentIdentifierBuilder::find_india_passports_in_text,
            PiiType::IndiaPassport,
        ),
        (
            GovernmentIdentifierBuilder::find_brazil_cpfs_in_text,
            PiiType::BrazilCpf,
        ),
        (
            GovernmentIdentifierBuilder::find_brazil_cnpjs_in_text,
            PiiType::BrazilCnpj,
        ),
        (
            GovernmentIdentifierBuilder::find_mexico_curps_in_text,
            PiiType::MexicoCurp,
        ),
        (
            GovernmentIdentifierBuilder::find_nigeria_nins_in_text,
            PiiType::NigeriaNin,
        ),
        (
            GovernmentIdentifierBuilder::find_nigeria_bvns_in_text,
            PiiType::NigeriaBvn,
        ),
        (
            GovernmentIdentifierBuilder::find_nigeria_vehicle_registrations_in_text,
            PiiType::NigeriaVehicleReg,
        ),
        (
            GovernmentIdentifierBuilder::find_thailand_tnins_in_text,
            PiiType::ThailandTnin,
        ),
        (
            GovernmentIdentifierBuilder::find_singapore_nrics_in_text,
            PiiType::SingaporeNric,
        ),
        (
            GovernmentIdentifierBuilder::find_singapore_uens_in_text,
            PiiType::SingaporeUen,
        ),
        (
            GovernmentIdentifierBuilder::find_finland_hetus_in_text,
            PiiType::FinlandHetu,
        ),
        (
            GovernmentIdentifierBuilder::find_poland_pesels_in_text,
            PiiType::PolandPesel,
        ),
        (
            GovernmentIdentifierBuilder::find_italy_fiscal_codes_in_text,
            PiiType::ItalyFiscalCode,
        ),
        (
            GovernmentIdentifierBuilder::find_italy_vats_in_text,
            PiiType::ItalyVat,
        ),
        (
            GovernmentIdentifierBuilder::find_italy_passports_in_text,
            PiiType::ItalyPassport,
        ),
        (
            GovernmentIdentifierBuilder::find_italy_identity_cards_in_text,
            PiiType::ItalyIdentityCard,
        ),
        (
            GovernmentIdentifierBuilder::find_italy_driver_licenses_in_text,
            PiiType::ItalyDriverLicense,
        ),
        (
            GovernmentIdentifierBuilder::find_spain_nifs_in_text,
            PiiType::SpainNif,
        ),
        (
            GovernmentIdentifierBuilder::find_spain_nies_in_text,
            PiiType::SpainNie,
        ),
        (
            GovernmentIdentifierBuilder::find_uk_nis_in_text,
            PiiType::UkNi,
        ),
    ];

    let government = GovernmentIdentifierBuilder::new();
    for &(finder, pii_type) in SCANNERS {
        if !finder(&government, text).is_empty() {
            pii_types.push(pii_type);
        }
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
        if !medical.find_dea_numbers_in_text(text).is_empty() {
            pii_types.push(PiiType::DeaNumber);
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
        if !biometric
            .detect_biometric_templates_in_text(text)
            .is_empty()
        {
            pii_types.push(PiiType::BiometricTemplate);
        }
    }
}

/// Scan for location data (GPS, address, postal code, named location)
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
    if !location.find_named_locations_in_text(text).is_empty() {
        pii_types.push(PiiType::NamedLocation);
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

/// Scan for network identifiers (IP, MAC, UUID, URL, domain, hostname, port)
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
        if !network.find_domains_in_text(text).is_empty() {
            pii_types.push(PiiType::Domain);
        }
    }

    // Hostname and Port are checked unconditionally: their regex patterns are
    // not part of `is_network_present`'s aggregate, so the guard above would
    // skip text containing only a hostname or port.
    if !network.find_hostnames_in_text(text).is_empty() {
        pii_types.push(PiiType::Hostname);
    }
    if !network.find_ports_in_text(text).is_empty() {
        pii_types.push(PiiType::Port);
    }
}

/// Scan for tokens and secrets (API keys, JWT, passwords, etc.)
pub(super) fn scan_tokens(text: &str, pii_types: &mut Vec<PiiType>) {
    let token = TokenIdentifierBuilder::new();

    // Provider-specific token attribution. Iterate whitespace-split words and
    // dispatch through detect_token_type so each provider gets its own PiiType
    // variant (issue #97). Suppress the generic ApiKey emission when any
    // provider matched — it is reserved for unrecognized api-key-shaped input.
    let mut provider_matched = false;
    for word in text.split_whitespace() {
        // Strip surrounding shell punctuation (quotes, commas, parens, colons,
        // semicolons) but preserve characters that appear inside provider
        // tokens: `-` `_` `.` (separators) and `=` (base64 padding, e.g.
        // Azure `AccountKey=...==`).
        let trimmed = word.trim_matches(|c: char| {
            !c.is_alphanumeric() && c != '-' && c != '_' && c != '.' && c != '='
        });
        if trimmed.is_empty() {
            continue;
        }
        if let Some(token_type) = token.detect_token_type(trimmed)
            && let Some(pii) = token_type_to_pii(token_type)
        {
            pii_types.push(pii);
            provider_matched = true;
        }
    }

    // Generic ApiKey fallback: only when no provider-specific match.
    if !provider_matched
        && (token.is_api_key(text) || token.redact_api_keys_in_text(text).as_ref() != text)
    {
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

    // Framework-style credentials (Django, Rails YAML, .env, Docker Compose).
    // Mapped to ConnectionString since they identify the same kind of secret —
    // database access credentials in application configuration.
    if credential.is_framework_credential_present(text)
        && !pii_types.contains(&PiiType::ConnectionString)
    {
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

/// Map a detected `TokenType` to the corresponding provider-specific
/// `PiiType` variant.
///
/// Returns `None` for token types that are already handled by sibling
/// dispatches in `scan_tokens` (Jwt, SessionId, SshKey*, OnePassword*,
/// BearerToken, UrlWithCredentials) so they are not double-emitted, and for
/// `GenericApiKey` (handled by the trailing fallback). `AwsSecretKey` maps
/// to `ApiKey` because AWS secret keys are 40 base64 chars and
/// indistinguishable from random high-entropy strings — a dedicated variant
/// would create false positives.
fn token_type_to_pii(t: TokenType) -> Option<PiiType> {
    Some(match t {
        TokenType::GitHub => PiiType::GitHubToken,
        TokenType::GitLab => PiiType::GitLabToken,
        TokenType::BitbucketToken => PiiType::BitbucketToken,
        TokenType::AwsAccessKey => PiiType::AwsAccessKey,
        TokenType::AwsSessionToken => PiiType::AwsSessionToken,
        TokenType::AwsSecretKey => PiiType::ApiKey,
        TokenType::GcpApiKey => PiiType::GcpApiKey,
        TokenType::AzureKey => PiiType::AzureKey,
        TokenType::StripeKey => PiiType::StripeKey,
        TokenType::SquareToken => PiiType::SquareToken,
        TokenType::ShopifyToken => PiiType::ShopifyToken,
        TokenType::PayPalToken => PiiType::PayPalToken,
        TokenType::MailchimpToken => PiiType::MailchimpToken,
        TokenType::MailgunToken => PiiType::MailgunToken,
        TokenType::ResendToken => PiiType::ResendToken,
        TokenType::BrevoToken => PiiType::BrevoToken,
        TokenType::DatabricksToken => PiiType::DatabricksToken,
        TokenType::VaultToken => PiiType::VaultToken,
        TokenType::CloudflareOriginCaKey => PiiType::CloudflareOriginCaKey,
        TokenType::NpmToken => PiiType::NpmToken,
        TokenType::PyPiToken => PiiType::PyPiToken,
        TokenType::NuGetKey => PiiType::NuGetKey,
        TokenType::ArtifactoryToken => PiiType::ArtifactoryToken,
        TokenType::DockerHubToken => PiiType::DockerHubToken,
        TokenType::TelegramToken => PiiType::TelegramToken,
        TokenType::SendGridToken => PiiType::SendGridToken,
        TokenType::OpenAiKey => PiiType::OpenAiKey,
        TokenType::DiscordToken => PiiType::DiscordToken,
        TokenType::SlackToken => PiiType::SlackToken,
        TokenType::TwilioToken => PiiType::TwilioToken,
        TokenType::HerokuToken => PiiType::HerokuToken,
        TokenType::LinearToken => PiiType::LinearToken,
        TokenType::DopplerToken => PiiType::DopplerToken,
        TokenType::NetlifyToken => PiiType::NetlifyToken,
        TokenType::FlyIoToken => PiiType::FlyIoToken,
        TokenType::RenderToken => PiiType::RenderToken,
        TokenType::PlanetScaleToken => PiiType::PlanetScaleToken,
        TokenType::SupabaseToken => PiiType::SupabaseToken,
        // Already handled by sibling dispatches in scan_tokens — return
        // None to avoid double-emission.
        TokenType::Jwt
        | TokenType::SessionId
        | TokenType::UrlWithCredentials
        | TokenType::SshPrivateKey
        | TokenType::SshPublicKey
        | TokenType::SshFingerprint
        | TokenType::OnePasswordServiceToken
        | TokenType::OnePasswordVaultRef
        | TokenType::BearerToken
        // Generic api-key shape — emit ApiKey via the trailing fallback so
        // it is suppressed when a provider-specific match exists in the
        // same text.
        | TokenType::GenericApiKey => return None,
    })
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

    // Government domain — is_government_present aggregates all 17 government
    // finders (including country-specific variants) via
    // find_all_government_ids_in_text, so future additions are covered
    // automatically.
    if config.scan_government {
        let government = GovernmentIdentifierBuilder::new();
        if government.is_government_present(text) {
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
        if network.is_network_present(text)
            || !network.find_hostnames_in_text(text).is_empty()
            || !network.find_ports_in_text(text).is_empty()
        {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_scan_personal_detects_age_and_nrp() {
        let text = "The 42-year-old American Catholic Democrat patient.";
        let mut pii_types = Vec::new();
        scan_personal(text, &mut pii_types);
        assert!(pii_types.contains(&PiiType::Age), "expected Age");
        assert!(
            pii_types.contains(&PiiType::Nationality),
            "expected Nationality"
        );
        assert!(pii_types.contains(&PiiType::Religion), "expected Religion");
        assert!(
            pii_types.contains(&PiiType::PoliticalAffiliation),
            "expected PoliticalAffiliation"
        );
    }

    #[test]
    fn test_scan_personal_age_only_no_other_pii() {
        // "in her eighties" — should trip Age but not email/phone/etc.
        let text = "in her eighties";
        let mut pii_types = Vec::new();
        scan_personal(text, &mut pii_types);
        assert!(pii_types.contains(&PiiType::Age));
        assert!(!pii_types.contains(&PiiType::Email));
        assert!(!pii_types.contains(&PiiType::Phone));
    }
}

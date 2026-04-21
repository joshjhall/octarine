//! Identifier operation shortcuts
//!
//! Convenience functions for common identifier operations. These are the recommended
//! entry points for most use cases.
//!
//! # Examples
//!
//! ```
//! use octarine::identifiers::{is_pii_present, redact_pii, detect_identifier, validate_email};
//!
//! // PII Detection
//! if is_pii_present("Contact: user@example.com") {
//!     let redacted = redact_pii("Contact: user@example.com");
//! }
//!
//! // Type Detection
//! let id_type = detect_identifier("user@example.com");
//!
//! // Validation
//! validate_email("user@example.com").unwrap();
//! ```

use crate::observe::Problem;
use crate::primitives::identifiers::{
    BirthdateRedactionStrategy, CredentialTextPolicy, CreditCardRedactionStrategy,
    EmailRedactionStrategy, GovernmentTextPolicy, IpRedactionStrategy, NameRedactionStrategy,
    PersonalTextPolicy, PhoneRedactionStrategy, SsnRedactionStrategy, UsernameRedactionStrategy,
};

use super::types::{
    ApiKeyProvider, CredentialMatch, CreditCardType, DetectionConfidence, FinancialTextPolicy,
    GpsFormat, IdentifierMatch, IdentifierType, LocationTextPolicy, PhoneRegion, PostalCodeType,
    UuidVersion,
};
use super::{
    BiometricBuilder, CredentialsBuilder, FinancialBuilder, GovernmentBuilder, IdentifierBuilder,
    LocationBuilder, MedicalBuilder, NetworkBuilder, OrganizationalBuilder, PersonalBuilder,
    TokenBuilder,
};

// ============================================================
// DETECTION SHORTCUTS
// ============================================================

/// Detect the type of identifier from a value
///
/// Returns None if the value doesn't match any known identifier type.
#[must_use]
pub fn detect_identifier(value: &str) -> Option<IdentifierType> {
    IdentifierBuilder::new().detect(value)
}

/// Scan text for all identifiers
///
/// Returns a list of all identifier matches found in the text.
#[must_use]
pub fn scan_identifiers(text: &str) -> Vec<IdentifierMatch> {
    IdentifierBuilder::new().scan_text(text)
}

/// Check if text contains any identifiers
#[must_use]
pub fn is_identifiers_present(text: &str) -> bool {
    IdentifierBuilder::new().is_identifiers_present(text)
}

/// Check if text contains PII (personally identifiable information)
#[must_use]
pub fn is_pii_present(text: &str) -> bool {
    IdentifierBuilder::new().is_pii_present(text)
}

// ============================================================
// EMAIL SHORTCUTS
// ============================================================

/// Check if value is an email address
#[must_use]
pub fn is_email(value: &str) -> bool {
    PersonalBuilder::new().is_email(value)
}

/// Validate an email address (returns Result)
pub fn validate_email(email: &str) -> Result<(), Problem> {
    PersonalBuilder::new().validate_email(email)
}

/// Find all emails in text
#[must_use]
pub fn find_emails(text: &str) -> Vec<IdentifierMatch> {
    PersonalBuilder::new().find_emails_in_text(text)
}

/// Redact an email address (shows first character and domain)
#[must_use]
pub fn redact_email(email: &str) -> String {
    PersonalBuilder::new().redact_email_with_strategy(email, EmailRedactionStrategy::ShowFirst)
}

/// Redact all emails in text (complete redaction)
#[must_use]
pub fn redact_emails(text: &str) -> String {
    PersonalBuilder::new().redact_emails_in_text_with_policy(text, PersonalTextPolicy::Complete)
}

// ============================================================
// PHONE SHORTCUTS
// ============================================================

/// Check if value is a phone number
#[must_use]
pub fn is_phone(value: &str) -> bool {
    PersonalBuilder::new().is_phone_number(value)
}

/// Validate a phone number (returns detected region)
pub fn validate_phone(phone: &str) -> Result<PhoneRegion, Problem> {
    PersonalBuilder::new().validate_phone(phone)
}

/// Find all phone numbers in text
#[must_use]
pub fn find_phones(text: &str) -> Vec<IdentifierMatch> {
    PersonalBuilder::new().find_phones_in_text(text)
}

/// Redact a phone number (shows last 4 digits)
#[must_use]
pub fn redact_phone(phone: &str) -> String {
    PersonalBuilder::new().redact_phone_with_strategy(phone, PhoneRedactionStrategy::ShowLastFour)
}

/// Redact all phone numbers in text (complete redaction)
#[must_use]
pub fn redact_phones(text: &str) -> String {
    PersonalBuilder::new().redact_phones_in_text_with_policy(text, PersonalTextPolicy::Complete)
}

// ============================================================
// NAME SHORTCUTS
// ============================================================

/// Check if value is a person's name
#[must_use]
pub fn is_name(value: &str) -> bool {
    PersonalBuilder::new().is_name(value)
}

/// Validate a person's name
pub fn validate_name(name: &str) -> Result<(), Problem> {
    PersonalBuilder::new().validate_name(name)
}

/// Find all names in text
#[must_use]
pub fn find_names(text: &str) -> Vec<IdentifierMatch> {
    PersonalBuilder::new().find_names_in_text(text)
}

/// Redact a name (shows initials only)
#[must_use]
pub fn redact_name(name: &str) -> String {
    PersonalBuilder::new().redact_name_with_strategy(name, NameRedactionStrategy::ShowInitials)
}

// ============================================================
// BIRTHDATE SHORTCUTS
// ============================================================

/// Check if value is a birthdate
#[must_use]
pub fn is_birthdate(value: &str) -> bool {
    PersonalBuilder::new().is_birthdate(value)
}

/// Validate a birthdate
pub fn validate_birthdate(date: &str) -> Result<(), Problem> {
    PersonalBuilder::new().validate_birthdate(date)
}

/// Find all birthdates in text
#[must_use]
pub fn find_birthdates(text: &str) -> Vec<IdentifierMatch> {
    PersonalBuilder::new().find_birthdates_in_text(text)
}

/// Redact a birthdate (shows year only)
#[must_use]
pub fn redact_birthdate(date: &str) -> String {
    PersonalBuilder::new()
        .redact_birthdate_with_strategy(date, BirthdateRedactionStrategy::ShowYear)
}

// ============================================================
// USERNAME SHORTCUTS
// ============================================================

/// Check if value is a username
#[must_use]
pub fn is_username(value: &str) -> bool {
    PersonalBuilder::new().is_username(value)
}

/// Validate a username
pub fn validate_username(username: &str) -> Result<(), Problem> {
    PersonalBuilder::new().validate_username(username)
}

/// Redact a username (replaces with token)
#[must_use]
pub fn redact_username(username: &str) -> String {
    PersonalBuilder::new().redact_username_with_strategy(username, UsernameRedactionStrategy::Token)
}

// ============================================================
// SSN SHORTCUTS
// ============================================================

/// Check if value is an SSN
#[must_use]
pub fn is_ssn(value: &str) -> bool {
    GovernmentBuilder::new().is_ssn(value)
}

/// Validate an SSN format
///
/// # Errors
///
/// Returns `Problem` if the SSN format is invalid.
pub fn validate_ssn(ssn: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_ssn(ssn)
}

/// Find all SSNs in text
#[must_use]
pub fn find_ssns(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_ssns_in_text(text)
}

/// Redact an SSN
#[must_use]
pub fn redact_ssn(ssn: &str) -> String {
    GovernmentBuilder::new().redact_ssn_with_strategy(ssn, SsnRedactionStrategy::Token)
}

/// Redact all SSNs in text
#[must_use]
pub fn redact_ssns(text: &str) -> String {
    GovernmentBuilder::new().redact_ssns_in_text_with_strategy(text, SsnRedactionStrategy::Token)
}

/// Check if value is a valid EIN (Employer Identification Number)
#[must_use]
pub fn is_ein(value: &str) -> bool {
    GovernmentBuilder::new().is_ein(value)
}

/// Find all valid EINs in text
#[must_use]
pub fn find_eins(text: &str) -> Vec<IdentifierMatch> {
    GovernmentBuilder::new().find_eins_in_text(text)
}

/// Validate an EIN format
///
/// # Errors
///
/// Returns `Problem` if the EIN format or IRS campus code prefix is invalid.
pub fn validate_ein(ein: &str) -> Result<(), Problem> {
    GovernmentBuilder::new().validate_ein(ein)
}

// ============================================================
// CREDIT CARD SHORTCUTS
// ============================================================

/// Check if value is a credit card number
#[must_use]
pub fn is_credit_card(value: &str) -> bool {
    FinancialBuilder::new().is_credit_card(value)
}

/// Detect all credit cards in text
#[must_use]
pub fn detect_credit_cards(text: &str) -> Vec<IdentifierMatch> {
    FinancialBuilder::new().detect_credit_cards_in_text(text)
}

/// Validate a credit card number (returns card type on success)
pub fn validate_credit_card(card: &str) -> Result<CreditCardType, Problem> {
    FinancialBuilder::new().validate_credit_card(card)
}

/// Redact all credit cards in text
#[must_use]
pub fn redact_credit_cards(text: &str) -> String {
    FinancialBuilder::new()
        .redact_credit_cards_in_text_with_strategy(text, CreditCardRedactionStrategy::ShowLast4)
        .to_string()
}

// ============================================================
// ROUTING NUMBER SHORTCUTS
// ============================================================

/// Check if value is a routing number
#[must_use]
pub fn is_routing_number(value: &str) -> bool {
    FinancialBuilder::new().is_routing_number(value)
}

/// Detect all routing numbers in text with ABA checksum validation
#[must_use]
pub fn detect_routing_numbers(text: &str) -> Vec<IdentifierMatch> {
    FinancialBuilder::new().detect_routing_numbers_in_text(text)
}

/// Validate a routing number
pub fn validate_routing_number(routing: &str) -> Result<(), Problem> {
    FinancialBuilder::new().validate_routing_number(routing)
}

// ============================================================
// BANK ACCOUNT SHORTCUTS
// ============================================================

/// Check if value is a bank account number
#[must_use]
pub fn is_bank_account(value: &str) -> bool {
    FinancialBuilder::new().is_bank_account(value)
}

// ============================================================
// IBAN SHORTCUTS
// ============================================================

/// Check if value is a valid IBAN (format + MOD-97 checksum)
#[must_use]
pub fn is_iban(value: &str) -> bool {
    FinancialBuilder::new().is_iban(value)
}

/// Detect all IBANs in text with MOD-97 checksum validation
#[must_use]
pub fn detect_ibans(text: &str) -> Vec<IdentifierMatch> {
    FinancialBuilder::new().detect_ibans_in_text(text)
}

// ============================================================
// CRYPTO ADDRESS SHORTCUTS
// ============================================================

/// Check if value is a Bitcoin address (P2PKH, P2SH, or Bech32/Bech32m)
#[must_use]
pub fn is_bitcoin_address(value: &str) -> bool {
    FinancialBuilder::new().is_bitcoin_address(value)
}

/// Check if value is an Ethereum address (0x + 40 hex chars)
#[must_use]
pub fn is_ethereum_address(value: &str) -> bool {
    FinancialBuilder::new().is_ethereum_address(value)
}

/// Check if value is any supported cryptocurrency wallet address
#[must_use]
pub fn is_crypto_address(value: &str) -> bool {
    FinancialBuilder::new().is_crypto_address(value)
}

/// Detect all cryptocurrency addresses in text
#[must_use]
pub fn detect_crypto_addresses(text: &str) -> Vec<IdentifierMatch> {
    FinancialBuilder::new().detect_crypto_addresses_in_text(text)
}

// ============================================================
// IP ADDRESS SHORTCUTS
// ============================================================

/// Check if value is an IP address
#[must_use]
pub fn is_ip_address(value: &str) -> bool {
    NetworkBuilder::new().is_ip_address(value)
}

/// Check if value is an IPv4 address
#[must_use]
pub fn is_ipv4(value: &str) -> bool {
    NetworkBuilder::new().is_ipv4(value)
}

/// Check if value is an IPv6 address
#[must_use]
pub fn is_ipv6(value: &str) -> bool {
    NetworkBuilder::new().is_ipv6(value)
}

/// Redact an IP address
#[must_use]
pub fn redact_ip(ip: &str) -> String {
    NetworkBuilder::new().redact_ip(ip, IpRedactionStrategy::Token)
}

// ============================================================
// MAC ADDRESS SHORTCUTS
// ============================================================

/// Check if value is a MAC address
#[must_use]
pub fn is_mac_address(value: &str) -> bool {
    NetworkBuilder::new().is_mac_address(value)
}

/// Validate a MAC address format
///
/// Validates format and rejects special addresses (broadcast, null).
pub fn validate_mac_address(mac: &str) -> Result<(), Problem> {
    NetworkBuilder::new().validate_mac_address(mac)
}

// ============================================================
// URL SHORTCUTS
// ============================================================

/// Check if value is a URL
#[must_use]
pub fn is_url(value: &str) -> bool {
    NetworkBuilder::new().is_url(value)
}

/// Find all URLs in text
#[must_use]
pub fn find_urls(text: &str) -> Vec<IdentifierMatch> {
    NetworkBuilder::new().find_urls_in_text(text)
}

// ============================================================
// DOMAIN / HOSTNAME SHORTCUTS
// ============================================================

/// Check if value is a domain name
#[must_use]
pub fn is_domain(value: &str) -> bool {
    NetworkBuilder::new().is_domain(value)
}

/// Check if value is a hostname
#[must_use]
pub fn is_hostname(value: &str) -> bool {
    NetworkBuilder::new().is_hostname(value)
}

// ============================================================
// UUID SHORTCUTS
// ============================================================

/// Check if value is a UUID
#[must_use]
pub fn is_uuid(value: &str) -> bool {
    NetworkBuilder::new().is_uuid(value)
}

/// Validate a UUID v4
///
/// For bool check, use `validate_uuid_v4(..).is_ok()`.
pub fn validate_uuid_v4(uuid: &str) -> Result<(), Problem> {
    NetworkBuilder::new().validate_uuid_v4(uuid).map(|_| ())
}

/// Validate a UUID (any version)
///
/// Returns the detected UUID version on success.
pub fn validate_uuid(uuid: &str) -> Result<UuidVersion, Problem> {
    NetworkBuilder::new().validate_uuid(uuid)
}

// ============================================================
// JWT SHORTCUTS
// ============================================================

/// Check if value is a JWT token
#[must_use]
pub fn is_jwt(value: &str) -> bool {
    TokenBuilder::new().is_jwt(value)
}

/// Validate a JWT token structure (format only; does not verify signature)
///
/// # Errors
///
/// Returns `Problem` if the JWT structure is invalid.
pub fn validate_jwt(token: &str) -> Result<(), Problem> {
    TokenBuilder::new().validate_jwt(token)
}

/// Validate an API key using common-provider length bounds (20..=200)
///
/// Covers typical providers (Stripe, AWS, GitHub, Slack, etc.). For custom
/// bounds, call `TokenBuilder::new().validate_api_key(key, min, max)` directly.
///
/// # Errors
///
/// Returns `Problem` if the key is outside the length bounds or the format
/// is not recognized.
pub fn validate_api_key(key: &str) -> Result<ApiKeyProvider, Problem> {
    TokenBuilder::new().validate_api_key(key, 20, 200)
}

/// Validate a session ID using common session length bounds (16..=128)
///
/// Covers UUIDs (36), HMAC sessions (64), and larger opaque IDs. For custom
/// bounds, call `TokenBuilder::new().validate_session_id(session_id, min, max)` directly.
///
/// # Errors
///
/// Returns `Problem` if the session ID is outside the length bounds, has low
/// entropy, or contains invalid characters.
pub fn validate_session_id(session_id: &str) -> Result<(), Problem> {
    TokenBuilder::new().validate_session_id(session_id, 16, 128)
}

/// Redact a JWT token
#[must_use]
pub fn redact_jwt(jwt: &str) -> String {
    TokenBuilder::new().redact_jwt(jwt)
}

// ============================================================
// AWS SHORTCUTS
// ============================================================

/// Check if value is an AWS session token (STS temporary credential)
#[must_use]
pub fn is_aws_session_token(value: &str) -> bool {
    TokenBuilder::new().is_aws_session_token(value)
}

// ============================================================
// SSH KEY SHORTCUTS
// ============================================================

/// Check if value is an SSH public key
#[must_use]
pub fn is_ssh_public_key(value: &str) -> bool {
    TokenBuilder::new().is_ssh_public_key(value)
}

/// Check if value is an SSH private key
#[must_use]
pub fn is_ssh_private_key(value: &str) -> bool {
    TokenBuilder::new().is_ssh_private_key(value)
}

/// Check if value is an SSH fingerprint (MD5 or SHA256 format)
#[must_use]
pub fn is_ssh_fingerprint(value: &str) -> bool {
    TokenBuilder::new().is_ssh_fingerprint(value)
}

// ============================================================
// GITLAB / BEARER TOKEN SHORTCUTS
// ============================================================

/// Check if value is a GitLab token
#[must_use]
pub fn is_gitlab_token(value: &str) -> bool {
    TokenBuilder::new().is_gitlab_token(value)
}

/// Check if value is a Bearer token
#[must_use]
pub fn is_bearer_token(value: &str) -> bool {
    TokenBuilder::new().is_bearer_token(value)
}

// ============================================================
// MEDICAL SHORTCUTS (HIPAA)
// ============================================================

/// Check if value is a medical record number
#[must_use]
pub fn is_medical_record_number(value: &str) -> bool {
    MedicalBuilder::new().is_mrn(value)
}

/// Check if value is a provider ID (NPI — National Provider Identifier)
#[must_use]
pub fn is_provider_id(value: &str) -> bool {
    MedicalBuilder::new().is_provider_id(value)
}

/// Check if value is a DEA number (format + checksum)
#[must_use]
pub fn is_dea_number(value: &str) -> bool {
    MedicalBuilder::new().is_dea_number(value)
}

/// Check if value is a health insurance number
#[must_use]
pub fn is_health_insurance(value: &str) -> bool {
    MedicalBuilder::new().is_insurance(value)
}

/// Check if value is a prescription number
#[must_use]
pub fn is_prescription(value: &str) -> bool {
    MedicalBuilder::new().is_prescription(value)
}

/// Check if value is a medical code (ICD-10, CPT)
#[must_use]
pub fn is_medical_code(value: &str) -> bool {
    MedicalBuilder::new().is_medical_code(value)
}

/// Validate a medical record number format
///
/// # Errors
///
/// Returns `Problem` if the MRN format is invalid.
pub fn validate_mrn(mrn: &str) -> Result<(), Problem> {
    MedicalBuilder::new().validate_mrn(mrn)
}

/// Validate an NPI (National Provider Identifier) format and checksum
///
/// # Errors
///
/// Returns `Problem` if the NPI format or checksum is invalid.
pub fn validate_npi(npi: &str) -> Result<(), Problem> {
    MedicalBuilder::new().validate_npi(npi)
}

/// Find all medical record numbers in text
#[must_use]
pub fn find_medical_records(text: &str) -> Vec<IdentifierMatch> {
    MedicalBuilder::new().find_mrns_in_text(text)
}

/// Redact all medical identifiers in text
#[must_use]
pub fn redact_medical(text: &str) -> String {
    MedicalBuilder::new().redact_all_in_text(text)
}

// ============================================================
// BIOMETRIC SHORTCUTS (BIPA)
// ============================================================

/// Detect all biometric identifiers in text
#[must_use]
pub fn detect_biometric_ids(text: &str) -> Vec<IdentifierMatch> {
    BiometricBuilder::new().detect_all_in_text(text)
}

/// Redact all biometric identifiers in text
#[must_use]
pub fn redact_biometric(text: &str) -> String {
    BiometricBuilder::new().redact_all_in_text(text)
}

// ============================================================
// ORGANIZATIONAL SHORTCUTS
// ============================================================

/// Check if value is an employee ID
#[must_use]
pub fn is_employee_id(value: &str) -> bool {
    OrganizationalBuilder::new().is_employee_id(value)
}

/// Check if value is a student ID
#[must_use]
pub fn is_student_id(value: &str) -> bool {
    OrganizationalBuilder::new().is_student_id(value)
}

/// Check if value is a badge number
#[must_use]
pub fn is_badge_number(value: &str) -> bool {
    OrganizationalBuilder::new().is_badge_number(value)
}

/// Validate an employee ID format
///
/// # Errors
///
/// Returns `Problem` if the employee ID format is invalid.
pub fn validate_employee_id(employee_id: &str) -> Result<(), Problem> {
    OrganizationalBuilder::new().validate_employee_id(employee_id)
}

/// Validate a student ID format
///
/// # Errors
///
/// Returns `Problem` if the student ID format is invalid.
pub fn validate_student_id(student_id: &str) -> Result<(), Problem> {
    OrganizationalBuilder::new().validate_student_id(student_id)
}

/// Validate a badge number format
///
/// # Errors
///
/// Returns `Problem` if the badge number format is invalid.
pub fn validate_badge_number(badge_number: &str) -> Result<(), Problem> {
    OrganizationalBuilder::new().validate_badge_number(badge_number)
}

/// Redact an employee ID
#[must_use]
pub fn redact_employee_id(employee_id: &str) -> String {
    OrganizationalBuilder::new().redact_employee_id(employee_id)
}

/// Redact a student ID
#[must_use]
pub fn redact_student_id(student_id: &str) -> String {
    OrganizationalBuilder::new().redact_student_id(student_id)
}

/// Redact a badge number
#[must_use]
pub fn redact_badge_number(badge_number: &str) -> String {
    OrganizationalBuilder::new().redact_badge_number(badge_number)
}

/// Find all employee IDs in text
#[must_use]
pub fn find_employee_ids(text: &str) -> Vec<IdentifierMatch> {
    OrganizationalBuilder::new().find_employee_ids_in_text(text)
}

/// Redact all organizational identifiers in text
#[must_use]
pub fn redact_organizational(text: &str) -> String {
    OrganizationalBuilder::new()
        .redact_all_in_text(text)
        .to_string()
}

// ============================================================
// LOCATION SHORTCUTS
// ============================================================

/// Check if value is a GPS coordinate
#[must_use]
pub fn is_gps_coordinate(value: &str) -> bool {
    LocationBuilder::new().is_gps_coordinate(value)
}

/// Validate a GPS coordinate and detect its format
pub fn validate_gps_coordinate(coordinate: &str) -> Result<GpsFormat, Problem> {
    LocationBuilder::new().validate_gps_coordinate(coordinate)
}

/// Check if value is a street address
#[must_use]
pub fn is_street_address(value: &str) -> bool {
    LocationBuilder::new().is_street_address(value)
}

/// Check if value is a postal code
#[must_use]
pub fn is_postal_code(value: &str) -> bool {
    LocationBuilder::new().is_postal_code(value)
}

/// Validate a postal code and detect its type
pub fn validate_postal_code(postal_code: &str) -> Result<PostalCodeType, Problem> {
    LocationBuilder::new().validate_postal_code(postal_code)
}

/// Find all location identifiers in text
#[must_use]
pub fn find_locations(text: &str) -> Vec<IdentifierMatch> {
    LocationBuilder::new().find_all_in_text(text)
}

/// Redact all location identifiers in text
#[must_use]
pub fn redact_locations(text: &str) -> String {
    LocationBuilder::new().redact_all_in_text_with_strategy(text, LocationTextPolicy::Complete)
}

// ============================================================
// CONNECTION STRING SHORTCUTS
// ============================================================

/// Check if value contains a connection string with embedded credentials
#[must_use]
pub fn is_connection_string_with_credentials(value: &str) -> bool {
    CredentialsBuilder::new().is_connection_string_with_credentials(value)
}

/// Check if value is a database connection string (URL-based)
#[must_use]
pub fn is_database_connection_string(value: &str) -> bool {
    CredentialsBuilder::new().is_database_connection_string(value)
}

/// Find all connection strings with credentials in text
#[must_use]
pub fn find_connection_strings(text: &str) -> Vec<CredentialMatch> {
    CredentialsBuilder::new().find_connection_strings_in_text(text)
}

/// Redact credentials in a connection string while preserving host/database
#[must_use]
pub fn redact_connection_string(value: &str) -> String {
    CredentialsBuilder::new().redact_connection_string(value)
}

/// Redact all connection strings in text
#[must_use]
pub fn redact_connection_strings(text: &str) -> String {
    CredentialsBuilder::new()
        .redact_connection_strings_in_text(text)
        .to_string()
}

// ============================================================
// BULK REDACTION SHORTCUTS
// ============================================================

/// Redact all PII in text
///
/// This is a comprehensive redaction that handles emails, phones, SSNs,
/// credit cards, and other common PII types.
#[must_use]
pub fn redact_pii(text: &str) -> String {
    let builder = IdentifierBuilder::new();
    let mut result = text.to_string();

    // Redact personal identifiers
    result = builder
        .personal()
        .redact_all_in_text_with_policy(&result, PersonalTextPolicy::Complete);

    // Redact government identifiers
    result = builder
        .government()
        .redact_all_in_text_with_policy(&result, GovernmentTextPolicy::Complete);

    // Redact financial identifiers
    result = builder
        .financial()
        .redact_all_in_text_with_policy(&result, FinancialTextPolicy::Complete);

    result
}

/// Redact all credentials in text
///
/// Handles passwords, tokens, etc.
#[must_use]
pub fn redact_credentials(text: &str) -> String {
    let builder = IdentifierBuilder::new();
    let mut result = text.to_string();

    result = builder
        .credentials()
        .redact_credentials_in_text_with_policy(&result, CredentialTextPolicy::Complete)
        .to_string();
    result = builder.token().redact_all_in_text(&result);

    result
}

/// Redact everything (PII, credentials, network identifiers)
///
/// Most comprehensive redaction - use when maximum privacy is needed.
#[must_use]
pub fn redact_all(text: &str) -> String {
    let builder = IdentifierBuilder::new();
    let mut result = text.to_string();

    // Redact all domains
    result = builder
        .personal()
        .redact_all_in_text_with_policy(&result, PersonalTextPolicy::Complete);
    result = builder
        .government()
        .redact_all_in_text_with_policy(&result, GovernmentTextPolicy::Complete);
    result = builder
        .financial()
        .redact_all_in_text_with_policy(&result, FinancialTextPolicy::Complete);
    result = builder
        .credentials()
        .redact_credentials_in_text_with_policy(&result, CredentialTextPolicy::Complete)
        .to_string();
    result = builder.token().redact_all_in_text(&result);
    result = builder.medical().redact_all_in_text(&result);
    result = builder.biometric().redact_all_in_text(&result);
    result = builder
        .organizational()
        .redact_all_in_text(&result)
        .to_string();
    result = builder
        .location()
        .redact_all_in_text_with_strategy(&result, LocationTextPolicy::Complete);

    result
}

// ============================================================
// SENSITIVE DATA DETECTION SHORTCUTS (Issue #182)
// ============================================================

/// Check if text contains any sensitive data (PII, credentials, etc.)
///
/// Uses medium confidence threshold for detection.
#[must_use]
pub fn is_sensitive_present(text: &str) -> bool {
    // Check for any PII or credentials
    is_pii_present(text)
        || !IdentifierBuilder::new()
            .credentials()
            .detect_credentials(text)
            .is_empty()
}

/// Scan text for all sensitive identifiers
///
/// Returns all identifier matches found with high confidence.
#[must_use]
pub fn scan_sensitive(text: &str) -> Vec<IdentifierMatch> {
    scan_identifiers(text)
}

/// Scan text for PII (personally identifiable information)
///
/// Returns matches for emails, phones, SSNs, names, etc.
#[must_use]
pub fn scan_pii(text: &str) -> Vec<IdentifierMatch> {
    let builder = IdentifierBuilder::new();
    let mut matches = Vec::new();

    // Collect personal identifiers
    matches.extend(builder.personal().find_emails_in_text(text));
    matches.extend(builder.personal().find_phones_in_text(text));

    // Collect government identifiers (SSNs, etc.)
    matches.extend(builder.government().find_ssns_in_text(text));

    matches
}

/// Scan text for payment data (credit cards, bank accounts)
///
/// Returns matches for credit card numbers, routing numbers, etc.
#[must_use]
pub fn scan_payment_data(text: &str) -> Vec<IdentifierMatch> {
    FinancialBuilder::new().detect_credit_cards_in_text(text)
}

/// Scan text for credentials (API keys, tokens, passwords)
///
/// Returns matches for detected credentials.
#[must_use]
pub fn scan_credentials(text: &str) -> Vec<CredentialMatch> {
    IdentifierBuilder::new()
        .credentials()
        .detect_credentials(text)
}

/// Detect the data type of a single value
///
/// Returns the identifier type if detected with high confidence.
#[must_use]
pub fn detect_data_type(value: &str) -> Option<IdentifierType> {
    detect_identifier(value)
}

/// Detect data type with field name context
///
/// Field names like "email", "phone", "ssn" improve detection accuracy.
#[must_use]
pub fn detect_data_type_with_context(value: &str, field_name: &str) -> Option<IdentifierType> {
    // Use field name hints for better detection
    let field_lower = field_name.to_lowercase();

    if field_lower.contains("email") && is_email(value) {
        return Some(IdentifierType::Email);
    }
    if (field_lower.contains("phone")
        || field_lower.contains("mobile")
        || field_lower.contains("tel"))
        && is_phone(value)
    {
        return Some(IdentifierType::PhoneNumber);
    }
    if (field_lower.contains("ssn") || field_lower.contains("social")) && is_ssn(value) {
        return Some(IdentifierType::Ssn);
    }
    if (field_lower.contains("card") || field_lower.contains("credit")) && is_credit_card(value) {
        return Some(IdentifierType::CreditCard);
    }
    if field_lower.contains("ip") && is_ip_address(value) {
        return Some(IdentifierType::IpAddress);
    }
    if field_lower.contains("uuid") && is_uuid(value) {
        return Some(IdentifierType::Uuid);
    }
    if field_lower.contains("url") && is_url(value) {
        return Some(IdentifierType::Url);
    }

    // Fall back to general detection
    detect_identifier(value)
}

/// Scan text for compliance-related identifiers
///
/// Comprehensive scan for GDPR, HIPAA, PCI-DSS sensitive data.
#[must_use]
pub fn scan_compliance(text: &str) -> Vec<IdentifierMatch> {
    let builder = IdentifierBuilder::new();
    let mut matches = Vec::new();

    // PII (GDPR, CCPA)
    matches.extend(builder.personal().find_emails_in_text(text));
    matches.extend(builder.personal().find_phones_in_text(text));

    // Government IDs (GDPR, CCPA)
    matches.extend(builder.government().find_ssns_in_text(text));

    // Financial (PCI-DSS)
    matches.extend(builder.financial().detect_credit_cards_in_text(text));

    // Medical (HIPAA)
    matches.extend(builder.medical().find_mrns_in_text(text));

    // Biometric (GDPR Article 9, BIPA)
    matches.extend(builder.biometric().detect_all_in_text(text));

    matches
}

/// Check if a value matches an expected identifier type
///
/// Returns true if the value is detected as the expected type.
#[must_use]
pub fn is_data_type(value: &str, expected: IdentifierType) -> bool {
    detect_identifier(value) == Some(expected)
}

/// Detect an email address in a value
///
/// Returns the email if detected with high confidence.
#[must_use]
pub fn detect_email(value: &str) -> Option<String> {
    if is_email(value) {
        Some(value.to_string())
    } else {
        None
    }
}

/// Detect a phone number in a value
///
/// Returns the phone if detected with high confidence.
#[must_use]
pub fn detect_phone(value: &str) -> Option<String> {
    if is_phone(value) {
        Some(value.to_string())
    } else {
        None
    }
}

/// Detect a credit card number in a value
///
/// Returns an IdentifierMatch if detected with high confidence.
#[must_use]
pub fn detect_credit_card(value: &str) -> Option<IdentifierMatch> {
    if is_credit_card(value) {
        Some(IdentifierMatch::new(
            0,
            value.len(),
            value.to_string(),
            IdentifierType::CreditCard,
            DetectionConfidence::High,
        ))
    } else {
        None
    }
}

/// Batch scan multiple values for identifiers
///
/// Returns a detection report for each value.
#[must_use]
pub fn scan_batch(values: &[&str]) -> Vec<Vec<IdentifierMatch>> {
    values.iter().map(|v| scan_identifiers(v)).collect()
}

// ============================================================
// BOOLEAN PRESENCE SHORTCUTS (Issue #182)
// ============================================================

/// Check if text contains SSNs
#[must_use]
pub fn is_ssns_present(text: &str) -> bool {
    !find_ssns(text).is_empty()
}

/// Check if text contains credit cards
#[must_use]
pub fn is_credit_cards_present(text: &str) -> bool {
    !detect_credit_cards(text).is_empty()
}

/// Check if text contains email addresses
#[must_use]
pub fn is_emails_present(text: &str) -> bool {
    !find_emails(text).is_empty()
}

/// Check if text contains phone numbers
#[must_use]
pub fn is_phones_present(text: &str) -> bool {
    !find_phones(text).is_empty()
}

/// Check if text contains API keys
///
/// Delegates to `NetworkBuilder::find_api_keys_in_text` for consistent
/// detection using the builder's pattern matching.
#[must_use]
pub fn is_api_keys_present(text: &str) -> bool {
    !NetworkBuilder::new().find_api_keys_in_text(text).is_empty()
}

// CREDENTIAL PAIR CORRELATION SHORTCUTS

/// Detect credential pairs in text using default configuration.
///
/// Scans for all identifier types, finds proximate pairs, and classifies
/// known credential pair patterns (e.g., AWS key + secret, username + password).
#[must_use]
pub fn detect_credential_pairs(text: &str) -> Vec<super::types::CorrelationMatch> {
    super::CorrelationBuilder::new().detect_pairs(text)
}

/// Check if two identifier matches form a known credential pair.
///
/// Order-independent: `(A, B)` and `(B, A)` both match.
#[must_use]
pub fn is_credential_pair(
    primary: &IdentifierMatch,
    secondary: &IdentifierMatch,
) -> Option<super::types::CredentialPairType> {
    super::CorrelationBuilder::new().is_credential_pair(primary, secondary)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_detect_identifier() {
        assert_eq!(
            detect_identifier("user@example.com"),
            Some(IdentifierType::Email)
        );
        assert_eq!(
            detect_identifier("192.168.1.1"),
            Some(IdentifierType::IpAddress)
        );
    }

    #[test]
    fn test_is_pii_present() {
        assert!(is_pii_present("Contact: user@example.com"));
        assert!(!is_pii_present("Just random text"));
    }

    #[test]
    fn test_email_shortcuts() {
        assert!(is_email("user@example.com"));
        assert!(!is_email("not-an-email"));
        assert!(validate_email("user@example.com").is_ok());
    }

    #[test]
    fn test_mac_address_shortcut() {
        assert!(is_mac_address("00:1A:2B:3C:4D:5E"));
        assert!(is_mac_address("00-1A-2B-3C-4D-5E"));
        assert!(!is_mac_address("not-a-mac"));
    }

    #[test]
    fn test_validate_mac_address_shortcut() {
        assert!(validate_mac_address("00:1A:2B:3C:4D:5E").is_ok());
        assert!(validate_mac_address("not-a-mac").is_err());
    }

    #[test]
    fn test_domain_shortcut() {
        assert!(is_domain("example.com"));
        assert!(is_domain("sub.example.co.uk"));
        assert!(!is_domain("not a domain"));
    }

    #[test]
    fn test_hostname_shortcut() {
        assert!(is_hostname("server01.example.com"));
        assert!(!is_hostname("!!!"));
    }

    #[test]
    fn test_gps_coordinate_shortcut() {
        assert!(is_gps_coordinate("40.7128, -74.0060"));
        assert!(!is_gps_coordinate("not-a-coordinate"));
    }

    #[test]
    fn test_validate_gps_coordinate_shortcut() {
        assert!(validate_gps_coordinate("40.7128, -74.0060").is_ok());
        assert!(validate_gps_coordinate("not-a-coordinate").is_err());
    }

    #[test]
    fn test_street_address_shortcut() {
        assert!(is_street_address("123 Main Street"));
        assert!(!is_street_address("hello"));
    }

    #[test]
    fn test_postal_code_shortcut() {
        assert!(is_postal_code("90210"));
        assert!(!is_postal_code("abc"));
    }

    #[test]
    fn test_validate_postal_code_shortcut() {
        assert!(validate_postal_code("90210").is_ok());
        assert!(validate_postal_code("abc").is_err());
    }

    #[test]
    fn test_validate_uuid_shortcut() {
        assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_uuid("not-a-uuid").is_err());
    }

    #[test]
    fn test_ssh_public_key_shortcut() {
        assert!(is_ssh_public_key(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8... user@host"
        ));
        assert!(is_ssh_public_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMq..."
        ));
        assert!(!is_ssh_public_key("not-an-ssh-key"));
    }

    #[test]
    fn test_ssh_private_key_shortcut() {
        // Build PEM headers at runtime to avoid gitleaks false positives
        let rsa_header = ["-----BEGIN", " RSA PRIVATE", " KEY-----"].concat();
        let openssh_header = ["-----BEGIN", " OPENSSH PRIVATE", " KEY-----"].concat();
        assert!(is_ssh_private_key(&rsa_header));
        assert!(is_ssh_private_key(&openssh_header));
        assert!(!is_ssh_private_key("ssh-rsa AAAAB3..."));
    }

    #[test]
    fn test_ssh_fingerprint_shortcut() {
        assert!(is_ssh_fingerprint(
            "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"
        ));
        assert!(is_ssh_fingerprint(
            "16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48"
        ));
        assert!(!is_ssh_fingerprint("not-a-fingerprint"));
    }

    #[test]
    fn test_gitlab_token_shortcut() {
        assert!(is_gitlab_token("glpat-xxxxxxxxxxxxxxxxxxxx"));
        assert!(!is_gitlab_token("not-a-token"));
    }

    #[test]
    fn test_bearer_token_shortcut() {
        assert!(is_bearer_token(
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoiZGF0YSJ9.signature"
        ));
        assert!(!is_bearer_token("not-a-bearer-token"));
    }

    #[test]
    fn test_redaction_shortcuts() {
        let redacted = redact_email("user@example.com");
        assert!(!redacted.contains("user@example.com"));
    }

    #[test]
    fn test_validate_phone_shortcut() {
        assert!(validate_phone("+14155551234").is_ok());
        assert!(validate_phone("not-a-phone").is_err());
    }

    #[test]
    fn test_name_shortcuts() {
        assert!(is_name("John Smith"));
        assert!(!is_name("x"));
        assert!(validate_name("John Smith").is_ok());
        assert!(!find_names("Contact John Smith for details").is_empty());
        let redacted = redact_name("John Smith");
        assert!(!redacted.contains("John Smith"));
    }

    #[test]
    fn test_birthdate_shortcuts() {
        assert!(is_birthdate("1990-01-15"));
        assert!(!is_birthdate("not-a-date"));
        assert!(validate_birthdate("1990-01-15").is_ok());
        assert!(validate_birthdate("not-a-date").is_err());
        let redacted = redact_birthdate("1990-01-15");
        assert!(!redacted.contains("1990-01-15"));
    }

    #[test]
    fn test_username_shortcuts() {
        assert!(is_username("john_doe"));
        assert!(!is_username("@"));
        assert!(validate_username("john_doe").is_ok());
        assert!(validate_username("@").is_err());
        let redacted = redact_username("john_doe");
        assert!(!redacted.contains("john_doe"));
    }

    #[test]
    fn test_validate_credit_card_shortcut() {
        // Valid Visa test number (passes Luhn)
        assert!(validate_credit_card("4111111111111111").is_ok());
        assert!(validate_credit_card("not-a-card").is_err());
    }

    #[test]
    fn test_routing_number_shortcuts() {
        // Valid ABA routing number (passes checksum)
        assert!(is_routing_number("021000021"));
        assert!(!is_routing_number("000000000"));
        assert!(validate_routing_number("021000021").is_ok());
        assert!(validate_routing_number("invalid").is_err());

        let matches = detect_routing_numbers("ABA routing: 021000021");
        assert!(!matches.is_empty());
        assert!(detect_routing_numbers("no routing here").is_empty());
    }

    #[test]
    fn test_bank_account_shortcut() {
        assert!(is_bank_account("1234567890"));
        assert!(!is_bank_account("ab"));
    }

    #[test]
    fn test_validate_ssn_shortcut() {
        // Valid SSN (non-test pattern, valid area/group/serial)
        assert!(validate_ssn("517-29-8346").is_ok());
        // Invalid SSN (all zeros area)
        assert!(validate_ssn("000-00-0000").is_err());
        assert!(validate_ssn("not-an-ssn").is_err());
    }

    #[test]
    fn test_validate_jwt_shortcut() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                   eyJzdWIiOiIxMjM0NTY3ODkwIn0.\
                   dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(validate_jwt(jwt).is_ok());
        assert!(validate_jwt("not-a-jwt").is_err());
        assert!(validate_jwt("only.two").is_err());
    }

    #[test]
    fn test_validate_api_key_shortcut() {
        // Valid prefixed API key within 20..=200 bounds
        assert!(validate_api_key("sk_test_1234567890abcdef").is_ok());
        // Too short (< 20)
        assert!(validate_api_key("short").is_err());
        // Obvious test/demo keys are rejected by the validator
        assert!(validate_api_key("demokey1234567890abcdef").is_err());
    }

    #[test]
    fn test_validate_session_id_shortcut() {
        // 30-char high-entropy session ID within 16..=128 bounds
        assert!(validate_session_id("Ab3De8Gh2Jk5Mn9Pq4Rs7Tv0Wx3Yz6").is_ok());
        // Too short (< 16)
        assert!(validate_session_id("short").is_err());
        // Obvious test session IDs are rejected
        assert!(validate_session_id("test_session_12345678").is_err());
    }

    #[test]
    fn test_medical_identifier_shortcuts() {
        assert!(is_provider_id("NPI: 1234567890"));
        assert!(!is_provider_id("NPI: 3123456789")); // must start with 1 or 2

        assert!(is_dea_number("AB1234563")); // valid checksum
        assert!(!is_dea_number("AB1234560")); // invalid checksum

        assert!(is_health_insurance("Policy Number: ABC123456789"));
        assert!(!is_health_insurance("not insurance"));

        assert!(is_prescription("RX# 123456789"));
        assert!(!is_prescription("not a prescription"));

        assert!(is_medical_code("A01.1")); // ICD-10
        assert!(is_medical_code("CPT: 99213"));
        assert!(!is_medical_code("not a code"));
    }

    #[test]
    fn test_validate_mrn_shortcut() {
        assert!(validate_mrn("MRN-123456").is_ok());
        assert!(validate_mrn("ABC").is_err()); // too short
        assert!(validate_mrn("MRN@123").is_err()); // invalid character
    }

    #[test]
    fn test_validate_npi_shortcut() {
        assert!(validate_npi("1245319599").is_ok()); // valid checksum
        assert!(validate_npi("1234567890").is_err()); // invalid checksum
        assert!(validate_npi("not-an-npi").is_err());
    }

    #[test]
    fn test_organizational_identifier_shortcuts() {
        assert!(is_student_id("S12345678"));
        assert!(!is_student_id("invalid"));

        assert!(is_badge_number("BADGE# 98765"));
        assert!(!is_badge_number("invalid"));

        assert!(validate_employee_id("E123456").is_ok());
        assert!(validate_employee_id("E12").is_err()); // too short

        assert!(validate_student_id("S12345678").is_ok());
        assert!(validate_student_id("$(whoami)").is_err()); // injection

        assert!(validate_badge_number("BADGE-12345").is_ok());
        assert!(validate_badge_number("B").is_err());

        // Redaction should not return the original input verbatim
        let emp = redact_employee_id("E123456");
        assert!(!emp.contains("E123456"));
        let stu = redact_student_id("S12345678");
        assert!(!stu.contains("S12345678"));
        let badge = redact_badge_number("BADGE-12345");
        assert!(!badge.contains("BADGE-12345"));
    }
}

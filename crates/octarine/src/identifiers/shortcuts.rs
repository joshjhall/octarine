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
    CredentialTextPolicy, CreditCardRedactionStrategy, EmailRedactionStrategy,
    GovernmentTextPolicy, IpRedactionStrategy, PersonalTextPolicy, PhoneRedactionStrategy,
    SsnRedactionStrategy,
};

use super::types::{
    CredentialMatch, DetectionConfidence, FinancialTextPolicy, IdentifierMatch, IdentifierType,
    LocationTextPolicy,
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
// SSN SHORTCUTS
// ============================================================

/// Check if value is an SSN
#[must_use]
pub fn is_ssn(value: &str) -> bool {
    GovernmentBuilder::new().is_ssn(value)
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

/// Redact all credit cards in text
#[must_use]
pub fn redact_credit_cards(text: &str) -> String {
    FinancialBuilder::new()
        .redact_credit_cards_in_text_with_strategy(text, CreditCardRedactionStrategy::ShowLast4)
        .to_string()
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

// ============================================================
// JWT SHORTCUTS
// ============================================================

/// Check if value is a JWT token
#[must_use]
pub fn is_jwt(value: &str) -> bool {
    TokenBuilder::new().is_jwt(value)
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
// MEDICAL SHORTCUTS (HIPAA)
// ============================================================

/// Check if value is a medical record number
#[must_use]
pub fn is_medical_record_number(value: &str) -> bool {
    MedicalBuilder::new().is_mrn(value)
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
    fn test_redaction_shortcuts() {
        let redacted = redact_email("user@example.com");
        assert!(!redacted.contains("user@example.com"));
    }
}

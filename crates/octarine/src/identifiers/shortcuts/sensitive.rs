//! Sensitive-data scanning and boolean presence shortcuts (issue #182).
//!
//! Higher-level helpers that compose the per-domain shortcuts for
//! field-aware detection, compliance-oriented scans, and boolean presence checks.

use super::super::IdentifierBuilder;
use super::super::types::{CredentialMatch, DetectionConfidence, IdentifierMatch, IdentifierType};
use super::detection::{is_pii_present, scan_identifiers};
use super::financial::{detect_credit_cards, is_credit_card};
use super::government::{find_ssns, is_ssn};
use super::network::{is_ip_address, is_url, is_uuid};
use super::personal::{find_emails, find_phones, is_email, is_phone};

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
    IdentifierBuilder::new()
        .financial()
        .detect_credit_cards_in_text(text)
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
    super::detection::detect_identifier(value)
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
    super::detection::detect_identifier(value)
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
    super::detection::detect_identifier(value) == Some(expected)
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
    !super::super::NetworkBuilder::new()
        .find_api_keys_in_text(text)
        .is_empty()
}

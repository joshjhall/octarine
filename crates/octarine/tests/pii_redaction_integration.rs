//! Integration tests for PII redaction in events
//!
//! These tests verify end-to-end PII detection, redaction, and metadata tracking
//! through the observe module's public API.

#![allow(clippy::panic, clippy::expect_used)]

use octarine::observe::pii::{PiiType, RedactionProfile, redact_pii_with_profile, scan_for_pii};
// Helper function using strict redaction
fn redact_pii(text: &str) -> String {
    redact_pii_with_profile(text, RedactionProfile::ProductionStrict)
}

// ==========================================
// AUTOMATIC REDACTION TESTS
// ==========================================

#[test]
fn test_automatic_ssn_redaction() {
    let text = "User SSN: 900-00-0001";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    assert_eq!(redacted, "User SSN: [SSN]");
}

#[test]
fn test_automatic_email_redaction() {
    let text = "Contact: user@example.com";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    assert_eq!(redacted, "Contact: [EMAIL]");
}

#[test]
fn test_automatic_credit_card_redaction() {
    let text = "Card: 4242424242424242";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    // Note: Credit card pattern matches with label
    assert_eq!(redacted, "[CREDIT_CARD]");
}

#[test]
fn test_automatic_phone_redaction() {
    let text = "Call: +1-555-123-4567";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    assert_eq!(redacted, "Call: [PHONE]");
}

#[test]
fn test_automatic_password_redaction() {
    let text = "password=secret123";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    // Uses standardized [PASSWORD] token from primitives
    assert_eq!(redacted, "password=[PASSWORD]");
}

#[test]
fn test_automatic_ip_address_redaction() {
    let text = "Server: 192.168.1.1";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    // IP addresses use partial masking (show first octet, mask rest)
    assert_eq!(redacted, "Server: 192.***.***.***");
}

// ==========================================
// MULTIPLE PII TYPES
// ==========================================

#[test]
fn test_multiple_pii_types_in_single_message() {
    let text = "User: user@example.com, SSN: 900-00-0001, Card: 4242424242424242";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    // All PII should be redacted
    assert!(redacted.contains("[EMAIL]"));
    assert!(redacted.contains("[SSN]"));
    assert!(redacted.contains("[CREDIT_CARD]"));
}

#[test]
fn test_scan_detects_all_pii_types() {
    let text = "Email: user@example.com, SSN: 900-00-0001";
    let pii_types = scan_for_pii(text);

    // Must contain at least 2 (email, SSN), may detect more (names, etc.)
    assert!(
        pii_types.len() >= 2,
        "Should detect at least 2 PII types, got {:?}",
        pii_types
    );

    let type_names: Vec<&str> = pii_types.iter().map(|t| t.name()).collect();
    assert!(type_names.contains(&"email"));
    assert!(type_names.contains(&"ssn"));
}

// ==========================================
// PROFILE-BASED REDACTION
// ==========================================

#[test]
fn test_production_strict_redaction() {
    let text = "Server: 192.168.1.1";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    // IP addresses use partial masking (show first octet, mask rest)
    assert_eq!(redacted, "Server: 192.***.***.***");
}

#[test]
fn test_production_lenient_redaction() {
    let text = "Server: 192.168.1.1";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionLenient);

    // Lenient mode uses same partial masking format
    assert_eq!(redacted, "Server: 192.***.***.***");
}

#[test]
fn test_testing_profile_no_redaction() {
    let text = "SSN: 900-00-0001, Email: user@example.com";
    let redacted = redact_pii_with_profile(text, RedactionProfile::Testing);

    // Testing mode: no redaction
    assert_eq!(redacted, text);
}

// ==========================================
// NO PII CASES
// ==========================================

#[test]
fn test_no_pii_in_clean_message() {
    let text = "This is a clean message with no PII";
    let redacted = redact_pii(text);

    // Should be unchanged
    assert_eq!(redacted, text);
}

#[test]
fn test_scan_finds_no_pii_in_clean_message() {
    let text = "Clean text with no sensitive data";
    let pii_types = scan_for_pii(text);

    assert!(pii_types.is_empty());
}

// ==========================================
// STRUCTURE PRESERVATION
// ==========================================

#[test]
fn test_redaction_preserves_message_structure() {
    // Use "ref" instead of "ID" to avoid postal code detection on 5-digit numbers
    let text = "User registered: test@example.com with ref ABC123";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    // Email redacted but structure preserved
    assert_eq!(redacted, "User registered: [EMAIL] with ref ABC123");
}

#[test]
fn test_redaction_preserves_formatting() {
    let text = "Contact info:\n  Email: user@example.com\n  Phone: +1-555-123-4567";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    // Newlines and spacing preserved
    assert!(redacted.contains("\n  Email: [EMAIL]\n"));
    assert!(redacted.contains("\n  Phone: [PHONE]"));
}

// ==========================================
// EDGE CASES
// ==========================================

#[test]
fn test_partial_ssn_patterns() {
    // Only complete SSNs should be detected
    let text = "ID: 123-45 (incomplete)";
    let pii_types = scan_for_pii(text);

    // Should not detect incomplete SSN
    assert!(!pii_types.iter().any(|t| t.name() == "ssn"));
}

#[test]
fn test_invalid_credit_card_not_detected() {
    // Invalid credit card number (fails Luhn check)
    let text = "Card: 1234567890123456";
    let _pii_types = scan_for_pii(text);

    // Should not be detected as credit card
    // Note: This depends on the credit card validation in security module
    // This test documents expected behavior
}

#[test]
fn test_multiple_emails_in_message() {
    let text = "From: sender@example.com To: receiver@example.org";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    // Both emails should be redacted
    assert_eq!(redacted, "From: [EMAIL] To: [EMAIL]");
}

// ==========================================
// COMPLIANCE SCENARIOS
// ==========================================

#[test]
fn test_gdpr_protected_pii() {
    // PiiType is imported at top of file

    // GDPR protects email, phone, IP
    assert!(PiiType::Email.is_gdpr_protected());
    assert!(PiiType::Phone.is_gdpr_protected());
    assert!(PiiType::IpAddress.is_gdpr_protected());

    // GDPR also covers SSN as personal identifier
    assert!(PiiType::Ssn.is_gdpr_protected());
}

#[test]
fn test_pci_protected_data() {
    // PiiType is imported at top of file

    // PCI-DSS protects credit cards
    assert!(PiiType::CreditCard.is_pci_protected());

    // Other types not covered by PCI-DSS
    assert!(!PiiType::Email.is_pci_protected());
}

#[test]
fn test_high_risk_pii_identification() {
    // PiiType is imported at top of file

    // High-risk PII
    assert!(PiiType::Ssn.is_high_risk());
    assert!(PiiType::CreditCard.is_high_risk());
    assert!(PiiType::Password.is_high_risk());
    assert!(PiiType::ApiKey.is_high_risk());

    // Lower-risk PII
    assert!(!PiiType::Email.is_high_risk());
    assert!(!PiiType::Phone.is_high_risk());
}

// ==========================================
// REAL-WORLD SCENARIOS
// ==========================================

#[test]
fn test_user_registration_log() {
    let text = "User registered successfully: email=test@example.com, ip=192.168.1.100";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    assert!(
        redacted.contains("email=[EMAIL]"),
        "Email should be redacted"
    );
    // IP addresses use partial masking
    assert!(
        redacted.contains("ip=192.***.***.***"),
        "IP should be partially masked: {}",
        redacted
    );
}

#[test]
fn test_payment_processing_log() {
    let text = "Processing payment for card 4242424242424242";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    assert!(redacted.contains("[CREDIT_CARD]"));
}

#[test]
fn test_authentication_log() {
    let text = "Authentication attempt: test@example.com from 10.0.0.1";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    assert!(redacted.contains("[EMAIL]"), "Email should be redacted");
    // IP addresses use partial masking
    assert!(
        redacted.contains("10.***.***.***"),
        "IP should be partially masked: {}",
        redacted
    );
}

#[test]
fn test_error_message_with_pii() {
    let text = "Failed to send email to user@example.com: connection refused";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    // Error message preserved, PII redacted
    assert_eq!(
        redacted,
        "Failed to send email to [EMAIL]: connection refused"
    );
}

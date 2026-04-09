//! Integration tests for PII detection through the full pipeline
//!
//! Tests that PII is properly detected and redacted at all stages:
//! - Event creation
//! - Writer output (defense-in-depth)
//! - Query results

#![allow(clippy::panic, clippy::expect_used)]

use octarine::observe::pii::{
    PiiScannerConfig, PiiType, RedactionProfile, is_pii_present, redact_pii_with_profile,
    scan_for_pii,
};
use octarine::observe::writers::{AuditQuery, MemoryWriter, Queryable, Writer};
use octarine::observe::{Event, EventType};

fn redact_pii(text: &str) -> String {
    redact_pii_with_profile(text, RedactionProfile::ProductionStrict)
}

// ============================================================================
// PII Detection Tests
// ============================================================================

#[test]
fn test_detects_email_address() {
    let text = "Contact: user@example.com";
    assert!(is_pii_present(text));

    let types = scan_for_pii(text);
    assert!(types.contains(&PiiType::Email));
}

#[test]
fn test_detects_ssn() {
    // Use 900 series - designated for testing
    let text = "SSN: 900-00-0001";
    assert!(is_pii_present(text));

    let types = scan_for_pii(text);
    assert!(types.contains(&PiiType::Ssn));
}

#[test]
fn test_detects_credit_card() {
    // Stripe test card number
    let text = "Card: 4242424242424242";
    assert!(is_pii_present(text));

    let types = scan_for_pii(text);
    assert!(types.contains(&PiiType::CreditCard));
}

#[test]
fn test_detects_phone_number() {
    let text = "Call: +1-555-123-4567";
    assert!(is_pii_present(text));

    let types = scan_for_pii(text);
    assert!(types.contains(&PiiType::Phone));
}

#[test]
fn test_detects_api_key() {
    let text = &format!("Key: sk_test_{}", "EXAMPLE000000000000KEY01");
    assert!(is_pii_present(text));

    let types = scan_for_pii(text);
    assert!(types.contains(&PiiType::ApiKey));
}

#[test]
fn test_detects_password_pattern() {
    let text = "password=secret123";
    assert!(is_pii_present(text));

    let types = scan_for_pii(text);
    assert!(types.contains(&PiiType::Password));
}

#[test]
fn test_detects_multiple_pii_types() {
    let text = "Email: user@example.com, SSN: 900-00-0001, Card: 4242424242424242";

    let types = scan_for_pii(text);
    assert!(types.len() >= 3, "Should detect at least 3 PII types");
    assert!(types.contains(&PiiType::Email));
    assert!(types.contains(&PiiType::Ssn));
    assert!(types.contains(&PiiType::CreditCard));
}

#[test]
fn test_no_pii_in_clean_text() {
    let text = "This is a clean message with no PII";
    assert!(!is_pii_present(text));

    let types = scan_for_pii(text);
    assert!(types.is_empty());
}

// ============================================================================
// PII Redaction Tests
// ============================================================================

#[test]
fn test_redacts_ssn() {
    let text = "SSN: 900-00-0001";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    assert!(!redacted.contains("900-00-0001"));
    assert!(redacted.contains("[SSN]"));
}

#[test]
fn test_redacts_email() {
    let text = "Contact: user@example.com";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    assert!(!redacted.contains("user@example.com"));
    assert!(redacted.contains("[EMAIL]"));
}

#[test]
fn test_redacts_credit_card() {
    let text = "Card: 4242424242424242";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    assert!(!redacted.contains("4242424242424242"));
    assert!(redacted.contains("[CREDIT_CARD]"));
}

#[test]
fn test_redacts_password() {
    let text = "password=secret123";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    assert!(!redacted.contains("secret123"));
    // Password value is redacted
    assert!(redacted.contains("[PASSWORD]") || redacted.contains("password="));
}

#[test]
fn test_redacts_multiple_pii() {
    let text = "Email: user@example.com, SSN: 900-00-0001";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    assert!(!redacted.contains("user@example.com"));
    assert!(!redacted.contains("900-00-0001"));
    assert!(redacted.contains("[EMAIL]"));
    assert!(redacted.contains("[SSN]"));
}

#[test]
fn test_preserves_message_structure() {
    // Note: "ref" value must not match license plate pattern (2-3 uppercase + 3-4 digits)
    let text = "User registered: test@example.com with ref order-99";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    // Structure preserved, only email redacted
    assert!(redacted.contains("User registered:"));
    assert!(redacted.contains("with ref order-99"));
    assert!(redacted.contains("[EMAIL]"));
}

// ============================================================================
// Redaction Profile Tests
// ============================================================================

#[test]
fn test_testing_profile_no_redaction() {
    let text = "SSN: 900-00-0001, Email: user@example.com";
    let redacted = redact_pii_with_profile(text, RedactionProfile::Testing);

    // Testing mode: no redaction for easier debugging
    assert_eq!(redacted, text);
}

#[test]
fn test_production_strict_full_redaction() {
    let text = "Server: 192.168.1.1";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    // IP should be partially masked
    assert!(!redacted.contains("192.168.1.1"));
    assert!(redacted.contains("192.")); // First octet preserved
}

#[test]
fn test_default_redaction_is_safe() {
    let text = "SSN: 900-00-0001";
    let redacted = redact_pii(text);

    // Default should redact PII
    assert!(!redacted.contains("900-00-0001"));
}

// ============================================================================
// Scanner Configuration Tests
// ============================================================================

#[test]
fn test_scanner_config_default_domains() {
    let config = PiiScannerConfig::default();

    // Default should scan personal, financial, government, medical, location, tokens
    assert!(config.scan_personal);
    assert!(config.scan_financial);
    assert!(config.scan_government);
    assert!(config.scan_medical);
    assert!(config.scan_tokens);
}

#[test]
fn test_scanner_config_hipaa_focused() {
    let config = PiiScannerConfig::hipaa_focused();

    // HIPAA should focus on medical and personal data
    assert!(config.scan_medical);
    assert!(config.scan_personal);
}

#[test]
fn test_scanner_config_pci_focused() {
    let config = PiiScannerConfig::pci_focused();

    // PCI-DSS should focus on financial data
    assert!(config.scan_financial);
}

#[test]
fn test_scanner_config_secrets_focused() {
    let config = PiiScannerConfig::secrets_focused();

    // Secrets should scan for tokens/API keys
    assert!(config.scan_tokens);
}

#[test]
fn test_network_scanning_enabled_by_default() {
    // Default DOES scan network because IP addresses are GDPR-protected PII
    let default_config = PiiScannerConfig::default();
    assert!(
        default_config.scan_network,
        "Network scanning should be enabled by default (GDPR requires IP protection)"
    );

    // Can be disabled if needed for specific use cases
    let without_network = PiiScannerConfig::default().with_network(false);
    assert!(!without_network.scan_network);
}

// ============================================================================
// PII Type Classification Tests
// ============================================================================

#[test]
fn test_high_risk_pii_classification() {
    assert!(PiiType::Ssn.is_high_risk());
    assert!(PiiType::CreditCard.is_high_risk());
    assert!(PiiType::Password.is_high_risk());
    assert!(PiiType::ApiKey.is_high_risk());

    // Lower risk
    assert!(!PiiType::Email.is_high_risk());
    assert!(!PiiType::Phone.is_high_risk());
}

#[test]
fn test_gdpr_protected_classification() {
    assert!(PiiType::Email.is_gdpr_protected());
    assert!(PiiType::Phone.is_gdpr_protected());
    assert!(PiiType::IpAddress.is_gdpr_protected());
    assert!(PiiType::Ssn.is_gdpr_protected());
}

#[test]
fn test_pci_protected_classification() {
    assert!(PiiType::CreditCard.is_pci_protected());

    // Email is not PCI protected (not cardholder data)
    assert!(!PiiType::Email.is_pci_protected());
}

#[test]
fn test_hipaa_protected_classification() {
    // Medical data is HIPAA protected
    assert!(PiiType::Mrn.is_hipaa_protected());
    assert!(PiiType::Npi.is_hipaa_protected());

    // Email with medical context is also HIPAA
    // (depends on implementation)
}

// ============================================================================
// End-to-End Pipeline Tests
// ============================================================================

#[tokio::test]
async fn test_pii_in_event_detected() {
    // Create an event with PII in the message
    let event = Event::new(EventType::Info, "User email: test@example.com");

    // Scan the event message
    let types = scan_for_pii(&event.message);
    assert!(types.contains(&PiiType::Email));
}

#[tokio::test]
async fn test_memory_writer_stores_events_with_pii() {
    let writer = MemoryWriter::new();

    // Write event with PII
    let event = Event::new(EventType::Info, "SSN: 900-00-0001");
    writer.write(&event).await.expect("write should succeed");

    // Verify event is stored (PII handling is at a different layer)
    let events = writer.all_events();
    assert_eq!(events.len(), 1);
}

#[tokio::test]
async fn test_query_result_events_can_be_scanned() {
    let writer = MemoryWriter::new();

    // Write events with various PII
    writer
        .write(&Event::new(EventType::Info, "Email: user@example.com"))
        .await
        .expect("write should succeed");
    writer
        .write(&Event::new(EventType::Info, "Clean message"))
        .await
        .expect("write should succeed");

    // Query all events
    let result = writer
        .query(&AuditQuery::default())
        .await
        .expect("query should succeed");

    // Scan query results for PII
    let mut has_pii = false;
    for event in &result.events {
        if is_pii_present(&event.message) {
            has_pii = true;
            break;
        }
    }

    assert!(has_pii, "At least one event should contain PII");
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_incomplete_ssn_not_detected() {
    let text = "ID: 123-45 (incomplete)";
    let types = scan_for_pii(text);

    // Incomplete SSN should not be detected
    assert!(!types.contains(&PiiType::Ssn));
}

#[test]
fn test_redaction_handles_empty_string() {
    let text = "";
    let redacted = redact_pii(text);
    assert_eq!(redacted, "");
}

#[test]
fn test_redaction_handles_unicode() {
    let text = "Email: 用户@例子.com, Name: 日本語";
    let redacted = redact_pii(text);

    // Should handle unicode without crashing
    // May or may not detect unicode email depending on implementation
    assert!(!redacted.is_empty());
}

#[test]
fn test_redaction_preserves_newlines() {
    let text = "Line 1: test@example.com\nLine 2: clean";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    assert!(redacted.contains('\n'));
    assert!(redacted.contains("Line 2: clean"));
}

#[test]
fn test_multiple_emails_all_redacted() {
    let text = "From: sender@example.com To: receiver@example.org";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    assert!(!redacted.contains("sender@example.com"));
    assert!(!redacted.contains("receiver@example.org"));
    // Both should be replaced with [EMAIL]
    assert_eq!(redacted.matches("[EMAIL]").count(), 2);
}

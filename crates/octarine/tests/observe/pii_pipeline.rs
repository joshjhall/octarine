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
    // 517-29-8346: SSA-valid area, group, and serial; safe SSN test value
    let text = "SSN: 517-29-8346";
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
    // Stripe-prefixed key now resolves to PiiType::StripeKey (issue #97).
    // Generic ApiKey is reserved as the fallback for unrecognized
    // api-key-shaped input.
    let text = &format!("Key: sk_test_{}", "EXAMPLE000000000000KEY01");
    assert!(is_pii_present(text));

    let types = scan_for_pii(text);
    assert!(types.contains(&PiiType::StripeKey));
    assert!(!types.contains(&PiiType::ApiKey));
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
    let text = "Email: user@example.com, SSN: 517-29-8346, Card: 4242424242424242";

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
    let text = "SSN: 517-29-8346";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    assert!(!redacted.contains("517-29-8346"));
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
    let text = "Email: user@example.com, SSN: 517-29-8346";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    assert!(!redacted.contains("user@example.com"));
    assert!(!redacted.contains("517-29-8346"));
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
    let text = "SSN: 517-29-8346, Email: user@example.com";
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
    let text = "SSN: 517-29-8346";
    let redacted = redact_pii(text);

    // Default should redact PII
    assert!(!redacted.contains("517-29-8346"));
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
    let event = Event::new(EventType::Info, "SSN: 517-29-8346");
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

#[test]
fn test_detects_hostname_in_scan() {
    let text = "Deploy to db-prod-01 and verify cache:8080 is healthy.";
    let types = scan_for_pii(text);
    assert!(
        types.contains(&PiiType::Hostname),
        "expected PiiType::Hostname in {types:?}",
    );
}

#[test]
fn test_detects_port_in_scan() {
    let text = "Service listens on :8080 and :443.";
    let types = scan_for_pii(text);
    assert!(
        types.contains(&PiiType::Port),
        "expected PiiType::Port in {types:?}",
    );
}

// ============================================================================
// Provider-specific token attribution (issue #97)
//
// Each test confirms that a recognizable provider token is reported with its
// dedicated PiiType variant and that the generic ApiKey fallback is suppressed.
// Fixtures are constructed via format!() to avoid pre-commit secret-scanner
// false positives — same convention as the unit tests in
// primitives/identifiers/token/detection/mod.rs.
// ============================================================================

fn assert_provider(text: &str, expected: PiiType) {
    let types = scan_for_pii(text);
    assert!(
        types.contains(&expected),
        "expected {expected:?} in {types:?} for input {text:?}"
    );
    assert!(
        !types.contains(&PiiType::ApiKey),
        "generic ApiKey should be suppressed when {expected:?} matches; got {types:?}"
    );
}

#[test]
fn test_detects_github_token() {
    assert_provider(
        &format!("token: ghp_{}", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"),
        PiiType::GitHubToken,
    );
}

#[test]
fn test_detects_gitlab_token() {
    assert_provider(
        &format!("Auth: glpat-{}", "xxxxxxxxxxxxxxxxxxxx"),
        PiiType::GitLabToken,
    );
}

#[test]
fn test_detects_bitbucket_token() {
    assert_provider(&format!("ATBB{}", "x".repeat(32)), PiiType::BitbucketToken);
}

#[test]
fn test_detects_aws_access_key() {
    let akia = format!("AKIA{}", "IOSFODNN7EXAMPLE");
    assert_provider(&format!("AWS_KEY={akia}"), PiiType::AwsAccessKey);
}

// AwsSessionToken is intentionally not tested here. The session-token regex
// (`[A-Za-z0-9/+=]{100,}`) is a strict superset of the AWS secret-key regex
// (`[A-Za-z0-9/+=]{40}`) which is checked first in `detect_token_type`,
// and AwsSecretKey routes to PiiType::ApiKey by design (see plan §F.4 —
// AWS secret keys are indistinguishable from random high-entropy strings
// without context). Real session-token attribution requires the
// `is_aws_session_token` short-circuit on the From<IdentifierType> path,
// which is exercised by the unit test
// `from_identifier_type_fallback_mappings` in observe/pii/types.rs.

#[test]
fn test_detects_gcp_api_key() {
    // Constructed via format! so gitleaks doesn't flag a literal AIza key.
    let key = format!("AIza{}", "SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe");
    assert_provider(&format!("GOOGLE_KEY={key}"), PiiType::GcpApiKey);
}

#[test]
fn test_detects_azure_key() {
    let key = format!(
        "AccountKey={}",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopqrstuvwx=="
    );
    assert_provider(&key, PiiType::AzureKey);
}

#[test]
fn test_detects_stripe_key() {
    assert_provider(
        &format!("STRIPE=sk_live_{}", "EXAMPLE000000000KEY01abcdef"),
        PiiType::StripeKey,
    );
}

#[test]
fn test_detects_square_token() {
    assert_provider(
        &format!("token=sq0atp-{}", "ABCDEFghijklmnopqrstuv"),
        PiiType::SquareToken,
    );
}

#[test]
fn test_detects_shopify_token() {
    assert_provider(
        &format!("shpat_{}", "abcdef1234567890abcdef1234567890"),
        PiiType::ShopifyToken,
    );
}

#[test]
fn test_detects_paypal_token() {
    assert_provider(
        &format!(
            "access_token$production${}${}",
            "abc1234567890xyz", "abcdef1234567890abcdef1234567890"
        ),
        PiiType::PayPalToken,
    );
}

#[test]
fn test_detects_mailchimp_token() {
    assert_provider(
        &format!("{}{}-us6", "abcdef1234567890", "abcdef1234567890"),
        PiiType::MailchimpToken,
    );
}

#[test]
fn test_detects_mailgun_token() {
    assert_provider(
        &format!("key-{}", "ABCDEFghijklmnopqrstuv1234567890"),
        PiiType::MailgunToken,
    );
}

#[test]
fn test_detects_resend_token() {
    assert_provider(
        &format!("re_{}", "ABCDEFghijklmnopqrstuv1234567890ab"),
        PiiType::ResendToken,
    );
}

#[test]
fn test_detects_brevo_token() {
    assert_provider(
        &format!("xkeysib-{}-{}", "a".repeat(64), "B".repeat(16)),
        PiiType::BrevoToken,
    );
}

#[test]
fn test_detects_databricks_token() {
    assert_provider(&format!("dapi{}", "a".repeat(32)), PiiType::DatabricksToken);
}

#[test]
fn test_detects_vault_token() {
    assert_provider(&format!("hvs.{}", "A".repeat(24)), PiiType::VaultToken);
}

#[test]
fn test_detects_cloudflare_origin_ca_key() {
    assert_provider(
        &format!("v1.0-{}-{}", "a".repeat(24), "b".repeat(146)),
        PiiType::CloudflareOriginCaKey,
    );
}

#[test]
fn test_detects_npm_token() {
    assert_provider(&format!("npm_{}", "A".repeat(36)), PiiType::NpmToken);
}

#[test]
fn test_detects_pypi_token() {
    assert_provider(
        &format!("pypi-AgEIcHlwaS5vcmc{}", "A".repeat(50)),
        PiiType::PyPiToken,
    );
}

#[test]
fn test_detects_nuget_key() {
    assert_provider(&format!("oy2{}", "a".repeat(43)), PiiType::NuGetKey);
}

#[test]
fn test_detects_artifactory_token() {
    assert_provider(&format!("AKC{}", "a".repeat(10)), PiiType::ArtifactoryToken);
}

#[test]
fn test_detects_docker_hub_token() {
    assert_provider(
        &format!("dckr_pat_{}", "A".repeat(27)),
        PiiType::DockerHubToken,
    );
}

#[test]
fn test_detects_telegram_token() {
    assert_provider(
        &format!("12345678:{}", "A".repeat(35)),
        PiiType::TelegramToken,
    );
}

#[test]
fn test_detects_sendgrid_token() {
    assert_provider(
        &format!("SG.{}.{}", "A".repeat(22), "b".repeat(43)),
        PiiType::SendGridToken,
    );
}

#[test]
fn test_detects_openai_key() {
    assert_provider(
        &format!("sk-{}T3BlbkFJ{}", "A".repeat(20), "B".repeat(20)),
        PiiType::OpenAiKey,
    );
}

#[test]
fn test_detects_discord_token() {
    assert_provider(
        &format!("M{}.{}.{}", "A".repeat(23), "AbCdEf", "a".repeat(27)),
        PiiType::DiscordToken,
    );
}

#[test]
fn test_detects_slack_token() {
    assert_provider(
        &format!("xoxb-{}-{}", "1".repeat(12), "A".repeat(24)),
        PiiType::SlackToken,
    );
}

#[test]
fn test_detects_twilio_token() {
    assert_provider(&format!("AC{}", "a".repeat(32)), PiiType::TwilioToken);
}

#[test]
fn test_unrecognized_api_key_falls_back_to_generic() {
    // api_key=... shape with no provider prefix. The redact_api_keys_in_text
    // primitive recognises the labeled form and the generic fallback fires.
    let text = "config: api_key=zzzz9999aaaa8888bbbb7777cccc6666";
    let types = scan_for_pii(text);
    assert!(
        types.contains(&PiiType::ApiKey),
        "unrecognized api-key shape should fall back to ApiKey: {types:?}"
    );
}

#[test]
fn test_multiple_providers_in_one_text() {
    let text = format!(
        "GH: ghp_{} STRIPE: sk_live_{} AWS: AKIA{}",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "EXAMPLE000000000KEY01abcdef", "IOSFODNN7EXAMPLE"
    );
    let types = scan_for_pii(&text);
    assert!(types.contains(&PiiType::GitHubToken), "{types:?}");
    assert!(types.contains(&PiiType::StripeKey), "{types:?}");
    assert!(types.contains(&PiiType::AwsAccessKey), "{types:?}");
    assert!(
        !types.contains(&PiiType::ApiKey),
        "generic ApiKey must be suppressed when providers matched: {types:?}"
    );
}

//! PII redaction engine
//!
//! Redacts PII from text using the primitives sanitization layer and
//! environment-aware profiles.
//!
//! ## Module Organization
//!
//! - `credentials` - Passwords, PINs, security answers, passphrases
//! - `tokens` - API keys, JWTs, session tokens, SSH keys
//! - `government` - SSNs, driver licenses, passports, VINs, EINs
//! - `financial` - Credit cards, bank accounts, routing numbers
//! - `medical` - MRNs, NPIs, insurance numbers, ICD codes
//! - `biometric` - Fingerprints, facial data, voice prints, iris, DNA
//! - `location` - GPS coordinates, addresses, postal codes
//! - `organizational` - Employee IDs, student IDs, badge numbers
//! - `network` - MAC addresses, UUIDs, URLs, domains
//! - `personal` - Emails, phone numbers

mod biometric;
mod credentials;
mod financial;
mod government;
mod location;
mod medical;
mod network;
mod organizational;
mod personal;
mod tokens;

use super::config::RedactionProfile;
use super::scanner::scan_and_prepare;
use super::types::{PiiScanResult, PiiType};

// Re-export submodule functions for internal use
use biometric::*;
use credentials::*;
use financial::*;
use government::*;
use location::*;
use medical::*;
use network::*;
use organizational::*;
use personal::*;
use tokens::*;

/// Redact PII from text using the default profile (auto-detected from environment)
///
/// This is the simplest API - automatically detects the environment and applies
/// the appropriate redaction profile.
///
/// # Examples
///
/// ```
/// use octarine::observe::pii::redact_pii;
///
/// let text = "Contact: user@example.com, SSN: 123-45-6789";
/// let safe = redact_pii(text);
///
/// // In ProductionStrict: "Contact: [Email], SSN: [SSN]"
/// // In ProductionLenient: "Contact: u***@example.com, SSN: ***-**-6789"
/// // In Development: "Contact: user@example.com, SSN: ***-**-6789"
/// ```
pub fn redact_pii(text: &str) -> String {
    let profile = RedactionProfile::from_environment();
    redact_pii_with_profile(text, profile)
}

/// Redact PII from text using an explicit redaction profile
///
/// Provides full control over the redaction strategy.
///
/// # Examples
///
/// ```rust
/// use octarine::observe::pii::{redact_pii_with_profile, RedactionProfile};
///
/// let text = "SSN: 123-45-6789";
///
/// // Strict (production) - Complete redaction with token strategy
/// let strict = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
/// assert_eq!(strict, "SSN: [SSN]");
///
/// // Lenient (staging) - Partial redaction (last digits)
/// let lenient = redact_pii_with_profile(text, RedactionProfile::ProductionLenient);
/// assert_eq!(lenient, "SSN: ***-**-6789");
/// ```
pub fn redact_pii_with_profile(text: &str, profile: RedactionProfile) -> String {
    // Scan for PII first
    let (pii_types, contains_pii) = scan_and_prepare(text);

    // If no PII, return as-is
    if !contains_pii {
        return text.to_string();
    }

    // Apply redactions based on profile
    // Note: No logging here to avoid recursion when EventBuilder calls redact_pii()
    let mut result = text.to_string();

    // Process each PII type in priority order (most sensitive first)
    for pii_type in &pii_types {
        result = match pii_type {
            // Credentials (highest priority - NIST Factor 1: Something You Know)
            PiiType::Password => redact_passwords(&result, profile),
            PiiType::Pin => redact_pins(&result, profile),
            PiiType::SecurityAnswer => redact_security_answers(&result, profile),
            PiiType::Passphrase => redact_passphrases(&result, profile),
            // Token/Secrets
            PiiType::ApiKey => redact_api_keys(&result, profile),
            PiiType::Jwt => redact_jwts(&result, profile),
            PiiType::SessionId | PiiType::OAuthToken => {
                // Session IDs and OAuth tokens use similar redaction to API keys
                redact_session_tokens(&result, profile)
            }
            PiiType::SshKey => redact_ssh_keys(&result, profile),
            // New token types - reuse API key redaction for now
            PiiType::OnePasswordToken
            | PiiType::OnePasswordVaultRef
            | PiiType::BearerToken
            | PiiType::UrlWithCredentials
            | PiiType::ConnectionString => redact_api_keys(&result, profile),
            // Government IDs
            PiiType::Ssn => redact_ssns(&result, profile),
            PiiType::DriverLicense => redact_driver_licenses(&result, profile),
            PiiType::Passport => redact_passports(&result, profile),
            PiiType::Vin | PiiType::Ein | PiiType::TaxId | PiiType::NationalId => {
                // VIN, EIN, Tax IDs, and National IDs use generic government ID redaction
                redact_government_ids(&result, profile)
            }
            // Financial
            PiiType::CreditCard => redact_credit_cards(&result, profile),
            PiiType::BankAccount => redact_bank_accounts(&result, profile),
            PiiType::RoutingNumber => redact_routing_numbers(&result, profile),
            // Personal
            PiiType::Email => redact_emails(&result, profile),
            PiiType::Phone => redact_phones(&result, profile),
            PiiType::Name | PiiType::Birthdate | PiiType::Username => {
                // Names, birthdates, and usernames are harder to redact reliably
                // without false positives - they're detected but not automatically redacted
                result
            }
            // Medical (PHI)
            PiiType::Mrn => redact_medical_record_numbers(&result, profile),
            PiiType::Npi => redact_provider_ids(&result, profile),
            PiiType::InsuranceNumber => redact_insurance_numbers(&result, profile),
            PiiType::IcdCode => redact_medical_codes(&result, profile),
            PiiType::PrescriptionNumber => redact_prescriptions(&result, profile),
            // Biometric
            PiiType::FingerprintId => redact_fingerprints(&result, profile),
            PiiType::FaceId => redact_facial_data(&result, profile),
            PiiType::VoiceId => redact_voice_prints(&result, profile),
            PiiType::IrisId => redact_iris_scans(&result, profile),
            PiiType::DnaId => redact_dna_sequences(&result, profile),
            // Location
            PiiType::GpsCoordinates => redact_gps_coordinates(&result, profile),
            PiiType::Address => redact_addresses(&result, profile),
            PiiType::PostalCode => redact_postal_codes(&result, profile),
            // Organizational
            PiiType::EmployeeId => redact_employee_ids(&result, profile),
            PiiType::StudentId => redact_student_ids(&result, profile),
            PiiType::BadgeNumber => redact_badge_numbers(&result, profile),
            // Network
            PiiType::IpAddress => redact_ip_addresses(&result, profile),
            PiiType::MacAddress => redact_mac_addresses(&result, profile),
            PiiType::Uuid => redact_uuids(&result, profile),
            PiiType::Domain | PiiType::Url | PiiType::Hostname => redact_urls(&result, profile),
            PiiType::Port => {
                // Ports are too short to redact meaningfully
                result
            }
            // Catch-all
            PiiType::Generic => result,
        };
    }

    result
}

/// Scan and redact PII, returning a complete result with metadata
///
/// This is the internal function used by the Event builder.
pub(in crate::observe) fn scan_and_redact(text: &str, profile: RedactionProfile) -> PiiScanResult {
    let (pii_types, contains_pii) = scan_and_prepare(text);

    if !contains_pii {
        return PiiScanResult::no_pii(text.to_string());
    }

    let redacted = redact_pii_with_profile(text, profile);

    PiiScanResult::with_pii(pii_types, redacted)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_ssn_strict() {
        let text = "SSN: 900-00-0001";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        // ProductionStrict uses Complete::Token strategy → [SSN]
        assert_eq!(result, "SSN: [SSN]");
    }

    #[test]
    fn test_redact_credit_card() {
        let text = "Card: 4242424242424242";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        // ProductionStrict uses Complete::Token strategy → [CREDIT_CARD]
        // Note: The LABELED pattern in security module matches "Card: 4242..." entirely
        assert_eq!(result, "[CREDIT_CARD]");
    }

    #[test]
    fn test_redact_email() {
        let text = "Email: user@example.com";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        // ProductionStrict uses Complete::Token strategy → [EMAIL]
        assert_eq!(result, "Email: [EMAIL]");
    }

    #[test]
    fn test_redact_phone() {
        let text = "Phone: +1-555-123-4567";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        // ProductionStrict uses Complete::Token strategy → [PHONE]
        assert_eq!(result, "Phone: [PHONE]");
    }

    #[test]
    fn test_redact_api_key() {
        // Use the same Stripe API key format as the scanner test
        let text = &format!("Key: sk_test_{}", "EXAMPLE000000000000KEY01");
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        // Primitives use partial masking for API keys (show prefix, mask rest)
        assert!(
            result.contains("sk_test_") && result.contains("****"),
            "API key should be partially masked, got: {}",
            result
        );
    }

    #[test]
    fn test_redact_password() {
        let text = "password=secret123";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        // Uses standardized [PASSWORD] token from primitives
        assert_eq!(result, "password=[PASSWORD]");
    }

    #[test]
    fn test_redact_ip_address_strict() {
        // IP addresses are GDPR-protected PII and detected by default
        let text = "Server: 192.168.1.1";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        // Primitives use partial masking for IPs (show first octet, mask rest)
        assert_eq!(result, "Server: 192.***.***.***");
    }

    #[test]
    fn test_redact_ip_address_lenient() {
        // Lenient mode uses same partial masking as strict
        let text = "Server: 192.168.1.1";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionLenient);
        assert_eq!(result, "Server: 192.***.***.***");
    }

    #[test]
    fn test_redact_multiple_pii() {
        let text = "Contact: user@example.com, SSN: 900-00-0001, Card: 4242424242424242";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        // ProductionStrict uses Complete::Token strategy
        assert!(result.contains("[EMAIL]"));
        assert!(result.contains("[SSN]"));
        assert!(result.contains("[CREDIT_CARD]"));
    }

    #[test]
    fn test_redact_no_pii() {
        let text = "Clean text with no PII";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_testing_profile() {
        let text = "SSN: 900-00-0001, Email: user@example.com";
        let result = redact_pii_with_profile(text, RedactionProfile::Testing);
        assert_eq!(result, text); // No redaction in testing mode
    }

    #[test]
    fn test_scan_and_redact() {
        let text = "Email: user@example.com, SSN: 900-00-0001";
        let result = scan_and_redact(text, RedactionProfile::ProductionStrict);

        assert!(result.contains_pii);
        // Must contain at least 2 (email, SSN), may detect more (names, etc.)
        assert!(
            result.pii_types.len() >= 2,
            "Should detect at least 2 PII types, got {:?}",
            result.pii_types
        );
        // ProductionStrict uses Complete::Token strategy
        assert!(result.redacted.contains("[EMAIL]"), "Should redact email");
        assert!(result.redacted.contains("[SSN]"), "Should redact SSN");
    }

    #[test]
    fn test_scan_and_redact_no_pii() {
        let text = "Clean text";
        let result = scan_and_redact(text, RedactionProfile::ProductionStrict);

        assert!(!result.contains_pii);
        assert!(result.pii_types.is_empty());
        assert_eq!(result.redacted, text);
    }

    // ============================================================================
    // Edge Case Tests
    // ============================================================================

    #[test]
    fn test_email_in_url() {
        let text = "Visit https://user@example.com/path or email user@example.com";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        // Both email occurrences should be redacted
        assert!(result.contains("[EMAIL]"));
        // The URL structure should remain somewhat intact
        assert!(result.contains("https://"));
    }

    #[test]
    fn test_multiple_ssns_in_line() {
        let text = "SSN1: 900-00-0001, SSN2: 900-00-0002, SSN3: 900-00-0003";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        // All SSNs should be redacted
        let ssn_count = result.matches("[SSN]").count();
        assert_eq!(ssn_count, 3, "Expected 3 SSNs to be redacted");
    }

    #[test]
    fn test_credit_card_with_spaces() {
        let text = "Card: 4242 4242 4242 4242";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        // Should handle credit cards with spaces
        assert!(result.contains("[CREDIT_CARD]") || !result.contains("4242"));
    }

    #[test]
    fn test_credit_card_with_dashes() {
        let text = "Card: 4242-4242-4242-4242";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        // Should handle credit cards with dashes
        assert!(result.contains("[CREDIT_CARD]") || !result.contains("4242-4242-4242-4242"));
    }

    #[test]
    fn test_phone_various_formats() {
        // Test different phone number formats
        let formats = vec![
            "+1-555-123-4567", // International with dashes
            "(555) 123-4567",  // US format with parens
            "555.123.4567",    // Dots
            "1-555-123-4567",  // US with leading 1
        ];

        for format in formats {
            let text = format!("Call: {}", format);
            let result = redact_pii_with_profile(&text, RedactionProfile::ProductionStrict);
            // Phone should be redacted in some form
            assert!(
                result.contains("[PHONE]") || result != text,
                "Phone format '{}' was not redacted",
                format
            );
        }
    }

    #[test]
    fn test_false_positive_numbers() {
        // Numbers that look like PII but aren't
        let text = "Product: 123-45-6789 items, Order: 4242424242424242";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        // These might be detected as SSN/credit card - that's okay, better safe than sorry
        // Just verify the function doesn't crash
        assert!(!result.is_empty());
    }

    #[test]
    fn test_mixed_content_with_urls() {
        let text = "Contact user@example.com or visit https://example.com?email=test@test.com&ssn=123-45-6789";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        // Should redact emails in both plain text and URL parameters
        assert!(result.contains("[EMAIL]"));
        // Should redact SSN in URL parameter
        assert!(result.contains("[SSN]"));
    }

    #[test]
    fn test_pii_at_line_boundaries() {
        // Test PII at start/end of text
        let test_cases = vec![
            "user@example.com at start",
            "at end user@example.com",
            "900-00-0001",
        ];

        for input in test_cases {
            let result = redact_pii_with_profile(input, RedactionProfile::ProductionStrict);
            assert!(
                result.contains("[EMAIL]") || result.contains("[SSN]"),
                "Failed to redact '{}', got '{}'",
                input,
                result
            );
        }
    }

    #[test]
    fn test_partial_redaction_lenient() {
        // Test that ProductionLenient shows partial data
        let text = "SSN: 900-00-0001";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionLenient);
        // Should show last digits in lenient mode
        assert!(result.contains("0001") || result.contains("***"));
    }

    #[test]
    fn test_unicode_with_pii() {
        // Test PII detection with unicode characters nearby
        let text = "用户邮箱: user@example.com, 电话: +1-555-123-4567";
        let result = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
        // Should detect PII even with unicode
        assert!(result.contains("[EMAIL]") || result.contains("[PHONE]"));
    }

    #[test]
    fn test_empty_and_whitespace() {
        // Edge cases for empty/whitespace input
        let test_cases = vec!["", "   ", "\n", "\t", "  \n  \t  "];

        for input in test_cases {
            let result = redact_pii_with_profile(input, RedactionProfile::ProductionStrict);
            // Should handle gracefully without panicking
            assert_eq!(result, input);
        }
    }

    #[test]
    fn test_very_long_text_with_pii() {
        // Test performance with longer text
        let mut text = String::new();
        for i in 0..100 {
            text.push_str(&format!("Line {}: user{}@example.com, ", i, i));
        }

        let result = redact_pii_with_profile(&text, RedactionProfile::ProductionStrict);
        // Should redact all emails
        assert!(result.contains("[EMAIL]"));
        // Original emails should not be present
        assert!(!result.contains("user0@example.com"));
    }
}

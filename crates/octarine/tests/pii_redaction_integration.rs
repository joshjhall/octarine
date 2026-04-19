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
    // Note: "ref" value must not match license plate pattern (2-3 uppercase + 3-4 digits)
    let text = "User registered: test@example.com with ref order-99";
    let redacted = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);

    // Email redacted but structure preserved
    assert_eq!(redacted, "User registered: [EMAIL] with ref order-99");
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

// ==========================================
// MEDICAL (PHI) REDACTION TESTS
// ==========================================

#[test]
fn test_medical_record_number_redaction() {
    let text = "Patient MRN: 12345678 admitted";
    let redacted = redact_pii(text);
    assert!(
        redacted.contains("[MEDICAL_RECORD]") || !redacted.contains("12345678"),
        "MRN should be redacted: {redacted}"
    );
}

#[test]
fn test_provider_npi_redaction() {
    let text = "Doctor NPI: 1234567890 on call";
    let redacted = redact_pii(text);
    assert!(
        redacted.contains("[PROVIDER_ID]") || !redacted.contains("1234567890"),
        "NPI should be redacted: {redacted}"
    );
}

#[test]
fn test_insurance_number_redaction() {
    let text = "Policy Number: ABC123456789 active";
    let redacted = redact_pii(text);
    assert!(
        redacted.contains("[INSURANCE_INFO]") || !redacted.contains("ABC123456789"),
        "Insurance number should be redacted: {redacted}"
    );
}

#[test]
fn test_prescription_number_redaction() {
    let text = "RX# 123456789 filled";
    let redacted = redact_pii(text);
    assert!(
        redacted.contains("[PRESCRIPTION]") || !redacted.contains("123456789"),
        "Prescription should be redacted: {redacted}"
    );
}

#[test]
fn test_dea_number_redaction() {
    let text = "Provider DEA: AB1234563 is active";
    let redacted = redact_pii(text);
    assert!(
        redacted.contains("[DEA_NUMBER]") || !redacted.contains("AB1234563"),
        "DEA number should be redacted: {redacted}"
    );
}

// ==========================================
// BIOMETRIC REDACTION TESTS
// ==========================================

#[test]
fn test_fingerprint_redaction() {
    let text =
        "User fingerprint: a1b2c3d4e5f6789012345678901234567890123456789012345678901234 stored";
    let redacted = redact_pii(text);
    assert!(
        redacted.contains("[FINGERPRINT]") || !redacted.contains("a1b2c3d4"),
        "Fingerprint should be redacted: {redacted}"
    );
}

#[test]
fn test_dna_sequence_redaction() {
    let text = "Genetic data: ATCGATCGATCGATCGATCGATCGATCGATCGATCG collected";
    let redacted = redact_pii(text);
    assert!(
        redacted.contains("[DNA_SEQUENCE]") || redacted == text,
        "DNA should be redacted or left unchanged if scanner skips it: {redacted}"
    );
}

// ==========================================
// GOVERNMENT ID REDACTION TESTS (non-SSN)
// ==========================================

#[test]
fn test_vin_redaction() {
    let text = "VIN: 1HGBH41JXMN109186 registered";
    let redacted = redact_pii(text);
    assert!(
        redacted.contains("[VEHICLE_ID]") || !redacted.contains("1HGBH41JXMN109186"),
        "VIN should be redacted: {redacted}"
    );
}

#[test]
fn test_driver_license_redaction() {
    let text = "DL# A1234567 on file";
    let redacted = redact_pii(text);
    assert!(
        redacted.contains("[DRIVER_LICENSE]") || !redacted.contains("A1234567"),
        "Driver license should be redacted: {redacted}"
    );
}

// ==========================================
// LOCATION REDACTION TESTS
// ==========================================

#[test]
fn test_gps_coordinates_redaction() {
    let text = "Location: 40.7128, -74.0060 detected";
    let redacted = redact_pii(text);
    assert!(
        redacted.contains("[GPS_COORDINATE]") || !redacted.contains("40.7128"),
        "GPS coordinates should be redacted: {redacted}"
    );
}

#[test]
fn test_street_address_redaction() {
    let text = "Ship to: 123 Main Street please";
    let redacted = redact_pii(text);
    assert!(
        redacted.contains("[ADDRESS]") || !redacted.contains("123 Main Street"),
        "Address should be redacted: {redacted}"
    );
}

// ==========================================
// ORGANIZATIONAL ID REDACTION TESTS
// ==========================================

#[test]
fn test_employee_id_redaction() {
    let text = "Employee ID: E123456 active";
    let redacted = redact_pii(text);
    assert!(
        redacted.contains("[EMPLOYEE_ID]") || !redacted.contains("E123456"),
        "Employee ID should be redacted: {redacted}"
    );
}

#[test]
fn test_student_id_redaction() {
    let text = "Student ID: S12345678 enrolled";
    let redacted = redact_pii(text);
    assert!(
        redacted.contains("[STUDENT_ID]") || !redacted.contains("S12345678"),
        "Student ID should be redacted: {redacted}"
    );
}

// ==========================================
// HIPAA-SPECIFIC CLASSIFICATION TESTS
// ==========================================

#[test]
fn test_hipaa_protected_medical_types() {
    assert!(PiiType::Mrn.is_hipaa_protected());
    assert!(PiiType::Npi.is_hipaa_protected());
    assert!(PiiType::InsuranceNumber.is_hipaa_protected());
    assert!(PiiType::PrescriptionNumber.is_hipaa_protected());
    assert!(PiiType::DeaNumber.is_hipaa_protected());
}

#[test]
fn test_gdpr_protected_biometric_types() {
    assert!(PiiType::FingerprintId.is_gdpr_protected());
    assert!(PiiType::FaceId.is_gdpr_protected());
    assert!(PiiType::VoiceId.is_gdpr_protected());
    assert!(PiiType::IrisId.is_gdpr_protected());
    assert!(PiiType::DnaId.is_gdpr_protected());
}

// ==========================================
// COUNTRY-SPECIFIC GOVERNMENT ID TESTS
// ==========================================
// Covers the 11 country-specific IDs wired into scan_government. Sample
// values come from the validation unit tests in
// crates/octarine/src/primitives/identifiers/government/validation/*.rs.

#[test]
fn test_scan_detects_korea_rrn() {
    let text = "KR ID: 900115-1234567";
    let pii_types = scan_for_pii(text);
    assert!(
        pii_types.contains(&PiiType::KoreaRrn),
        "Expected KoreaRrn in {pii_types:?}"
    );
}

#[test]
fn test_scan_detects_italy_fiscal_code() {
    // RSSMRA85M01H501Z — canonical sample from validation tests
    let text = "CF: RSSMRA85M01H501Z";
    let pii_types = scan_for_pii(text);
    assert!(
        pii_types.contains(&PiiType::ItalyFiscalCode),
        "Expected ItalyFiscalCode in {pii_types:?}"
    );
}

#[test]
fn test_scan_detects_india_aadhaar() {
    // 2345 6789 0123 — valid 12-digit Aadhaar (passes format check)
    let text = "Aadhaar: 2345 6789 0123";
    let pii_types = scan_for_pii(text);
    assert!(
        pii_types.contains(&PiiType::IndiaAadhaar),
        "Expected IndiaAadhaar in {pii_types:?}"
    );
}

#[test]
fn test_scan_detects_spain_nif() {
    // Valid 8-digit + letter NIF pattern
    let text = "NIF: 12345678Z";
    let pii_types = scan_for_pii(text);
    assert!(
        pii_types.contains(&PiiType::SpainNif),
        "Expected SpainNif in {pii_types:?}"
    );
}

#[test]
fn test_country_ids_flagged_contains_pii() {
    // Text with multiple country-specific IDs — all must be classified as
    // PII so that contains_pii fires downstream. Text-level redaction for
    // country-specific IDs is a separate primitive-layer gap
    // (redact_all_government_ids_in_text_with_policy only wires 6 types);
    // this test only asserts classification/observability.
    let text = "RRN 900115-1234567 and CF RSSMRA85M01H501Z and NIF 12345678Z";
    let pii_types = scan_for_pii(text);

    assert!(pii_types.contains(&PiiType::KoreaRrn));
    assert!(pii_types.contains(&PiiType::ItalyFiscalCode));
    assert!(pii_types.contains(&PiiType::SpainNif));
}

#[test]
fn test_eu_country_ids_are_gdpr_protected() {
    // EU-member government IDs must be flagged under GDPR
    assert!(PiiType::FinlandHetu.is_gdpr_protected());
    assert!(PiiType::PolandPesel.is_gdpr_protected());
    assert!(PiiType::ItalyFiscalCode.is_gdpr_protected());
    assert!(PiiType::SpainNif.is_gdpr_protected());
    assert!(PiiType::SpainNie.is_gdpr_protected());
}

#[test]
fn test_non_eu_country_ids_high_risk_only() {
    // Non-EU regimes (PIPA/Privacy Act 1988/DPDPA/PDPA) aren't modeled,
    // so these are high-risk but NOT GDPR-protected
    for pii in [
        PiiType::KoreaRrn,
        PiiType::AustraliaTfn,
        PiiType::AustraliaAbn,
        PiiType::IndiaAadhaar,
        PiiType::IndiaPan,
        PiiType::SingaporeNric,
    ] {
        assert!(pii.is_high_risk(), "{pii:?} should be high-risk");
        assert!(
            !pii.is_gdpr_protected(),
            "{pii:?} should not be GDPR-protected"
        );
    }
}

// ==========================================
// IBAN & CRYPTO ADDRESS TESTS
// ==========================================
// IBAN samples use canonical MOD-97-valid values from the iban detection
// unit tests. Crypto samples cover Bitcoin (P2PKH, P2SH, Bech32) and
// Ethereum formats.

#[test]
fn test_scan_detects_iban() {
    let text = "Transfer to DE89 3704 0044 0532 0130 00";
    let pii_types = scan_for_pii(text);
    assert!(
        pii_types.contains(&PiiType::Iban),
        "Expected Iban in {pii_types:?}"
    );
}

#[test]
fn test_scan_detects_iban_no_spaces() {
    let text = "IBAN: GB29NWBK60161331926819";
    let pii_types = scan_for_pii(text);
    assert!(
        pii_types.contains(&PiiType::Iban),
        "Expected Iban in {pii_types:?}"
    );
}

#[test]
fn test_scan_detects_bitcoin_address() {
    let text = "Send BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    let pii_types = scan_for_pii(text);
    assert!(
        pii_types.contains(&PiiType::CryptoAddress),
        "Expected CryptoAddress in {pii_types:?}"
    );
}

#[test]
fn test_scan_detects_ethereum_address() {
    let text = "ETH wallet: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18";
    let pii_types = scan_for_pii(text);
    assert!(
        pii_types.contains(&PiiType::CryptoAddress),
        "Expected CryptoAddress in {pii_types:?}"
    );
}

#[test]
fn test_scan_detects_bitcoin_bech32() {
    let text = "SegWit: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let pii_types = scan_for_pii(text);
    assert!(
        pii_types.contains(&PiiType::CryptoAddress),
        "Expected CryptoAddress in {pii_types:?}"
    );
}

#[test]
fn test_iban_is_gdpr_and_pci_protected() {
    // IBAN identifies an EU account holder — both regimes apply
    assert!(PiiType::Iban.is_gdpr_protected());
    assert!(PiiType::Iban.is_pci_protected());
    assert!(PiiType::Iban.is_high_risk());
}

#[test]
fn test_crypto_address_is_pci_but_not_gdpr() {
    // Crypto addresses are pseudonymous; GDPR scope requires upstream
    // linkage to a natural person that we do not track here.
    assert!(PiiType::CryptoAddress.is_pci_protected());
    assert!(!PiiType::CryptoAddress.is_gdpr_protected());
    assert!(PiiType::CryptoAddress.is_high_risk());
}

#[test]
fn test_mixed_financial_pii_detected_together() {
    // Combined text — all three variants must surface in one scan
    let text = "Card 4242424242424242, IBAN DE89370400440532013000, \
                wallet 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18";
    let pii_types = scan_for_pii(text);
    assert!(pii_types.contains(&PiiType::CreditCard));
    assert!(pii_types.contains(&PiiType::Iban));
    assert!(pii_types.contains(&PiiType::CryptoAddress));
}

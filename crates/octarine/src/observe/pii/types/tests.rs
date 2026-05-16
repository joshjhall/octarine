//! Unit tests for `PiiType` classification and `From<IdentifierType>` mapping.

#![allow(clippy::panic, clippy::expect_used)]

use super::*;
use crate::primitives::identifiers::IdentifierType;

#[test]
fn test_pii_type_name() {
    assert_eq!(PiiType::Ssn.name(), "ssn");
    assert_eq!(PiiType::Email.name(), "email");
    assert_eq!(PiiType::CreditCard.name(), "credit_card");
    assert_eq!(PiiType::Mrn.name(), "mrn");
    assert_eq!(PiiType::ApiKey.name(), "api_key");
}

#[test]
fn test_pii_type_domain() {
    assert_eq!(PiiType::Email.domain(), "personal");
    assert_eq!(PiiType::CreditCard.domain(), "financial");
    assert_eq!(PiiType::Ssn.domain(), "government");
    assert_eq!(PiiType::Mrn.domain(), "medical");
    assert_eq!(PiiType::FingerprintId.domain(), "biometric");
    assert_eq!(PiiType::GpsCoordinates.domain(), "location");
    assert_eq!(PiiType::EmployeeId.domain(), "organizational");
    assert_eq!(PiiType::IpAddress.domain(), "network");
    assert_eq!(PiiType::ApiKey.domain(), "token");
}

#[test]
fn test_high_risk() {
    // Financial
    assert!(PiiType::CreditCard.is_high_risk());
    assert!(PiiType::BankAccount.is_high_risk());
    // Government
    assert!(PiiType::Ssn.is_high_risk());
    assert!(PiiType::Passport.is_high_risk());
    // Government (added)
    assert!(PiiType::Vin.is_high_risk());
    // Medical
    assert!(PiiType::Mrn.is_high_risk());
    assert!(PiiType::IcdCode.is_high_risk());
    assert!(PiiType::PrescriptionNumber.is_high_risk());
    // Biometric
    assert!(PiiType::FingerprintId.is_high_risk());
    // Token/secrets
    assert!(PiiType::Password.is_high_risk());
    assert!(PiiType::ApiKey.is_high_risk());
    // Low risk
    assert!(!PiiType::Email.is_high_risk());
    assert!(!PiiType::Phone.is_high_risk());
    assert!(!PiiType::PostalCode.is_high_risk());
}

#[test]
fn test_gdpr_protected() {
    assert!(PiiType::Email.is_gdpr_protected());
    assert!(PiiType::Phone.is_gdpr_protected());
    assert!(PiiType::IpAddress.is_gdpr_protected());
    assert!(PiiType::GpsCoordinates.is_gdpr_protected());
    assert!(PiiType::FingerprintId.is_gdpr_protected());
    // Not GDPR protected
    assert!(!PiiType::ApiKey.is_gdpr_protected());
    assert!(!PiiType::EmployeeId.is_gdpr_protected());
}

#[test]
fn test_pci_protected() {
    assert!(PiiType::CreditCard.is_pci_protected());
    assert!(PiiType::BankAccount.is_pci_protected());
    assert!(PiiType::RoutingNumber.is_pci_protected());
    assert!(!PiiType::Email.is_pci_protected());
    assert!(!PiiType::Ssn.is_pci_protected());
}

#[test]
fn test_hipaa_protected() {
    // Medical
    assert!(PiiType::Mrn.is_hipaa_protected());
    assert!(PiiType::Npi.is_hipaa_protected());
    assert!(PiiType::InsuranceNumber.is_hipaa_protected());
    // PHI identifiers
    assert!(PiiType::Ssn.is_hipaa_protected());
    assert!(PiiType::Name.is_hipaa_protected());
    assert!(PiiType::Birthdate.is_hipaa_protected());
    // Not HIPAA
    assert!(!PiiType::CreditCard.is_hipaa_protected());
    assert!(!PiiType::ApiKey.is_hipaa_protected());
}

#[test]
fn test_is_secret() {
    assert!(PiiType::Password.is_secret());
    assert!(PiiType::Pin.is_secret());
    assert!(PiiType::SecurityAnswer.is_secret());
    assert!(PiiType::Passphrase.is_secret());
    assert!(PiiType::ApiKey.is_secret());
    assert!(PiiType::Jwt.is_secret());
    assert!(PiiType::SessionId.is_secret());
    assert!(PiiType::SshKey.is_secret());
    // Not secrets
    assert!(!PiiType::Email.is_secret());
    assert!(!PiiType::Ssn.is_secret());
    assert!(!PiiType::CreditCard.is_secret());
}

#[test]
fn test_iban_classifications() {
    assert_eq!(PiiType::Iban.name(), "iban");
    assert_eq!(PiiType::Iban.domain(), "financial");
    assert!(PiiType::Iban.is_high_risk());
    assert!(PiiType::Iban.is_pci_protected());
    // IBAN identifies an EU account holder — GDPR applies
    assert!(PiiType::Iban.is_gdpr_protected());
    assert!(!PiiType::Iban.is_hipaa_protected());
    assert!(!PiiType::Iban.is_secret());
}

#[test]
fn test_crypto_address_classifications() {
    assert_eq!(PiiType::CryptoAddress.name(), "crypto_address");
    assert_eq!(PiiType::CryptoAddress.domain(), "financial");
    assert!(PiiType::CryptoAddress.is_high_risk());
    assert!(PiiType::CryptoAddress.is_pci_protected());
    // Crypto addresses are pseudonymous; GDPR does not apply absent an
    // upstream linkage to an identifiable person.
    assert!(!PiiType::CryptoAddress.is_gdpr_protected());
    assert!(!PiiType::CryptoAddress.is_hipaa_protected());
    assert!(!PiiType::CryptoAddress.is_secret());
}

#[test]
fn test_national_id_classifications() {
    assert_eq!(PiiType::NationalId.name(), "national_id");
    assert_eq!(PiiType::NationalId.domain(), "government");
    assert!(PiiType::NationalId.is_high_risk());
    assert!(PiiType::NationalId.is_gdpr_protected());
    assert!(!PiiType::NationalId.is_pci_protected());
    assert!(!PiiType::NationalId.is_secret());
}

#[test]
fn test_country_specific_government_classifications() {
    // EU-member (and UK GDPR) IDs are GDPR-protected
    for pii in [
        PiiType::FinlandHetu,
        PiiType::PolandPesel,
        PiiType::ItalyFiscalCode,
        PiiType::SpainNif,
        PiiType::SpainNie,
        PiiType::UkNi,
    ] {
        assert_eq!(pii.domain(), "government", "{pii:?} domain");
        assert!(pii.is_high_risk(), "{pii:?} should be high-risk");
        assert!(pii.is_gdpr_protected(), "{pii:?} is EU/UK, expect GDPR");
        assert!(!pii.is_pci_protected(), "{pii:?} not PCI");
        assert!(!pii.is_hipaa_protected(), "{pii:?} not HIPAA");
        assert!(!pii.is_secret(), "{pii:?} not a secret");
    }

    // Non-EU IDs are high-risk but not GDPR-protected (PIPA/PDPA/DPDPA/
    // Privacy Act 1988 are not yet modeled in the compliance flags)
    for pii in [
        PiiType::KoreaRrn,
        PiiType::AustraliaTfn,
        PiiType::AustraliaAbn,
        PiiType::IndiaAadhaar,
        PiiType::IndiaPan,
        PiiType::IndiaGstin,
        PiiType::IndiaVehicleReg,
        PiiType::IndiaVoterId,
        PiiType::IndiaPassport,
        PiiType::BrazilCpf,
        PiiType::BrazilCnpj,
        PiiType::MexicoCurp,
        PiiType::NigeriaNin,
        PiiType::ThailandTnin,
        PiiType::SingaporeNric,
    ] {
        assert_eq!(pii.domain(), "government", "{pii:?} domain");
        assert!(pii.is_high_risk(), "{pii:?} should be high-risk");
        assert!(!pii.is_gdpr_protected(), "{pii:?} non-EU, no GDPR");
        assert!(!pii.is_pci_protected(), "{pii:?} not PCI");
        assert!(!pii.is_hipaa_protected(), "{pii:?} not HIPAA");
        assert!(!pii.is_secret(), "{pii:?} not a secret");
    }

    // Names follow the IdentifierType variant naming
    assert_eq!(PiiType::KoreaRrn.name(), "korea_rrn");
    assert_eq!(PiiType::ItalyFiscalCode.name(), "italy_fiscal_code");
    assert_eq!(PiiType::SpainNie.name(), "spain_nie");
    assert_eq!(PiiType::UkNi.name(), "uk_ni");
}

#[test]
fn test_hostname_classifications() {
    assert_eq!(PiiType::Hostname.name(), "hostname");
    assert_eq!(PiiType::Hostname.domain(), "network");
    assert!(!PiiType::Hostname.is_high_risk());
    assert!(!PiiType::Hostname.is_gdpr_protected());
    assert!(!PiiType::Hostname.is_pci_protected());
    assert!(!PiiType::Hostname.is_secret());
}

#[test]
fn test_port_classifications() {
    assert_eq!(PiiType::Port.name(), "port");
    assert_eq!(PiiType::Port.domain(), "network");
    assert!(!PiiType::Port.is_high_risk());
    assert!(!PiiType::Port.is_gdpr_protected());
    assert!(!PiiType::Port.is_pci_protected());
    assert!(!PiiType::Port.is_secret());
}

#[test]
fn test_payment_token_classifications() {
    assert_eq!(PiiType::PaymentToken.name(), "payment_token");
    assert_eq!(PiiType::PaymentToken.domain(), "financial");
    assert!(PiiType::PaymentToken.is_high_risk());
    assert!(!PiiType::PaymentToken.is_gdpr_protected());
    assert!(PiiType::PaymentToken.is_pci_protected());
    assert!(PiiType::PaymentToken.is_secret());
}

#[test]
fn test_biometric_template_classifications() {
    assert_eq!(PiiType::BiometricTemplate.name(), "biometric_template");
    assert_eq!(PiiType::BiometricTemplate.domain(), "biometric");
    assert!(PiiType::BiometricTemplate.is_high_risk());
    assert!(PiiType::BiometricTemplate.is_gdpr_protected());
    assert!(PiiType::BiometricTemplate.is_hipaa_protected());
    assert!(!PiiType::BiometricTemplate.is_pci_protected());
    assert!(!PiiType::BiometricTemplate.is_secret());
}

#[test]
fn test_scan_result_no_pii() {
    let result = PiiScanResult::no_pii("clean text".to_string());
    assert!(!result.contains_pii);
    assert!(result.pii_types.is_empty());
    assert_eq!(result.redacted, "clean text");
    assert!(!result.contains_phi);
}

#[test]
fn test_scan_result_with_pii() {
    let result = PiiScanResult::with_pii(
        vec![PiiType::Email, PiiType::Ssn],
        "redacted text".to_string(),
    );
    assert!(result.contains_pii);
    assert_eq!(result.pii_types.len(), 2);
    assert_eq!(result.redacted, "redacted text");
    // Email and SSN are HIPAA-protected
    assert!(result.contains_phi);
}

#[test]
fn test_scan_result_phi_detection() {
    // Medical record triggers PHI
    let result = PiiScanResult::with_pii(vec![PiiType::Mrn], "redacted".to_string());
    assert!(result.contains_phi);

    // Credit card alone does not trigger PHI
    let result = PiiScanResult::with_pii(vec![PiiType::CreditCard], "redacted".to_string());
    assert!(!result.contains_phi);
}

#[test]
fn from_identifier_type_direct_mappings() {
    // One-to-one pairs where the PiiType variant matches the IdentifierType
    // variant by name or by the scanner's direct-push convention.

    // Personal
    assert_eq!(PiiType::from(IdentifierType::Email), PiiType::Email);
    assert_eq!(PiiType::from(IdentifierType::Ssn), PiiType::Ssn);
    assert_eq!(PiiType::from(IdentifierType::Birthdate), PiiType::Birthdate);
    assert_eq!(PiiType::from(IdentifierType::Username), PiiType::Username);

    // Credential
    assert_eq!(PiiType::from(IdentifierType::Password), PiiType::Password);
    assert_eq!(PiiType::from(IdentifierType::Pin), PiiType::Pin);
    assert_eq!(
        PiiType::from(IdentifierType::Passphrase),
        PiiType::Passphrase
    );
    assert_eq!(
        PiiType::from(IdentifierType::SecurityAnswer),
        PiiType::SecurityAnswer
    );

    // Network
    assert_eq!(PiiType::from(IdentifierType::Uuid), PiiType::Uuid);
    assert_eq!(PiiType::from(IdentifierType::IpAddress), PiiType::IpAddress);
    assert_eq!(
        PiiType::from(IdentifierType::MacAddress),
        PiiType::MacAddress
    );
    assert_eq!(PiiType::from(IdentifierType::Url), PiiType::Url);
    assert_eq!(PiiType::from(IdentifierType::Domain), PiiType::Domain);
    assert_eq!(PiiType::from(IdentifierType::Hostname), PiiType::Hostname);
    assert_eq!(PiiType::from(IdentifierType::Port), PiiType::Port);

    // Payment
    assert_eq!(
        PiiType::from(IdentifierType::CreditCard),
        PiiType::CreditCard
    );
    assert_eq!(
        PiiType::from(IdentifierType::BankAccount),
        PiiType::BankAccount
    );
    assert_eq!(
        PiiType::from(IdentifierType::RoutingNumber),
        PiiType::RoutingNumber
    );
    assert_eq!(
        PiiType::from(IdentifierType::PaymentToken),
        PiiType::PaymentToken
    );
    assert_eq!(PiiType::from(IdentifierType::Iban), PiiType::Iban);
    assert_eq!(
        PiiType::from(IdentifierType::CryptoAddress),
        PiiType::CryptoAddress
    );

    // Token/Key
    assert_eq!(PiiType::from(IdentifierType::Jwt), PiiType::Jwt);
    assert_eq!(PiiType::from(IdentifierType::ApiKey), PiiType::ApiKey);
    assert_eq!(PiiType::from(IdentifierType::SessionId), PiiType::SessionId);
    assert_eq!(
        PiiType::from(IdentifierType::OAuthToken),
        PiiType::OAuthToken
    );
    assert_eq!(PiiType::from(IdentifierType::SshKey), PiiType::SshKey);
    assert_eq!(
        PiiType::from(IdentifierType::OnePasswordToken),
        PiiType::OnePasswordToken
    );
    assert_eq!(
        PiiType::from(IdentifierType::OnePasswordVaultRef),
        PiiType::OnePasswordVaultRef
    );
    assert_eq!(
        PiiType::from(IdentifierType::BearerToken),
        PiiType::BearerToken
    );
    assert_eq!(
        PiiType::from(IdentifierType::UrlWithCredentials),
        PiiType::UrlWithCredentials
    );

    // Database
    assert_eq!(
        PiiType::from(IdentifierType::ConnectionString),
        PiiType::ConnectionString
    );

    // Government
    assert_eq!(
        PiiType::from(IdentifierType::DriverLicense),
        PiiType::DriverLicense
    );
    assert_eq!(PiiType::from(IdentifierType::Passport), PiiType::Passport);
    assert_eq!(PiiType::from(IdentifierType::Ein), PiiType::Ein);
    assert_eq!(PiiType::from(IdentifierType::TaxId), PiiType::TaxId);
    assert_eq!(
        PiiType::from(IdentifierType::NationalId),
        PiiType::NationalId
    );
    assert_eq!(PiiType::from(IdentifierType::KoreaRrn), PiiType::KoreaRrn);
    assert_eq!(
        PiiType::from(IdentifierType::AustraliaTfn),
        PiiType::AustraliaTfn
    );
    assert_eq!(
        PiiType::from(IdentifierType::AustraliaAbn),
        PiiType::AustraliaAbn
    );
    assert_eq!(
        PiiType::from(IdentifierType::IndiaAadhaar),
        PiiType::IndiaAadhaar
    );
    assert_eq!(PiiType::from(IdentifierType::IndiaPan), PiiType::IndiaPan);
    assert_eq!(PiiType::from(IdentifierType::BrazilCpf), PiiType::BrazilCpf);
    assert_eq!(
        PiiType::from(IdentifierType::BrazilCnpj),
        PiiType::BrazilCnpj
    );
    assert_eq!(
        PiiType::from(IdentifierType::MexicoCurp),
        PiiType::MexicoCurp
    );
    assert_eq!(
        PiiType::from(IdentifierType::NigeriaNin),
        PiiType::NigeriaNin
    );
    assert_eq!(
        PiiType::from(IdentifierType::ThailandTnin),
        PiiType::ThailandTnin
    );
    assert_eq!(
        PiiType::from(IdentifierType::SingaporeNric),
        PiiType::SingaporeNric
    );
    assert_eq!(
        PiiType::from(IdentifierType::FinlandHetu),
        PiiType::FinlandHetu
    );
    assert_eq!(
        PiiType::from(IdentifierType::PolandPesel),
        PiiType::PolandPesel
    );
    assert_eq!(
        PiiType::from(IdentifierType::ItalyFiscalCode),
        PiiType::ItalyFiscalCode
    );
    assert_eq!(PiiType::from(IdentifierType::SpainNif), PiiType::SpainNif);
    assert_eq!(PiiType::from(IdentifierType::SpainNie), PiiType::SpainNie);
    assert_eq!(PiiType::from(IdentifierType::UkNi), PiiType::UkNi);

    // Organizational
    assert_eq!(
        PiiType::from(IdentifierType::EmployeeId),
        PiiType::EmployeeId
    );
    assert_eq!(PiiType::from(IdentifierType::StudentId), PiiType::StudentId);
    assert_eq!(
        PiiType::from(IdentifierType::BadgeNumber),
        PiiType::BadgeNumber
    );

    // Location
    assert_eq!(
        PiiType::from(IdentifierType::PostalCode),
        PiiType::PostalCode
    );

    // Biometric
    assert_eq!(
        PiiType::from(IdentifierType::BiometricTemplate),
        PiiType::BiometricTemplate
    );
}

#[test]
fn from_identifier_type_scanner_parity() {
    // Non-obvious mappings — these mirror what
    // observe/pii/scanner/domains.rs pushes for each detected
    // IdentifierType. Changing either side without the other would create
    // silent drift.

    // Personal (scanner: scan_personal)
    assert_eq!(PiiType::from(IdentifierType::PhoneNumber), PiiType::Phone);
    assert_eq!(PiiType::from(IdentifierType::PersonalName), PiiType::Name);

    // Organizational (scanner: scan_government, L75-77)
    assert_eq!(PiiType::from(IdentifierType::VehicleId), PiiType::Vin);

    // Location (scanner: scan_location)
    assert_eq!(
        PiiType::from(IdentifierType::GPSCoordinate),
        PiiType::GpsCoordinates
    );
    assert_eq!(
        PiiType::from(IdentifierType::StreetAddress),
        PiiType::Address
    );

    // Medical (scanner: scan_medical)
    assert_eq!(
        PiiType::from(IdentifierType::MedicalRecordNumber),
        PiiType::Mrn
    );
    assert_eq!(PiiType::from(IdentifierType::ProviderID), PiiType::Npi);
    assert_eq!(
        PiiType::from(IdentifierType::HealthInsurance),
        PiiType::InsuranceNumber
    );
    assert_eq!(PiiType::from(IdentifierType::MedicalCode), PiiType::IcdCode);
    assert_eq!(
        PiiType::from(IdentifierType::Prescription),
        PiiType::PrescriptionNumber
    );
    assert_eq!(
        PiiType::from(IdentifierType::MedicalLicense),
        PiiType::DeaNumber
    );

    // Biometric (scanner: scan_biometric)
    assert_eq!(
        PiiType::from(IdentifierType::Fingerprint),
        PiiType::FingerprintId
    );
    assert_eq!(
        PiiType::from(IdentifierType::FacialRecognition),
        PiiType::FaceId
    );
    assert_eq!(PiiType::from(IdentifierType::IrisScan), PiiType::IrisId);
    assert_eq!(PiiType::from(IdentifierType::VoicePrint), PiiType::VoiceId);
    assert_eq!(PiiType::from(IdentifierType::DNASequence), PiiType::DnaId);
}

#[test]
fn from_identifier_type_fallback_mappings() {
    // Pin the intentional fallbacks so they can't silently change. When a
    // dedicated PiiType variant is eventually added, the corresponding
    // assertion here will flip and signal the mapping needs review.

    // Provider-specific developer tokens now map to dedicated variants
    // (issue #97). HighEntropyString remains the only ApiKey fallback —
    // AWS secret keys are 40 base64 chars and indistinguishable from
    // random high-entropy strings without context.
    assert_eq!(
        PiiType::from(IdentifierType::GitHubToken),
        PiiType::GitHubToken
    );
    assert_eq!(
        PiiType::from(IdentifierType::GitLabToken),
        PiiType::GitLabToken
    );
    assert_eq!(
        PiiType::from(IdentifierType::AwsAccessKey),
        PiiType::AwsAccessKey
    );
    assert_eq!(
        PiiType::from(IdentifierType::AwsSessionToken),
        PiiType::AwsSessionToken
    );
    assert_eq!(
        PiiType::from(IdentifierType::HighEntropyString),
        PiiType::ApiKey,
        "HighEntropyString remains the ApiKey fallback (no dedicated variant)"
    );

    // Generic catch-all
    assert_eq!(PiiType::from(IdentifierType::Unknown), PiiType::Generic);
}

//! Canonical string labels for [`IdentifierType`].
//!
//! The bidirectional bridge between the enum and its wire name — the
//! SCREAMING_SNAKE_CASE label that appears in LLM recognizer configs, detection
//! prompts, and `RecognizerResult::entity_type`.
//!
//! Kept in its own file rather than alongside the enum in `core.rs`: the table
//! has one arm per variant in each direction, so inlining it would push that
//! file past the project's split threshold while burying the type definitions.

use super::core::IdentifierType;

impl IdentifierType {
    /// The canonical SCREAMING_SNAKE_CASE label for this type.
    ///
    /// This is the wire name: it is what an LLM recognizer's `entity_mapping`
    /// keys on, what an LLM detection prompt asks models to emit, and what
    /// appears in a
    /// [`RecognizerResult`](crate::anonymize::RecognizerResult)'s `entity_type`.
    /// Presidio's spellings are used where one exists (`PERSON`, `US_SSN`,
    /// `IBAN_CODE`) so a config written against Presidio transfers unchanged.
    ///
    /// The match has no wildcard arm. Because `IdentifierType` is not
    /// `#[non_exhaustive]`, adding a variant fails compilation here until it is
    /// given a label — the same compile-time guard
    /// `From<IdentifierType> for PiiType` uses to keep the PII bridge in sync.
    ///
    /// Labels are stable across releases: they end up in stored audit records
    /// and in operator-authored config files.
    ///
    /// # Examples
    ///
    /// ```
    /// use octarine::identifiers::IdentifierType;
    ///
    /// assert_eq!(IdentifierType::Email.as_str(), "EMAIL_ADDRESS");
    /// assert_eq!(IdentifierType::PersonalName.as_str(), "PERSON");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            // Personal
            Self::Email => "EMAIL_ADDRESS",
            Self::PhoneNumber => "PHONE_NUMBER",
            Self::Ssn => "US_SSN",
            Self::PersonalName => "PERSON",
            Self::Birthdate => "BIRTHDATE",
            Self::Username => "USERNAME",
            Self::Age => "AGE",
            Self::Nationality => "NATIONALITY",
            Self::Religion => "RELIGION",
            Self::PoliticalAffiliation => "POLITICAL_AFFILIATION",

            // Credential
            Self::Password => "PASSWORD",
            Self::Pin => "PIN",
            Self::SecurityAnswer => "SECURITY_ANSWER",
            Self::Passphrase => "PASSPHRASE",

            // Network
            Self::Uuid => "UUID",
            Self::IpAddress => "IP_ADDRESS",
            Self::MacAddress => "MAC_ADDRESS",
            Self::Url => "URL",
            Self::Domain => "DOMAIN",
            Self::Hostname => "HOSTNAME",
            Self::Port => "PORT",

            // Payment
            Self::CreditCard => "CREDIT_CARD",
            Self::BankAccount => "US_BANK_NUMBER",
            Self::RoutingNumber => "ROUTING_NUMBER",
            Self::PaymentToken => "PAYMENT_TOKEN",
            Self::CryptoAddress => "CRYPTO_ADDRESS",
            Self::Iban => "IBAN_CODE",
            Self::IndiaUpi => "INDIA_UPI",

            // Token/Key
            Self::GitHubToken => "GITHUB_TOKEN",
            Self::GitLabToken => "GITLAB_TOKEN",
            Self::AwsAccessKey => "AWS_ACCESS_KEY",
            Self::AwsSessionToken => "AWS_SESSION_TOKEN",
            Self::Jwt => "JWT",
            Self::ApiKey => "API_KEY",
            Self::SessionId => "SESSION_ID",
            Self::OAuthToken => "OAUTH_TOKEN",
            Self::SshKey => "SSH_KEY",
            Self::OnePasswordToken => "ONEPASSWORD_TOKEN",
            Self::OnePasswordVaultRef => "ONEPASSWORD_VAULT_REF",
            Self::BearerToken => "BEARER_TOKEN",
            Self::UrlWithCredentials => "URL_WITH_CREDENTIALS",
            Self::HighEntropyString => "HIGH_ENTROPY_STRING",

            // Database
            Self::ConnectionString => "CONNECTION_STRING",

            // Government/Official
            Self::DriverLicense => "US_DRIVER_LICENSE",
            Self::Passport => "US_PASSPORT",
            Self::Ein => "US_EIN",
            Self::Itin => "US_ITIN",
            Self::Mbi => "US_MBI",
            Self::TaxId => "TAX_ID",
            Self::NationalId => "NATIONAL_ID",
            Self::KoreaRrn => "KOREA_RRN",
            Self::KoreaFrn => "KOREA_FRN",
            Self::KoreaDriverLicense => "KOREA_DRIVER_LICENSE",
            Self::KoreaPassport => "KOREA_PASSPORT",
            Self::KoreaBrn => "KOREA_BRN",
            Self::AustraliaTfn => "AUSTRALIA_TFN",
            Self::AustraliaAbn => "AUSTRALIA_ABN",
            Self::AustraliaMedicare => "AUSTRALIA_MEDICARE",
            Self::AustraliaAcn => "AUSTRALIA_ACN",
            Self::IndiaAadhaar => "INDIA_AADHAAR",
            Self::IndiaPan => "INDIA_PAN",
            Self::IndiaGstin => "INDIA_GSTIN",
            Self::IndiaVehicleReg => "INDIA_VEHICLE_REG",
            Self::IndiaVoterId => "INDIA_VOTER_ID",
            Self::IndiaPassport => "INDIA_PASSPORT",
            Self::BrazilCpf => "BRAZIL_CPF",
            Self::BrazilCnpj => "BRAZIL_CNPJ",
            Self::MexicoCurp => "MEXICO_CURP",
            Self::NigeriaNin => "NIGERIA_NIN",
            Self::NigeriaBvn => "NIGERIA_BVN",
            Self::NigeriaVehicleReg => "NIGERIA_VEHICLE_REG",
            Self::ThailandTnin => "THAILAND_TNIN",
            Self::TurkeyTckn => "TURKEY_TCKN",
            Self::TurkeyLicensePlate => "TURKEY_LICENSE_PLATE",
            Self::SingaporeNric => "SINGAPORE_NRIC",
            Self::SingaporeUen => "SINGAPORE_UEN",
            Self::FinlandHetu => "FINLAND_HETU",
            Self::PolandPesel => "POLAND_PESEL",
            Self::ItalyFiscalCode => "ITALY_FISCAL_CODE",
            Self::ItalyVat => "ITALY_VAT",
            Self::ItalyPassport => "ITALY_PASSPORT",
            Self::ItalyIdentityCard => "ITALY_IDENTITY_CARD",
            Self::ItalyDriverLicense => "ITALY_DRIVER_LICENSE",
            Self::SpainNif => "SPAIN_NIF",
            Self::SpainNie => "SPAIN_NIE",
            Self::SpainPassport => "SPAIN_PASSPORT",
            Self::UkNi => "UK_NINO",
            Self::UkNhs => "UK_NHS",
            Self::UkPassport => "UK_PASSPORT",
            Self::UkDrivingLicence => "UK_DRIVING_LICENCE",
            Self::SwedenPersonnummer => "SWEDEN_PERSONNUMMER",
            Self::SwedenOrgnummer => "SWEDEN_ORGNUMMER",
            Self::GermanyTaxId => "GERMANY_TAX_ID",
            Self::GermanyIdCard => "GERMANY_ID_CARD",
            Self::GermanyPassport => "GERMANY_PASSPORT",

            // Organizational
            Self::EmployeeId => "EMPLOYEE_ID",
            Self::StudentId => "STUDENT_ID",
            Self::BadgeNumber => "BADGE_NUMBER",
            Self::VehicleId => "VEHICLE_ID",

            // Location
            Self::GPSCoordinate => "GPS_COORDINATE",
            Self::StreetAddress => "STREET_ADDRESS",
            Self::PostalCode => "POSTAL_CODE",
            Self::NamedLocation => "NAMED_LOCATION",

            // Medical/Health
            Self::MedicalRecordNumber => "MEDICAL_RECORD_NUMBER",
            Self::HealthInsurance => "HEALTH_INSURANCE",
            Self::Prescription => "PRESCRIPTION",
            Self::ProviderID => "PROVIDER_ID",
            Self::MedicalCode => "MEDICAL_CODE",
            Self::MedicalLicense => "MEDICAL_LICENSE",
            Self::UsClia => "US_CLIA",

            // Biometric
            Self::Fingerprint => "FINGERPRINT",
            Self::FacialRecognition => "FACIAL_RECOGNITION",
            Self::IrisScan => "IRIS_SCAN",
            Self::VoicePrint => "VOICE_PRINT",
            Self::DNASequence => "DNA_SEQUENCE",
            Self::BiometricTemplate => "BIOMETRIC_TEMPLATE",

            // Generic
            Self::Unknown => "UNKNOWN",
        }
    }
}

impl std::fmt::Display for IdentifierType {
    /// Renders the canonical label, so `{}` and [`as_str`](IdentifierType::as_str)
    /// never diverge.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for IdentifierType {
    type Err = UnknownIdentifierType;

    /// Parses a canonical label back into its variant.
    ///
    /// Matching is case-insensitive on the ASCII label, so `email_address` and
    /// `EMAIL_ADDRESS` both resolve — operator-authored TOML should not fail on
    /// capitalization.
    ///
    /// An unrecognized label is an **error, never
    /// [`Unknown`](IdentifierType::Unknown)**. Degrading a typo to `Unknown`
    /// would silently reduce detection coverage: a config asking for `PERSEN`
    /// would load clean and then quietly detect nothing. Failing here surfaces
    /// the typo at startup instead.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownIdentifierType`] carrying the unrecognized input.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use octarine::identifiers::IdentifierType;
    ///
    /// assert_eq!(IdentifierType::from_str("PERSON"), Ok(IdentifierType::PersonalName));
    /// assert!(IdentifierType::from_str("PERSEN").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let upper = s.trim().to_ascii_uppercase();
        match upper.as_str() {
            "EMAIL_ADDRESS" => Ok(Self::Email),
            "PHONE_NUMBER" => Ok(Self::PhoneNumber),
            "US_SSN" => Ok(Self::Ssn),
            "PERSON" => Ok(Self::PersonalName),
            "BIRTHDATE" => Ok(Self::Birthdate),
            "USERNAME" => Ok(Self::Username),
            "AGE" => Ok(Self::Age),
            "NATIONALITY" => Ok(Self::Nationality),
            "RELIGION" => Ok(Self::Religion),
            "POLITICAL_AFFILIATION" => Ok(Self::PoliticalAffiliation),
            "PASSWORD" => Ok(Self::Password),
            "PIN" => Ok(Self::Pin),
            "SECURITY_ANSWER" => Ok(Self::SecurityAnswer),
            "PASSPHRASE" => Ok(Self::Passphrase),
            "UUID" => Ok(Self::Uuid),
            "IP_ADDRESS" => Ok(Self::IpAddress),
            "MAC_ADDRESS" => Ok(Self::MacAddress),
            "URL" => Ok(Self::Url),
            "DOMAIN" => Ok(Self::Domain),
            "HOSTNAME" => Ok(Self::Hostname),
            "PORT" => Ok(Self::Port),
            "CREDIT_CARD" => Ok(Self::CreditCard),
            "US_BANK_NUMBER" => Ok(Self::BankAccount),
            "ROUTING_NUMBER" => Ok(Self::RoutingNumber),
            "PAYMENT_TOKEN" => Ok(Self::PaymentToken),
            "CRYPTO_ADDRESS" => Ok(Self::CryptoAddress),
            "IBAN_CODE" => Ok(Self::Iban),
            "INDIA_UPI" => Ok(Self::IndiaUpi),
            "GITHUB_TOKEN" => Ok(Self::GitHubToken),
            "GITLAB_TOKEN" => Ok(Self::GitLabToken),
            "AWS_ACCESS_KEY" => Ok(Self::AwsAccessKey),
            "AWS_SESSION_TOKEN" => Ok(Self::AwsSessionToken),
            "JWT" => Ok(Self::Jwt),
            "API_KEY" => Ok(Self::ApiKey),
            "SESSION_ID" => Ok(Self::SessionId),
            "OAUTH_TOKEN" => Ok(Self::OAuthToken),
            "SSH_KEY" => Ok(Self::SshKey),
            "ONEPASSWORD_TOKEN" => Ok(Self::OnePasswordToken),
            "ONEPASSWORD_VAULT_REF" => Ok(Self::OnePasswordVaultRef),
            "BEARER_TOKEN" => Ok(Self::BearerToken),
            "URL_WITH_CREDENTIALS" => Ok(Self::UrlWithCredentials),
            "HIGH_ENTROPY_STRING" => Ok(Self::HighEntropyString),
            "CONNECTION_STRING" => Ok(Self::ConnectionString),
            "US_DRIVER_LICENSE" => Ok(Self::DriverLicense),
            "US_PASSPORT" => Ok(Self::Passport),
            "US_EIN" => Ok(Self::Ein),
            "US_ITIN" => Ok(Self::Itin),
            "US_MBI" => Ok(Self::Mbi),
            "TAX_ID" => Ok(Self::TaxId),
            "NATIONAL_ID" => Ok(Self::NationalId),
            "KOREA_RRN" => Ok(Self::KoreaRrn),
            "KOREA_FRN" => Ok(Self::KoreaFrn),
            "KOREA_DRIVER_LICENSE" => Ok(Self::KoreaDriverLicense),
            "KOREA_PASSPORT" => Ok(Self::KoreaPassport),
            "KOREA_BRN" => Ok(Self::KoreaBrn),
            "AUSTRALIA_TFN" => Ok(Self::AustraliaTfn),
            "AUSTRALIA_ABN" => Ok(Self::AustraliaAbn),
            "AUSTRALIA_MEDICARE" => Ok(Self::AustraliaMedicare),
            "AUSTRALIA_ACN" => Ok(Self::AustraliaAcn),
            "INDIA_AADHAAR" => Ok(Self::IndiaAadhaar),
            "INDIA_PAN" => Ok(Self::IndiaPan),
            "INDIA_GSTIN" => Ok(Self::IndiaGstin),
            "INDIA_VEHICLE_REG" => Ok(Self::IndiaVehicleReg),
            "INDIA_VOTER_ID" => Ok(Self::IndiaVoterId),
            "INDIA_PASSPORT" => Ok(Self::IndiaPassport),
            "BRAZIL_CPF" => Ok(Self::BrazilCpf),
            "BRAZIL_CNPJ" => Ok(Self::BrazilCnpj),
            "MEXICO_CURP" => Ok(Self::MexicoCurp),
            "NIGERIA_NIN" => Ok(Self::NigeriaNin),
            "NIGERIA_BVN" => Ok(Self::NigeriaBvn),
            "NIGERIA_VEHICLE_REG" => Ok(Self::NigeriaVehicleReg),
            "THAILAND_TNIN" => Ok(Self::ThailandTnin),
            "TURKEY_TCKN" => Ok(Self::TurkeyTckn),
            "TURKEY_LICENSE_PLATE" => Ok(Self::TurkeyLicensePlate),
            "SINGAPORE_NRIC" => Ok(Self::SingaporeNric),
            "SINGAPORE_UEN" => Ok(Self::SingaporeUen),
            "FINLAND_HETU" => Ok(Self::FinlandHetu),
            "POLAND_PESEL" => Ok(Self::PolandPesel),
            "ITALY_FISCAL_CODE" => Ok(Self::ItalyFiscalCode),
            "ITALY_VAT" => Ok(Self::ItalyVat),
            "ITALY_PASSPORT" => Ok(Self::ItalyPassport),
            "ITALY_IDENTITY_CARD" => Ok(Self::ItalyIdentityCard),
            "ITALY_DRIVER_LICENSE" => Ok(Self::ItalyDriverLicense),
            "SPAIN_NIF" => Ok(Self::SpainNif),
            "SPAIN_NIE" => Ok(Self::SpainNie),
            "SPAIN_PASSPORT" => Ok(Self::SpainPassport),
            "UK_NINO" => Ok(Self::UkNi),
            "UK_NHS" => Ok(Self::UkNhs),
            "UK_PASSPORT" => Ok(Self::UkPassport),
            "UK_DRIVING_LICENCE" => Ok(Self::UkDrivingLicence),
            "SWEDEN_PERSONNUMMER" => Ok(Self::SwedenPersonnummer),
            "SWEDEN_ORGNUMMER" => Ok(Self::SwedenOrgnummer),
            "GERMANY_TAX_ID" => Ok(Self::GermanyTaxId),
            "GERMANY_ID_CARD" => Ok(Self::GermanyIdCard),
            "GERMANY_PASSPORT" => Ok(Self::GermanyPassport),
            "EMPLOYEE_ID" => Ok(Self::EmployeeId),
            "STUDENT_ID" => Ok(Self::StudentId),
            "BADGE_NUMBER" => Ok(Self::BadgeNumber),
            "VEHICLE_ID" => Ok(Self::VehicleId),
            "GPS_COORDINATE" => Ok(Self::GPSCoordinate),
            "STREET_ADDRESS" => Ok(Self::StreetAddress),
            "POSTAL_CODE" => Ok(Self::PostalCode),
            "NAMED_LOCATION" => Ok(Self::NamedLocation),
            "MEDICAL_RECORD_NUMBER" => Ok(Self::MedicalRecordNumber),
            "HEALTH_INSURANCE" => Ok(Self::HealthInsurance),
            "PRESCRIPTION" => Ok(Self::Prescription),
            "PROVIDER_ID" => Ok(Self::ProviderID),
            "MEDICAL_CODE" => Ok(Self::MedicalCode),
            "MEDICAL_LICENSE" => Ok(Self::MedicalLicense),
            "US_CLIA" => Ok(Self::UsClia),
            "FINGERPRINT" => Ok(Self::Fingerprint),
            "FACIAL_RECOGNITION" => Ok(Self::FacialRecognition),
            "IRIS_SCAN" => Ok(Self::IrisScan),
            "VOICE_PRINT" => Ok(Self::VoicePrint),
            "DNA_SEQUENCE" => Ok(Self::DNASequence),
            "BIOMETRIC_TEMPLATE" => Ok(Self::BiometricTemplate),
            "UNKNOWN" => Ok(Self::Unknown),
            _ => Err(UnknownIdentifierType(s.to_string())),
        }
    }
}

/// The error returned when a string does not name an [`IdentifierType`].
///
/// Carries the offending input so a caller can build a message naming both the
/// config field and the value — an LLM recognizer config reports
/// `recognizer.entity_mapping.PERSEN: unknown IdentifierType "PERSEN"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownIdentifierType(pub String);

impl std::fmt::Display for UnknownIdentifierType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown IdentifierType {:?}", self.0)
    }
}

impl std::error::Error for UnknownIdentifierType {}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use std::collections::HashSet;
    use std::str::FromStr;

    /// Every variant, so the round-trip and uniqueness tests cover the whole
    /// enum rather than a sample. Kept exhaustive by the same compile-time
    /// guard as `as_str`: a new variant must be added here too.
    fn all_variants() -> Vec<IdentifierType> {
        vec![
            IdentifierType::Email,
            IdentifierType::PhoneNumber,
            IdentifierType::Ssn,
            IdentifierType::PersonalName,
            IdentifierType::Birthdate,
            IdentifierType::Username,
            IdentifierType::Age,
            IdentifierType::Nationality,
            IdentifierType::Religion,
            IdentifierType::PoliticalAffiliation,
            IdentifierType::Password,
            IdentifierType::Pin,
            IdentifierType::SecurityAnswer,
            IdentifierType::Passphrase,
            IdentifierType::Uuid,
            IdentifierType::IpAddress,
            IdentifierType::MacAddress,
            IdentifierType::Url,
            IdentifierType::Domain,
            IdentifierType::Hostname,
            IdentifierType::Port,
            IdentifierType::CreditCard,
            IdentifierType::BankAccount,
            IdentifierType::RoutingNumber,
            IdentifierType::PaymentToken,
            IdentifierType::CryptoAddress,
            IdentifierType::Iban,
            IdentifierType::IndiaUpi,
            IdentifierType::GitHubToken,
            IdentifierType::GitLabToken,
            IdentifierType::AwsAccessKey,
            IdentifierType::AwsSessionToken,
            IdentifierType::Jwt,
            IdentifierType::ApiKey,
            IdentifierType::SessionId,
            IdentifierType::OAuthToken,
            IdentifierType::SshKey,
            IdentifierType::OnePasswordToken,
            IdentifierType::OnePasswordVaultRef,
            IdentifierType::BearerToken,
            IdentifierType::UrlWithCredentials,
            IdentifierType::HighEntropyString,
            IdentifierType::ConnectionString,
            IdentifierType::DriverLicense,
            IdentifierType::Passport,
            IdentifierType::Ein,
            IdentifierType::Itin,
            IdentifierType::Mbi,
            IdentifierType::TaxId,
            IdentifierType::NationalId,
            IdentifierType::KoreaRrn,
            IdentifierType::KoreaFrn,
            IdentifierType::KoreaDriverLicense,
            IdentifierType::KoreaPassport,
            IdentifierType::KoreaBrn,
            IdentifierType::AustraliaTfn,
            IdentifierType::AustraliaAbn,
            IdentifierType::AustraliaMedicare,
            IdentifierType::AustraliaAcn,
            IdentifierType::IndiaAadhaar,
            IdentifierType::IndiaPan,
            IdentifierType::IndiaGstin,
            IdentifierType::IndiaVehicleReg,
            IdentifierType::IndiaVoterId,
            IdentifierType::IndiaPassport,
            IdentifierType::BrazilCpf,
            IdentifierType::BrazilCnpj,
            IdentifierType::MexicoCurp,
            IdentifierType::NigeriaNin,
            IdentifierType::NigeriaBvn,
            IdentifierType::NigeriaVehicleReg,
            IdentifierType::ThailandTnin,
            IdentifierType::TurkeyTckn,
            IdentifierType::TurkeyLicensePlate,
            IdentifierType::SingaporeNric,
            IdentifierType::SingaporeUen,
            IdentifierType::FinlandHetu,
            IdentifierType::PolandPesel,
            IdentifierType::ItalyFiscalCode,
            IdentifierType::ItalyVat,
            IdentifierType::ItalyPassport,
            IdentifierType::ItalyIdentityCard,
            IdentifierType::ItalyDriverLicense,
            IdentifierType::SpainNif,
            IdentifierType::SpainNie,
            IdentifierType::SpainPassport,
            IdentifierType::UkNi,
            IdentifierType::UkNhs,
            IdentifierType::UkPassport,
            IdentifierType::UkDrivingLicence,
            IdentifierType::SwedenPersonnummer,
            IdentifierType::SwedenOrgnummer,
            IdentifierType::GermanyTaxId,
            IdentifierType::GermanyIdCard,
            IdentifierType::GermanyPassport,
            IdentifierType::EmployeeId,
            IdentifierType::StudentId,
            IdentifierType::BadgeNumber,
            IdentifierType::VehicleId,
            IdentifierType::GPSCoordinate,
            IdentifierType::StreetAddress,
            IdentifierType::PostalCode,
            IdentifierType::NamedLocation,
            IdentifierType::MedicalRecordNumber,
            IdentifierType::HealthInsurance,
            IdentifierType::Prescription,
            IdentifierType::ProviderID,
            IdentifierType::MedicalCode,
            IdentifierType::MedicalLicense,
            IdentifierType::UsClia,
            IdentifierType::Fingerprint,
            IdentifierType::FacialRecognition,
            IdentifierType::IrisScan,
            IdentifierType::VoicePrint,
            IdentifierType::DNASequence,
            IdentifierType::BiometricTemplate,
            IdentifierType::Unknown,
        ]
    }

    #[test]
    fn every_variant_round_trips_through_its_label() {
        for variant in all_variants() {
            let label = variant.as_str();
            let parsed = IdentifierType::from_str(label)
                .unwrap_or_else(|_| panic!("{label} must parse back to {variant:?}"));
            assert_eq!(
                parsed, variant,
                "{label} parsed to {parsed:?}, not the {variant:?} it came from"
            );
        }
    }

    #[test]
    fn labels_are_unique_across_every_variant() {
        // A collision would make `from_str` silently resolve one variant's
        // label to a different variant — the round-trip test above would then
        // fail for whichever lost, but this names the real cause.
        let variants = all_variants();
        let labels: HashSet<&str> = variants.iter().map(IdentifierType::as_str).collect();
        assert_eq!(
            labels.len(),
            variants.len(),
            "two variants share a label; every label must be distinct"
        );
    }

    #[test]
    fn an_unknown_label_is_an_error_not_the_unknown_variant() {
        // The whole point of strict resolution: a typo must fail loudly at
        // load time rather than degrade to a variant that detects nothing.
        let err = IdentifierType::from_str("PERSEN").expect_err("a typo must not resolve");
        assert_eq!(err, UnknownIdentifierType("PERSEN".to_string()));
        assert_ne!(
            IdentifierType::from_str("PERSEN").ok(),
            Some(IdentifierType::Unknown),
            "degrading to Unknown would silently reduce detection coverage"
        );
    }

    #[test]
    fn the_error_message_quotes_the_offending_value() {
        // A config loader builds its field-path message around this.
        let rendered = UnknownIdentifierType("PERSEN".to_string()).to_string();
        assert!(
            rendered.contains("PERSEN"),
            "the message must name the value that failed: {rendered}"
        );
    }

    #[test]
    fn parsing_is_case_insensitive_and_trims() {
        // Operator-authored TOML should not fail on capitalization.
        for spelling in [
            "EMAIL_ADDRESS",
            "email_address",
            "Email_Address",
            "  EMAIL_ADDRESS  ",
        ] {
            assert_eq!(
                IdentifierType::from_str(spelling),
                Ok(IdentifierType::Email),
                "{spelling:?} must resolve to Email"
            );
        }
    }

    #[test]
    fn presidio_spellings_are_used_where_one_exists() {
        // A config written against Presidio must transfer unchanged; a
        // mechanical derivation would have produced PERSONAL_NAME here.
        assert_eq!(IdentifierType::PersonalName.as_str(), "PERSON");
        assert_eq!(IdentifierType::Ssn.as_str(), "US_SSN");
        assert_eq!(IdentifierType::Iban.as_str(), "IBAN_CODE");
        assert_eq!(IdentifierType::Email.as_str(), "EMAIL_ADDRESS");
    }

    #[test]
    fn display_and_as_str_agree() {
        for variant in all_variants() {
            assert_eq!(variant.to_string(), variant.as_str());
        }
    }

    #[test]
    fn an_empty_or_whitespace_label_is_rejected() {
        for blank in ["", "   ", "\t"] {
            assert!(
                IdentifierType::from_str(blank).is_err(),
                "{blank:?} names no type"
            );
        }
    }
}

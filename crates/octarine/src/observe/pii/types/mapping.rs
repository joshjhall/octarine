//! `From<IdentifierType> for PiiType` bridge
//!
//! Maps every `IdentifierType` variant to its `PiiType` counterpart. The match
//! has no wildcard arm; because `IdentifierType` is not `#[non_exhaustive]`,
//! adding a new variant will fail compilation here until it is explicitly
//! mapped. This is the compile-time bridge that keeps the two registries in
//! sync — the scanner (`observe/pii/scanner/domains.rs`) remains the
//! authoritative source for the mapping semantics.

use crate::primitives::identifiers::IdentifierType;

use super::PiiType;

impl From<IdentifierType> for PiiType {
    fn from(id: IdentifierType) -> Self {
        match id {
            // Personal
            IdentifierType::Email => Self::Email,
            IdentifierType::PhoneNumber => Self::Phone,
            IdentifierType::Ssn => Self::Ssn,
            IdentifierType::PersonalName => Self::Name,
            IdentifierType::Birthdate => Self::Birthdate,
            IdentifierType::Username => Self::Username,
            IdentifierType::Age => Self::Age,
            IdentifierType::Nationality => Self::Nationality,
            IdentifierType::Religion => Self::Religion,
            IdentifierType::PoliticalAffiliation => Self::PoliticalAffiliation,

            // Credential
            IdentifierType::Password => Self::Password,
            IdentifierType::Pin => Self::Pin,
            IdentifierType::SecurityAnswer => Self::SecurityAnswer,
            IdentifierType::Passphrase => Self::Passphrase,

            // Network
            IdentifierType::Uuid => Self::Uuid,
            IdentifierType::IpAddress => Self::IpAddress,
            IdentifierType::MacAddress => Self::MacAddress,
            IdentifierType::Url => Self::Url,
            IdentifierType::Domain => Self::Domain,
            IdentifierType::Hostname => Self::Hostname,
            IdentifierType::Port => Self::Port,

            // Payment
            IdentifierType::CreditCard => Self::CreditCard,
            IdentifierType::BankAccount => Self::BankAccount,
            IdentifierType::RoutingNumber => Self::RoutingNumber,
            IdentifierType::PaymentToken => Self::PaymentToken,
            IdentifierType::CryptoAddress => Self::CryptoAddress,
            IdentifierType::Iban => Self::Iban,

            // Token/Key
            IdentifierType::Jwt => Self::Jwt,
            IdentifierType::ApiKey => Self::ApiKey,
            IdentifierType::SessionId => Self::SessionId,
            IdentifierType::OAuthToken => Self::OAuthToken,
            IdentifierType::SshKey => Self::SshKey,
            IdentifierType::OnePasswordToken => Self::OnePasswordToken,
            IdentifierType::OnePasswordVaultRef => Self::OnePasswordVaultRef,
            IdentifierType::BearerToken => Self::BearerToken,
            IdentifierType::UrlWithCredentials => Self::UrlWithCredentials,
            // Provider-specific developer tokens — each maps to its dedicated
            // PiiType variant. AWS secret keys still fall back via
            // HighEntropyString (no dedicated variant — they're 40 base64
            // chars, indistinguishable from random high-entropy strings).
            IdentifierType::GitHubToken => Self::GitHubToken,
            IdentifierType::GitLabToken => Self::GitLabToken,
            IdentifierType::AwsAccessKey => Self::AwsAccessKey,
            IdentifierType::AwsSessionToken => Self::AwsSessionToken,
            IdentifierType::HighEntropyString => Self::ApiKey,

            // Database
            IdentifierType::ConnectionString => Self::ConnectionString,

            // Government
            IdentifierType::DriverLicense => Self::DriverLicense,
            IdentifierType::Passport => Self::Passport,
            IdentifierType::Ein => Self::Ein,
            IdentifierType::TaxId => Self::TaxId,
            IdentifierType::NationalId => Self::NationalId,
            IdentifierType::KoreaRrn => Self::KoreaRrn,
            IdentifierType::KoreaFrn => Self::KoreaFrn,
            IdentifierType::KoreaDriverLicense => Self::KoreaDriverLicense,
            IdentifierType::KoreaPassport => Self::KoreaPassport,
            IdentifierType::KoreaBrn => Self::KoreaBrn,
            IdentifierType::AustraliaTfn => Self::AustraliaTfn,
            IdentifierType::AustraliaAbn => Self::AustraliaAbn,
            IdentifierType::AustraliaMedicare => Self::AustraliaMedicare,
            IdentifierType::AustraliaAcn => Self::AustraliaAcn,
            IdentifierType::IndiaAadhaar => Self::IndiaAadhaar,
            IdentifierType::IndiaPan => Self::IndiaPan,
            IdentifierType::IndiaGstin => Self::IndiaGstin,
            IdentifierType::IndiaVehicleReg => Self::IndiaVehicleReg,
            IdentifierType::IndiaVoterId => Self::IndiaVoterId,
            IdentifierType::IndiaPassport => Self::IndiaPassport,
            IdentifierType::BrazilCpf => Self::BrazilCpf,
            IdentifierType::BrazilCnpj => Self::BrazilCnpj,
            IdentifierType::MexicoCurp => Self::MexicoCurp,
            IdentifierType::NigeriaNin => Self::NigeriaNin,
            IdentifierType::NigeriaBvn => Self::NigeriaBvn,
            IdentifierType::NigeriaVehicleReg => Self::NigeriaVehicleReg,
            IdentifierType::ThailandTnin => Self::ThailandTnin,
            IdentifierType::SingaporeNric => Self::SingaporeNric,
            IdentifierType::SingaporeUen => Self::SingaporeUen,
            IdentifierType::FinlandHetu => Self::FinlandHetu,
            IdentifierType::PolandPesel => Self::PolandPesel,
            IdentifierType::ItalyFiscalCode => Self::ItalyFiscalCode,
            IdentifierType::ItalyVat => Self::ItalyVat,
            IdentifierType::ItalyPassport => Self::ItalyPassport,
            IdentifierType::ItalyIdentityCard => Self::ItalyIdentityCard,
            IdentifierType::ItalyDriverLicense => Self::ItalyDriverLicense,
            IdentifierType::SpainNif => Self::SpainNif,
            IdentifierType::SpainNie => Self::SpainNie,
            IdentifierType::UkNi => Self::UkNi,

            // Organizational
            IdentifierType::EmployeeId => Self::EmployeeId,
            IdentifierType::StudentId => Self::StudentId,
            IdentifierType::BadgeNumber => Self::BadgeNumber,
            IdentifierType::VehicleId => Self::Vin,

            // Location
            IdentifierType::GPSCoordinate => Self::GpsCoordinates,
            IdentifierType::StreetAddress => Self::Address,
            IdentifierType::PostalCode => Self::PostalCode,
            IdentifierType::NamedLocation => Self::NamedLocation,

            // Medical
            IdentifierType::MedicalRecordNumber => Self::Mrn,
            IdentifierType::HealthInsurance => Self::InsuranceNumber,
            IdentifierType::Prescription => Self::PrescriptionNumber,
            IdentifierType::ProviderID => Self::Npi,
            IdentifierType::MedicalCode => Self::IcdCode,
            IdentifierType::MedicalLicense => Self::DeaNumber,

            // Biometric
            IdentifierType::Fingerprint => Self::FingerprintId,
            IdentifierType::FacialRecognition => Self::FaceId,
            IdentifierType::IrisScan => Self::IrisId,
            IdentifierType::VoicePrint => Self::VoiceId,
            IdentifierType::DNASequence => Self::DnaId,
            IdentifierType::BiometricTemplate => Self::BiometricTemplate,

            // Generic
            IdentifierType::Unknown => Self::Generic,
        }
    }
}

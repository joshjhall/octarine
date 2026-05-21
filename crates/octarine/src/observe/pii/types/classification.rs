//! Compliance classification methods for `PiiType`
//!
//! - `is_high_risk`: financial, government, medical, biometric, credentials
//! - `is_gdpr_protected`: EU regulation coverage
//! - `is_pci_protected`: PCI-DSS coverage
//! - `is_hipaa_protected`: HIPAA PHI coverage
//! - `is_secret`: never-loggable credentials and tokens

use super::PiiType;

impl PiiType {
    /// Returns true if this PII type is considered high-risk
    ///
    /// High-risk types include financial data, government IDs, medical records,
    /// biometric data, and authentication credentials.
    pub fn is_high_risk(&self) -> bool {
        matches!(
            self,
            // Financial
            Self::CreditCard | Self::BankAccount | Self::RoutingNumber | Self::PaymentToken |
            Self::Iban | Self::CryptoAddress |
            // Government (identity theft risk)
            Self::Ssn | Self::DriverLicense | Self::Passport | Self::Ein | Self::TaxId | Self::NationalId | Self::Vin |
            Self::KoreaRrn | Self::AustraliaTfn | Self::AustraliaAbn | Self::IndiaAadhaar | Self::IndiaPan |
            Self::IndiaGstin | Self::IndiaVehicleReg | Self::IndiaVoterId | Self::IndiaPassport |
            Self::BrazilCpf | Self::BrazilCnpj | Self::MexicoCurp | Self::NigeriaNin | Self::NigeriaBvn | Self::NigeriaVehicleReg | Self::ThailandTnin |
            Self::SingaporeNric | Self::FinlandHetu | Self::PolandPesel | Self::ItalyFiscalCode |
            Self::SpainNif | Self::SpainNie | Self::UkNi |
            // Medical (HIPAA)
            Self::Mrn | Self::Npi | Self::InsuranceNumber | Self::DeaNumber | Self::IcdCode | Self::PrescriptionNumber |
            // Biometric (irreplaceable)
            Self::FingerprintId | Self::FaceId | Self::VoiceId | Self::IrisId | Self::DnaId | Self::BiometricTemplate |
            // Authentication (security breach)
            Self::Password | Self::Pin | Self::SecurityAnswer | Self::Passphrase |
            Self::ApiKey | Self::Jwt | Self::SessionId | Self::OAuthToken | Self::SshKey |
            Self::OnePasswordToken | Self::OnePasswordVaultRef | Self::BearerToken | Self::UrlWithCredentials |
            Self::ConnectionString |
            Self::GitHubToken | Self::GitLabToken | Self::BitbucketToken |
            Self::AwsAccessKey | Self::AwsSessionToken |
            Self::GcpApiKey | Self::AzureKey | Self::StripeKey |
            Self::SquareToken | Self::ShopifyToken | Self::PayPalToken |
            Self::MailchimpToken | Self::MailgunToken | Self::ResendToken | Self::BrevoToken |
            Self::DatabricksToken | Self::VaultToken | Self::CloudflareOriginCaKey |
            Self::NpmToken | Self::PyPiToken | Self::NuGetKey | Self::ArtifactoryToken | Self::DockerHubToken |
            Self::TelegramToken | Self::SendGridToken | Self::OpenAiKey |
            Self::DiscordToken | Self::SlackToken | Self::TwilioToken |
            Self::HerokuToken | Self::LinearToken | Self::DopplerToken | Self::NetlifyToken |
            Self::FlyIoToken | Self::RenderToken | Self::PlanetScaleToken | Self::SupabaseToken
        )
    }

    /// Returns true if this PII type is covered by GDPR
    pub fn is_gdpr_protected(&self) -> bool {
        matches!(
            self,
            // Personal data
            Self::Email | Self::Phone | Self::Name | Self::Birthdate | Self::Username |
            // Government IDs
            Self::Ssn | Self::DriverLicense | Self::Passport | Self::TaxId | Self::NationalId |
            // EU-member country-specific government IDs (non-EU IDs like KoreaRrn,
            // AustraliaTfn/Abn, IndiaAadhaar/Pan/Gstin/VehicleReg/VoterId/Passport,
            // SingaporeNric are protected by their own regimes —
            // PIPA/Privacy Act 1988/DPDPA/PDPA — not GDPR)
            Self::FinlandHetu | Self::PolandPesel | Self::ItalyFiscalCode | Self::SpainNif | Self::SpainNie | Self::UkNi |
            // Financial — IBAN identifies an EU account holder (Recital 30 /
            // Art. 4(1)). Crypto addresses are pseudonymous by design and are
            // excluded unless linked to an identifiable person upstream.
            Self::Iban |
            // Location
            Self::IpAddress | Self::GpsCoordinates | Self::Address | Self::PostalCode |
            // Biometric
            Self::FingerprintId | Self::FaceId | Self::VoiceId | Self::IrisId | Self::DnaId | Self::BiometricTemplate |
            // Medical
            Self::Mrn | Self::InsuranceNumber
        )
    }

    /// Returns true if this PII type is covered by PCI-DSS
    pub fn is_pci_protected(&self) -> bool {
        matches!(
            self,
            Self::CreditCard
                | Self::BankAccount
                | Self::RoutingNumber
                | Self::PaymentToken
                | Self::Iban
                | Self::CryptoAddress
        )
    }

    /// Returns true if this PII type is covered by HIPAA (PHI)
    pub fn is_hipaa_protected(&self) -> bool {
        matches!(
            self,
            Self::Mrn
                | Self::Npi
                | Self::InsuranceNumber
                | Self::IcdCode
                | Self::PrescriptionNumber
                | Self::DeaNumber
                | Self::Ssn // SSN is also PHI in medical context
                | Self::Name // Names in medical context
                | Self::Birthdate // DOB in medical context
                | Self::Address // Address in medical context
                | Self::Phone // Phone in medical context
                | Self::Email // Email in medical context
                | Self::BiometricTemplate // Biometric identifiers are PHI under HIPAA
        )
    }

    /// Returns true if this is a secret/credential that should never be logged
    pub fn is_secret(&self) -> bool {
        matches!(
            self,
            Self::Password
                | Self::Pin
                | Self::SecurityAnswer
                | Self::Passphrase
                | Self::ApiKey
                | Self::Jwt
                | Self::SessionId
                | Self::OAuthToken
                | Self::SshKey
                | Self::OnePasswordToken
                | Self::OnePasswordVaultRef
                | Self::BearerToken
                | Self::UrlWithCredentials
                | Self::ConnectionString
                | Self::PaymentToken
                | Self::GitHubToken
                | Self::GitLabToken
                | Self::BitbucketToken
                | Self::AwsAccessKey
                | Self::AwsSessionToken
                | Self::GcpApiKey
                | Self::AzureKey
                | Self::StripeKey
                | Self::SquareToken
                | Self::ShopifyToken
                | Self::PayPalToken
                | Self::MailchimpToken
                | Self::MailgunToken
                | Self::ResendToken
                | Self::BrevoToken
                | Self::DatabricksToken
                | Self::VaultToken
                | Self::CloudflareOriginCaKey
                | Self::NpmToken
                | Self::PyPiToken
                | Self::NuGetKey
                | Self::ArtifactoryToken
                | Self::DockerHubToken
                | Self::TelegramToken
                | Self::SendGridToken
                | Self::OpenAiKey
                | Self::DiscordToken
                | Self::SlackToken
                | Self::TwilioToken
                | Self::HerokuToken
                | Self::LinearToken
                | Self::DopplerToken
                | Self::NetlifyToken
                | Self::FlyIoToken
                | Self::RenderToken
                | Self::PlanetScaleToken
                | Self::SupabaseToken
        )
    }
}

//! Core `PiiType` methods — human-readable name and compliance domain.

use super::PiiType;

impl PiiType {
    /// Returns a human-readable name for this PII type
    pub fn name(&self) -> &'static str {
        match self {
            // Personal
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Name => "name",
            Self::Birthdate => "birthdate",
            Self::Username => "username",
            Self::Age => "age",
            Self::Nationality => "nationality",
            Self::Religion => "religion",
            Self::PoliticalAffiliation => "political_affiliation",
            // Financial
            Self::CreditCard => "credit_card",
            Self::BankAccount => "bank_account",
            Self::RoutingNumber => "routing_number",
            Self::PaymentToken => "payment_token",
            Self::Iban => "iban",
            Self::CryptoAddress => "crypto_address",
            // Government
            Self::Ssn => "ssn",
            Self::DriverLicense => "driver_license",
            Self::Passport => "passport",
            Self::Vin => "vin",
            Self::Ein => "ein",
            Self::TaxId => "tax_id",
            Self::NationalId => "national_id",
            Self::KoreaRrn => "korea_rrn",
            Self::KoreaFrn => "korea_frn",
            Self::KoreaDriverLicense => "korea_driver_license",
            Self::KoreaPassport => "korea_passport",
            Self::KoreaBrn => "korea_brn",
            Self::AustraliaTfn => "australia_tfn",
            Self::AustraliaAbn => "australia_abn",
            Self::AustraliaMedicare => "australia_medicare",
            Self::AustraliaAcn => "australia_acn",
            Self::IndiaAadhaar => "india_aadhaar",
            Self::IndiaPan => "india_pan",
            Self::IndiaGstin => "india_gstin",
            Self::IndiaVehicleReg => "india_vehicle_reg",
            Self::IndiaVoterId => "india_voter_id",
            Self::IndiaPassport => "india_passport",
            Self::BrazilCpf => "brazil_cpf",
            Self::BrazilCnpj => "brazil_cnpj",
            Self::MexicoCurp => "mexico_curp",
            Self::NigeriaNin => "nigeria_nin",
            Self::NigeriaBvn => "nigeria_bvn",
            Self::NigeriaVehicleReg => "nigeria_vehicle_reg",
            Self::ThailandTnin => "thailand_tnin",
            Self::SingaporeNric => "singapore_nric",
            Self::SingaporeUen => "singapore_uen",
            Self::FinlandHetu => "finland_hetu",
            Self::PolandPesel => "poland_pesel",
            Self::ItalyFiscalCode => "italy_fiscal_code",
            Self::ItalyVat => "italy_vat",
            Self::ItalyPassport => "italy_passport",
            Self::ItalyIdentityCard => "italy_identity_card",
            Self::ItalyDriverLicense => "italy_driver_license",
            Self::SpainNif => "spain_nif",
            Self::SpainNie => "spain_nie",
            Self::UkNi => "uk_ni",
            Self::UkNhs => "uk_nhs",
            Self::UkPassport => "uk_passport",
            Self::UkDrivingLicence => "uk_driving_licence",
            // Medical
            Self::Mrn => "mrn",
            Self::Npi => "npi",
            Self::InsuranceNumber => "insurance_number",
            Self::IcdCode => "icd_code",
            Self::PrescriptionNumber => "prescription_number",
            Self::DeaNumber => "dea_number",
            // Biometric
            Self::FingerprintId => "fingerprint_id",
            Self::FaceId => "face_id",
            Self::VoiceId => "voice_id",
            Self::IrisId => "iris_id",
            Self::DnaId => "dna_id",
            Self::BiometricTemplate => "biometric_template",
            // Location
            Self::GpsCoordinates => "gps_coordinates",
            Self::Address => "address",
            Self::PostalCode => "postal_code",
            Self::NamedLocation => "named_location",
            // Organizational
            Self::EmployeeId => "employee_id",
            Self::StudentId => "student_id",
            Self::BadgeNumber => "badge_number",
            // Network
            Self::IpAddress => "ip_address",
            Self::MacAddress => "mac_address",
            Self::Uuid => "uuid",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Hostname => "hostname",
            Self::Port => "port",
            // Token
            Self::ApiKey => "api_key",
            Self::Jwt => "jwt",
            Self::SessionId => "session_id",
            Self::OAuthToken => "oauth_token",
            Self::SshKey => "ssh_key",
            Self::OnePasswordToken => "onepassword_token",
            Self::OnePasswordVaultRef => "onepassword_vault_ref",
            Self::BearerToken => "bearer_token",
            Self::UrlWithCredentials => "url_with_credentials",
            Self::ConnectionString => "connection_string",
            // Provider-specific tokens
            Self::GitHubToken => "github_token",
            Self::GitLabToken => "gitlab_token",
            Self::BitbucketToken => "bitbucket_token",
            Self::AwsAccessKey => "aws_access_key",
            Self::AwsSessionToken => "aws_session_token",
            Self::GcpApiKey => "gcp_api_key",
            Self::AzureKey => "azure_key",
            Self::StripeKey => "stripe_key",
            Self::SquareToken => "square_token",
            Self::ShopifyToken => "shopify_token",
            Self::PayPalToken => "paypal_token",
            Self::MailchimpToken => "mailchimp_token",
            Self::MailgunToken => "mailgun_token",
            Self::ResendToken => "resend_token",
            Self::BrevoToken => "brevo_token",
            Self::DatabricksToken => "databricks_token",
            Self::VaultToken => "vault_token",
            Self::CloudflareOriginCaKey => "cloudflare_origin_ca_key",
            Self::NpmToken => "npm_token",
            Self::PyPiToken => "pypi_token",
            Self::NuGetKey => "nuget_key",
            Self::ArtifactoryToken => "artifactory_token",
            Self::DockerHubToken => "docker_hub_token",
            Self::TelegramToken => "telegram_token",
            Self::SendGridToken => "sendgrid_token",
            Self::OpenAiKey => "openai_key",
            Self::DiscordToken => "discord_token",
            Self::SlackToken => "slack_token",
            Self::TwilioToken => "twilio_token",
            Self::HerokuToken => "heroku_token",
            Self::LinearToken => "linear_token",
            Self::DopplerToken => "doppler_token",
            Self::NetlifyToken => "netlify_token",
            Self::FlyIoToken => "fly_io_token",
            Self::RenderToken => "render_token",
            Self::PlanetScaleToken => "planetscale_token",
            Self::SupabaseToken => "supabase_token",
            // Credential
            Self::Password => "password",
            Self::Pin => "pin",
            Self::SecurityAnswer => "security_answer",
            Self::Passphrase => "passphrase",
            // Catch-all
            Self::Generic => "generic",
        }
    }

    /// Returns the domain this PII type belongs to
    pub fn domain(&self) -> &'static str {
        match self {
            Self::Email
            | Self::Phone
            | Self::Name
            | Self::Birthdate
            | Self::Username
            | Self::Age
            | Self::Nationality
            | Self::Religion
            | Self::PoliticalAffiliation => "personal",
            Self::CreditCard
            | Self::BankAccount
            | Self::RoutingNumber
            | Self::PaymentToken
            | Self::Iban
            | Self::CryptoAddress => "financial",
            Self::Ssn
            | Self::DriverLicense
            | Self::Passport
            | Self::Vin
            | Self::Ein
            | Self::TaxId
            | Self::NationalId
            | Self::KoreaRrn
            | Self::KoreaFrn
            | Self::KoreaDriverLicense
            | Self::KoreaPassport
            | Self::KoreaBrn
            | Self::AustraliaTfn
            | Self::AustraliaAbn
            | Self::AustraliaMedicare
            | Self::AustraliaAcn
            | Self::IndiaAadhaar
            | Self::IndiaPan
            | Self::IndiaGstin
            | Self::IndiaVehicleReg
            | Self::IndiaVoterId
            | Self::IndiaPassport
            | Self::BrazilCpf
            | Self::BrazilCnpj
            | Self::MexicoCurp
            | Self::NigeriaNin
            | Self::NigeriaBvn
            | Self::NigeriaVehicleReg
            | Self::ThailandTnin
            | Self::SingaporeNric
            | Self::SingaporeUen
            | Self::FinlandHetu
            | Self::PolandPesel
            | Self::ItalyFiscalCode
            | Self::ItalyVat
            | Self::ItalyPassport
            | Self::ItalyIdentityCard
            | Self::ItalyDriverLicense
            | Self::SpainNif
            | Self::SpainNie
            | Self::UkNi
            | Self::UkNhs
            | Self::UkPassport
            | Self::UkDrivingLicence => "government",
            Self::Mrn
            | Self::Npi
            | Self::InsuranceNumber
            | Self::IcdCode
            | Self::PrescriptionNumber
            | Self::DeaNumber => "medical",
            Self::FingerprintId
            | Self::FaceId
            | Self::VoiceId
            | Self::IrisId
            | Self::DnaId
            | Self::BiometricTemplate => "biometric",
            Self::GpsCoordinates | Self::Address | Self::PostalCode | Self::NamedLocation => {
                "location"
            }
            Self::EmployeeId | Self::StudentId | Self::BadgeNumber => "organizational",
            Self::IpAddress
            | Self::MacAddress
            | Self::Uuid
            | Self::Domain
            | Self::Url
            | Self::Hostname
            | Self::Port => "network",
            Self::ApiKey
            | Self::Jwt
            | Self::SessionId
            | Self::OAuthToken
            | Self::SshKey
            | Self::OnePasswordToken
            | Self::OnePasswordVaultRef
            | Self::BearerToken
            | Self::UrlWithCredentials
            | Self::ConnectionString
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
            | Self::SupabaseToken => "token",
            Self::Password | Self::Pin | Self::SecurityAnswer | Self::Passphrase => "credential",
            Self::Generic => "generic",
        }
    }
}

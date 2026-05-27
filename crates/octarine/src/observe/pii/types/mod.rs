//! PII type definitions
//!
//! Covers all 9 identifier domains:
//! - Personal: Email, Phone, SSN, Name, Birthdate, Username
//! - Financial: Credit Card, Bank Account, Routing Number
//! - Government: SSN, Driver License, Passport, VIN, EIN, Tax ID, National ID
//! - Medical: MRN, NPI, Insurance Number, ICD Code, Prescription
//! - Biometric: Fingerprint ID, Face ID, Voice ID, Iris ID, DNA ID
//! - Location: GPS Coordinates, Address, Postal Code
//! - Organizational: Employee ID, Student ID, Badge Number
//! - Network: IP Address, MAC Address, UUID, Domain, URL, Hostname, Port
//! - Token: API Key, JWT, Session ID, OAuth Token, SSH Key
//!
//! Split from the original 1368-LOC `types.rs`:
//!
//! - `core`: `name()` + `domain()` methods (per-variant matches)
//! - `classification`: `is_high_risk()`, `is_gdpr_protected()`,
//!   `is_pci_protected()`, `is_hipaa_protected()`, `is_secret()`
//! - `mapping`: `From<IdentifierType> for PiiType` bridge
//! - `scan_result`: `PiiScanResult` struct + impl
//! - `tests`: `#[cfg(test)]` unit tests
//!
//! The `PiiType` enum itself stays in this `mod.rs` (one source of truth);
//! per-section `impl PiiType` blocks live in the submodules.

mod classification;
mod core;
mod mapping;
mod scan_result;

pub(crate) use scan_result::PiiScanResult;

use serde::{Deserialize, Serialize};

/// Types of PII that can be detected
///
/// Organized by domain for clarity. Each variant maps to detection
/// functions in the corresponding primitives/identifiers domain module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PiiType {
    // =========================================================================
    // Personal Domain
    // =========================================================================
    /// Email address
    Email,
    /// Phone number
    Phone,
    /// Personal name
    Name,
    /// Date of birth
    Birthdate,
    /// Username or handle
    Username,
    /// Age expression (HIPAA Safe Harbor: ages > 89 require aggregation)
    Age,
    /// Nationality / ethnic group (GDPR Article 9 special category)
    Nationality,
    /// Religious belief (GDPR Article 9 special category)
    Religion,
    /// Political opinion / party (GDPR Article 9 special category)
    PoliticalAffiliation,

    // =========================================================================
    // Financial Domain
    // =========================================================================
    /// Credit card number
    CreditCard,
    /// Bank account number
    BankAccount,
    /// Bank routing number
    RoutingNumber,
    /// Payment token (Stripe, PayPal, etc.)
    PaymentToken,
    /// International Bank Account Number (ISO 13616)
    Iban,
    /// Cryptocurrency wallet address (Bitcoin, Ethereum)
    CryptoAddress,

    // =========================================================================
    // Government Domain
    // =========================================================================
    /// Social Security Number (US)
    Ssn,
    /// Driver's license number
    DriverLicense,
    /// Passport number
    Passport,
    /// Vehicle Identification Number
    Vin,
    /// Employer Identification Number
    Ein,
    /// Tax ID (generic)
    TaxId,
    /// National ID number (non-US government identifiers)
    NationalId,
    /// South Korea Resident Registration Number (RRN, citizens — gender digit 1-4)
    KoreaRrn,
    /// South Korea Foreign Registration Number (FRN, foreigners — gender digit 5-8)
    KoreaFrn,
    /// South Korea Driver License (NN-NN-NNNNNN-NN, regions 11-28)
    KoreaDriverLicense,
    /// South Korea Passport (MRS prefix + optional letter + 7-8 digits)
    KoreaPassport,
    /// South Korea Business Registration Number (BRN, NNN-NN-NNNNN, weighted mod-10)
    KoreaBrn,
    /// Australian Tax File Number (TFN)
    AustraliaTfn,
    /// Australian Business Number (ABN)
    AustraliaAbn,
    /// Australian Medicare number (10 digits, weighted mod-10 check digit)
    AustraliaMedicare,
    /// Australian Company Number (ACN, 9 digits, weighted mod-10 check digit)
    AustraliaAcn,
    /// Indian Aadhaar number (Verhoeff checksum)
    IndiaAadhaar,
    /// Indian Permanent Account Number (PAN)
    IndiaPan,
    /// Indian Goods and Services Tax Identification Number (GSTIN, MOD-36 checksum)
    IndiaGstin,
    /// Indian vehicle registration (license plate)
    IndiaVehicleReg,
    /// Indian Voter ID (EPIC - Electors Photo Identity Card)
    IndiaVoterId,
    /// Indian passport (P/S/D type indicator + 7 digits)
    IndiaPassport,
    /// Brazilian Cadastro de Pessoas Físicas (CPF, mod-11 dual check digits)
    BrazilCpf,
    /// Brazilian Cadastro Nacional da Pessoa Jurídica (CNPJ, mod-11 dual check digits)
    BrazilCnpj,
    /// Mexican Clave Única de Registro de Población (CURP)
    MexicoCurp,
    /// Nigerian National Identification Number (NIN)
    NigeriaNin,
    /// Nigerian Bank Verification Number (BVN, 11 digits)
    NigeriaBvn,
    /// Nigerian vehicle registration plate (XXX-NNN-XX current, AA999-AAA legacy)
    NigeriaVehicleReg,
    /// Thai National Identification Number (TNIN, mod-11 check digit)
    ThailandTnin,
    /// Singapore NRIC / FIN
    SingaporeNric,
    /// Singapore Unique Entity Number (UEN, 3 layout variants, opaque check letter)
    SingaporeUen,
    /// Finnish personal identity code (HETU)
    FinlandHetu,
    /// Polish personal identity number (PESEL)
    PolandPesel,
    /// Italian Codice Fiscale
    ItalyFiscalCode,
    /// Spanish NIF (Numero de Identificacion Fiscal)
    SpainNif,
    /// Spanish NIE (Numero de Identidad de Extranjero)
    SpainNie,
    /// UK National Insurance Number (NINO)
    UkNi,

    // =========================================================================
    // Medical Domain (PHI - Protected Health Information)
    // =========================================================================
    /// Medical Record Number
    Mrn,
    /// National Provider Identifier
    Npi,
    /// Health insurance number
    InsuranceNumber,
    /// ICD diagnostic code
    IcdCode,
    /// Prescription number
    PrescriptionNumber,
    /// DEA (Drug Enforcement Administration) number
    DeaNumber,

    // =========================================================================
    // Biometric Domain
    // =========================================================================
    /// Fingerprint template ID
    FingerprintId,
    /// Facial recognition ID
    FaceId,
    /// Voice print ID
    VoiceId,
    /// Iris scan ID
    IrisId,
    /// DNA profile ID
    DnaId,
    /// Biometric template (ISO/IEC 19794 FMR/FIR/FTR/IIR formats)
    BiometricTemplate,

    // =========================================================================
    // Location Domain
    // =========================================================================
    /// GPS coordinates
    GpsCoordinates,
    /// Street address
    Address,
    /// Postal/ZIP code
    PostalCode,

    // =========================================================================
    // Organizational Domain
    // =========================================================================
    /// Employee ID
    EmployeeId,
    /// Student ID
    StudentId,
    /// Badge/access card number
    BadgeNumber,

    // =========================================================================
    // Network Domain
    // =========================================================================
    /// IP address (v4 or v6)
    IpAddress,
    /// MAC address
    MacAddress,
    /// UUID/GUID
    Uuid,
    /// Domain name
    Domain,
    /// URL
    Url,
    /// Hostname (bare hostname without scheme)
    Hostname,
    /// Network port number
    Port,

    // =========================================================================
    // Token Domain (Secrets)
    // =========================================================================
    /// API key or token
    ApiKey,
    /// JSON Web Token
    Jwt,
    /// Session ID/token
    SessionId,
    /// OAuth token
    OAuthToken,
    /// SSH key (public or private)
    SshKey,
    /// 1Password service account token
    OnePasswordToken,
    /// 1Password vault reference (op://vault/item/field)
    OnePasswordVaultRef,
    /// Bearer token (Authorization header)
    BearerToken,
    /// URL with embedded credentials
    UrlWithCredentials,
    /// Connection string with embedded credentials (MSSQL, JDBC, database URLs)
    ConnectionString,

    // -------------------------------------------------------------------------
    // Provider-specific tokens
    // -------------------------------------------------------------------------
    /// GitHub Personal Access Token (ghp_, gho_, ghu_, ghs_, ghr_)
    GitHubToken,
    /// GitLab Personal Access Token (glpat-) or Deploy Token
    GitLabToken,
    /// Bitbucket Cloud App Password (ATBB...)
    BitbucketToken,
    /// AWS Access Key ID (AKIA* long-term, ASIA* temporary STS)
    AwsAccessKey,
    /// AWS Session Token (long base64 string from STS)
    AwsSessionToken,
    /// Google Cloud Platform API Key (AIza*)
    GcpApiKey,
    /// Azure Storage Account Key
    AzureKey,
    /// Stripe API Key (sk_live_, sk_test_, pk_live_, pk_test_, rk_*)
    StripeKey,
    /// Square API key (sq0atp-*, sq0csp-*, sq0idp-*)
    SquareToken,
    /// Shopify API token (shpat_*, shpca_*, shppa_*, shpss_*)
    ShopifyToken,
    /// PayPal/Braintree access token
    PayPalToken,
    /// Mailchimp API key
    MailchimpToken,
    /// Mailgun API key
    MailgunToken,
    /// Resend API key
    ResendToken,
    /// Brevo/Sendinblue API key
    BrevoToken,
    /// Databricks access token
    DatabricksToken,
    /// HashiCorp Vault token (hvs., s., b.)
    VaultToken,
    /// Cloudflare Origin CA key
    CloudflareOriginCaKey,
    /// NPM access token
    NpmToken,
    /// PyPI API token
    PyPiToken,
    /// NuGet API key
    NuGetKey,
    /// JFrog Artifactory API key
    ArtifactoryToken,
    /// Docker Hub Personal Access Token
    DockerHubToken,
    /// Telegram bot token
    TelegramToken,
    /// SendGrid API key
    SendGridToken,
    /// OpenAI API key (sk-*, sk-proj-*, org-*)
    OpenAiKey,
    /// Discord bot token or webhook URL
    DiscordToken,
    /// Slack token (bot/user/app/config/legacy) or webhook URL
    SlackToken,
    /// Twilio Account SID (AC...) or API Key SID (SK...)
    TwilioToken,
    /// Heroku modern API token (HRKU-AA prefix)
    HerokuToken,
    /// Linear API key (lin_api_ prefix)
    LinearToken,
    /// Doppler service/CLI/SCM/service-account token
    DopplerToken,
    /// Netlify Personal Access Token (nfp_ prefix)
    NetlifyToken,
    /// Fly.io macaroon-based token (FlyV1 prefix)
    FlyIoToken,
    /// Render API key (rnd_ prefix)
    RenderToken,
    /// PlanetScale service token (pscale_tkn_ prefix)
    PlanetScaleToken,
    /// Supabase Personal Access Token (sbp_ prefix)
    SupabaseToken,

    // =========================================================================
    // Credential Domain (NIST 800-63 Factor 1: Something You Know)
    // =========================================================================
    /// Password (context-based detection via labels like "password=")
    Password,
    /// PIN code (context-based detection via labels like "pin=")
    Pin,
    /// Security question answer
    SecurityAnswer,
    /// Passphrase (multi-word secret)
    Passphrase,

    // =========================================================================
    // Catch-all
    // =========================================================================
    /// Generic/unknown PII
    Generic,
}

#[cfg(test)]
mod tests;

//! Token type definitions
//!
//! Defines enums for API key providers, JWT algorithms, and token types.

// ============================================================================
// API Key Provider Enum
// ============================================================================

/// API key provider enumeration
///
/// Represents the detected API key provider based on prefix patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyProvider {
    /// Stripe API keys (sk_live_, sk_test_, pk_live_, pk_test_, rk_live_, rk_test_)
    Stripe,
    /// AWS access keys (AKIA...)
    Aws,
    /// GitHub personal access tokens (ghp_, gho_, ghu_, ghs_, ghr_)
    Github,
    /// Google Cloud Platform API keys (AIza...)
    Gcp,
    /// Azure connection strings and keys
    Azure,
    /// 1Password tokens (ops_ service tokens, op:// vault references)
    OnePassword,
    /// Square API keys (sq0atp-, sq0csp-, sq0idp-)
    Square,
    /// PayPal/Braintree tokens (access_token$production$..., access_token$sandbox$...)
    PayPal,
    /// Shopify API tokens (shpat_, shpca_, shppa_, shpss_)
    Shopify,
    /// Mailchimp API keys ([hex]{32}-us[N])
    Mailchimp,
    /// Mailgun API keys (key-[alnum]{32})
    Mailgun,
    /// Resend API keys (re_[alnum]{32+})
    Resend,
    /// Brevo/Sendinblue API keys (xkeysib-[hex]{64}-[alnum]{16})
    Brevo,
    /// Databricks access tokens (dapi[hex]{32})
    Databricks,
    /// HashiCorp Vault tokens (hvs., s., b.)
    HashicorpVault,
    /// Cloudflare tokens (v1.0-... origin CA key)
    Cloudflare,
    /// NPM access tokens (npm_[alnum]{36})
    Npm,
    /// PyPI API tokens (pypi-AgEIcHlwaS5vcmc[base64]{50+})
    PyPi,
    /// NuGet API keys (oy2[a-z0-9]{43})
    NuGet,
    /// JFrog Artifactory API keys (AKC[alnum]{10+})
    Artifactory,
    /// Docker Hub Personal Access Tokens (dckr_pat_[alnum]{27+})
    DockerHub,
    /// Telegram bot tokens ([0-9]{8,10}:[a-zA-Z0-9_-]{35})
    Telegram,
    /// Generic or unknown provider
    Generic,
}

impl std::fmt::Display for ApiKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stripe => write!(f, "Stripe"),
            Self::Aws => write!(f, "AWS"),
            Self::Github => write!(f, "GitHub"),
            Self::Gcp => write!(f, "Google Cloud Platform"),
            Self::Azure => write!(f, "Azure"),
            Self::OnePassword => write!(f, "1Password"),
            Self::Square => write!(f, "Square"),
            Self::PayPal => write!(f, "PayPal"),
            Self::Shopify => write!(f, "Shopify"),
            Self::Mailchimp => write!(f, "Mailchimp"),
            Self::Mailgun => write!(f, "Mailgun"),
            Self::Resend => write!(f, "Resend"),
            Self::Brevo => write!(f, "Brevo"),
            Self::Databricks => write!(f, "Databricks"),
            Self::HashicorpVault => write!(f, "HashiCorp Vault"),
            Self::Cloudflare => write!(f, "Cloudflare"),
            Self::Npm => write!(f, "NPM"),
            Self::PyPi => write!(f, "PyPI"),
            Self::NuGet => write!(f, "NuGet"),
            Self::Artifactory => write!(f, "Artifactory"),
            Self::DockerHub => write!(f, "Docker Hub"),
            Self::Telegram => write!(f, "Telegram"),
            Self::Generic => write!(f, "Generic"),
        }
    }
}

// ============================================================================
// JWT Algorithm Enum
// ============================================================================

/// JWT signing algorithm enumeration
///
/// Represents the cryptographic algorithm used to sign a JWT token.
/// Based on RFC 7518 (JSON Web Algorithms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtAlgorithm {
    // Symmetric (HMAC) algorithms
    /// HMAC with SHA-256
    Hs256,
    /// HMAC with SHA-384
    Hs384,
    /// HMAC with SHA-512
    Hs512,

    // Asymmetric (RSA) algorithms
    /// RSASSA-PKCS1-v1_5 with SHA-256
    Rs256,
    /// RSASSA-PKCS1-v1_5 with SHA-384
    Rs384,
    /// RSASSA-PKCS1-v1_5 with SHA-512
    Rs512,

    // Asymmetric (ECDSA) algorithms
    /// ECDSA with P-256 curve and SHA-256
    Es256,
    /// ECDSA with P-384 curve and SHA-384
    Es384,
    /// ECDSA with P-521 curve and SHA-512
    Es512,

    // Asymmetric (RSASSA-PSS) algorithms
    /// RSASSA-PSS with SHA-256
    Ps256,
    /// RSASSA-PSS with SHA-384
    Ps384,
    /// RSASSA-PSS with SHA-512
    Ps512,

    // EdDSA algorithm
    /// Edwards-curve Digital Signature Algorithm
    EdDsa,

    // None (insecure - no signature)
    /// No signature (INSECURE - should never be used)
    None,
}

impl std::fmt::Display for JwtAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hs256 => write!(f, "HS256 (HMAC-SHA256)"),
            Self::Hs384 => write!(f, "HS384 (HMAC-SHA384)"),
            Self::Hs512 => write!(f, "HS512 (HMAC-SHA512)"),
            Self::Rs256 => write!(f, "RS256 (RSA-SHA256)"),
            Self::Rs384 => write!(f, "RS384 (RSA-SHA384)"),
            Self::Rs512 => write!(f, "RS512 (RSA-SHA512)"),
            Self::Es256 => write!(f, "ES256 (ECDSA-SHA256)"),
            Self::Es384 => write!(f, "ES384 (ECDSA-SHA384)"),
            Self::Es512 => write!(f, "ES512 (ECDSA-SHA512)"),
            Self::Ps256 => write!(f, "PS256 (RSA-PSS-SHA256)"),
            Self::Ps384 => write!(f, "PS384 (RSA-PSS-SHA384)"),
            Self::Ps512 => write!(f, "PS512 (RSA-PSS-SHA512)"),
            Self::EdDsa => write!(f, "EdDSA (Edwards-curve)"),
            Self::None => write!(f, "none (INSECURE)"),
        }
    }
}

impl JwtAlgorithm {
    /// Check if this is a symmetric (HMAC) algorithm
    #[must_use]
    pub const fn is_symmetric(&self) -> bool {
        matches!(self, Self::Hs256 | Self::Hs384 | Self::Hs512)
    }

    /// Check if this is an asymmetric algorithm
    #[must_use]
    pub const fn is_asymmetric(&self) -> bool {
        matches!(
            self,
            Self::Rs256
                | Self::Rs384
                | Self::Rs512
                | Self::Es256
                | Self::Es384
                | Self::Es512
                | Self::Ps256
                | Self::Ps384
                | Self::Ps512
                | Self::EdDsa
        )
    }

    /// Check if this algorithm is secure (not "none")
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        !matches!(self, Self::None)
    }
}

// ============================================================================
// Token Type Enum
// ============================================================================

/// Token type classification
///
/// Identifies the specific type of authentication or authorization token detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenType {
    /// JSON Web Token (JWT)
    Jwt,
    /// GitHub Personal Access Token (ghp_, gho_, ghs_, ghr_)
    GitHub,
    /// GitLab Personal Access Token (glpat-) or Deploy Token (gldt-)
    GitLab,
    /// AWS Access Key ID (AKIA* long-term, ASIA* temporary STS)
    AwsAccessKey,
    /// AWS Secret Access Key (40 base64 characters)
    AwsSecretKey,
    /// AWS Session Token (long Base64 string from STS)
    AwsSessionToken,
    /// Google Cloud Platform API Key (AIza*)
    GcpApiKey,
    /// Azure Storage Account Key
    AzureKey,
    /// Stripe API Key (sk_*, pk_*)
    StripeKey,
    /// 1Password Service Account Token (ops_*)
    OnePasswordServiceToken,
    /// 1Password Vault Reference (op://vault/item/field)
    OnePasswordVaultRef,
    /// Bearer Token (Authorization: Bearer *)
    BearerToken,
    /// SSH Private Key (-----BEGIN * PRIVATE KEY-----)
    SshPrivateKey,
    /// Generic API Key (api_key*, token*, etc.)
    GenericApiKey,
    /// SSH Public Key (ssh-rsa, ssh-ed25519, etc.)
    SshPublicKey,
    /// SSH Fingerprint (MD5 or SHA256 format)
    SshFingerprint,
    /// High-entropy session identifier (heuristic)
    SessionId,
    /// URL with embedded credentials (https://user:pass@host)
    UrlWithCredentials,
    /// Square API key (sq0atp-*, sq0csp-*, sq0idp-*)
    SquareToken,
    /// PayPal/Braintree access token (access_token$production$*$*)
    PayPalToken,
    /// Shopify API token (shpat_*, shpca_*, shppa_*, shpss_*)
    ShopifyToken,
    /// Mailchimp API key ([hex]{32}-us[N])
    MailchimpToken,
    /// Mailgun API key (key-[alnum]{32})
    MailgunToken,
    /// Resend API key (re_[alnum]{32+})
    ResendToken,
    /// Brevo/Sendinblue API key (xkeysib-[hex]{64}-[alnum]{16})
    BrevoToken,
    /// Databricks access token (dapi[hex]{32})
    DatabricksToken,
    /// HashiCorp Vault token (hvs., s., b.)
    VaultToken,
    /// Cloudflare Origin CA key (v1.0-[hex]{24}-[hex]{146})
    CloudflareOriginCaKey,
    /// NPM access token (npm_[alnum]{36})
    NpmToken,
    /// PyPI API token (pypi-AgEIcHlwaS5vcmc...)
    PyPiToken,
    /// NuGet API key (oy2[a-z0-9]{43})
    NuGetKey,
    /// JFrog Artifactory API key (AKC[alnum]{10+})
    ArtifactoryToken,
    /// Docker Hub PAT (dckr_pat_[alnum]{27+})
    DockerHubToken,
    /// Telegram bot token ([0-9]{8,10}:[a-zA-Z0-9_-]{35})
    TelegramToken,
}

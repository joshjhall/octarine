//! API key detection
//!
//! Pure detection functions for various API key formats (AWS, Azure, GCP, GitHub, Stripe, etc.)

use super::super::super::common::patterns;

use super::types::ApiKeyProvider;

/// Maximum identifier length for single-value checks
const MAX_IDENTIFIER_LENGTH: usize = 1_000;

/// Azure keys can be longer
const MAX_AZURE_KEY_LENGTH: usize = 10_000;

// ============================================================================
// Public API
// ============================================================================

/// Detect API key provider from the key string
///
/// Analyzes the API key prefix and format to determine the likely provider.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::detection::{detect_api_key_provider, ApiKeyProvider};
///
/// assert_eq!(detect_api_key_provider("sk_live_123456"), Some(ApiKeyProvider::Stripe));
/// assert_eq!(detect_api_key_provider(&format!("AKIA{}", "IOSFODNN7EXAMPLE")), Some(ApiKeyProvider::Aws));
/// assert_eq!(detect_api_key_provider("ghp_xxxxxxxxxxxx"), Some(ApiKeyProvider::Github));
/// ```
pub fn detect_api_key_provider(key: &str) -> Option<ApiKeyProvider> {
    let key_lower = key.to_lowercase();

    // Stripe keys (sk_, pk_, rk_ with live/test suffix)
    if key_lower.starts_with("sk_") || key_lower.starts_with("pk_") || key_lower.starts_with("rk_")
    {
        return Some(ApiKeyProvider::Stripe);
    }

    // AWS keys (starts with AKIA for long-term or ASIA for temporary STS credentials)
    if (key.starts_with("AKIA") || key.starts_with("ASIA")) && key.len() >= 20 {
        return Some(ApiKeyProvider::Aws);
    }

    // GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_, github_pat_)
    if key_lower.starts_with("ghp_")
        || key_lower.starts_with("gho_")
        || key_lower.starts_with("ghu_")
        || key_lower.starts_with("ghs_")
        || key_lower.starts_with("ghr_")
        || key_lower.starts_with("github_pat_")
    {
        return Some(ApiKeyProvider::Github);
    }

    // Google Cloud Platform (AIza...)
    if key.starts_with("AIza") {
        return Some(ApiKeyProvider::Gcp);
    }

    // Azure (various patterns, less definitive)
    if key_lower.contains("accountkey") || key_lower.contains("sharedaccesskey") {
        return Some(ApiKeyProvider::Azure);
    }

    // 1Password service account tokens
    if key_lower.starts_with("ops_") {
        return Some(ApiKeyProvider::OnePassword);
    }

    // Square API keys (sq0atp-, sq0csp-, sq0idp-)
    if key_lower.starts_with("sq0atp-")
        || key_lower.starts_with("sq0csp-")
        || key_lower.starts_with("sq0idp-")
    {
        return Some(ApiKeyProvider::Square);
    }

    // Shopify API tokens (shpat_, shpca_, shppa_, shpss_)
    if key_lower.starts_with("shpat_")
        || key_lower.starts_with("shpca_")
        || key_lower.starts_with("shppa_")
        || key_lower.starts_with("shpss_")
    {
        return Some(ApiKeyProvider::Shopify);
    }

    // PayPal/Braintree access tokens (access_token$production$..., access_token$sandbox$...)
    if key_lower.starts_with("access_token$production$")
        || key_lower.starts_with("access_token$sandbox$")
    {
        return Some(ApiKeyProvider::PayPal);
    }

    // Mailgun API keys (key-[alnum]{32})
    if key_lower.starts_with("key-") && key.len() >= 36 {
        return Some(ApiKeyProvider::Mailgun);
    }

    // Resend API keys (re_[alnum]{32+})
    if key_lower.starts_with("re_") && key.len() >= 35 {
        return Some(ApiKeyProvider::Resend);
    }

    // Brevo/Sendinblue API keys (xkeysib-[hex]{64}-[alnum]{16})
    if key_lower.starts_with("xkeysib-") {
        return Some(ApiKeyProvider::Brevo);
    }

    // Mailchimp API keys ([hex]{32}-us[N]) - uses regex since no literal prefix
    if patterns::network::API_KEY_MAILCHIMP.is_match(key) {
        return Some(ApiKeyProvider::Mailchimp);
    }

    // Databricks access tokens (dapi[hex]{32})
    if key_lower.starts_with("dapi") && key.len() >= 36 {
        return Some(ApiKeyProvider::Databricks);
    }

    // HashiCorp Vault tokens (hvs., s., b.)
    if key.starts_with("hvs.")
        || (key.starts_with("b.") && key.len() >= 26)
        || (key.starts_with("s.") && key.len() == 26)
    {
        return Some(ApiKeyProvider::HashicorpVault);
    }

    // Cloudflare Origin CA key (v1.0-[hex]{24}-[hex]{146})
    if key.starts_with("v1.0-") && key.len() >= 175 {
        return Some(ApiKeyProvider::Cloudflare);
    }

    // NPM access tokens (npm_[alnum]{36})
    if key_lower.starts_with("npm_") && key.len() >= 40 {
        return Some(ApiKeyProvider::Npm);
    }

    // PyPI API tokens (pypi-AgEIcHlwaS5vcmc...)
    if key.starts_with("pypi-") {
        return Some(ApiKeyProvider::PyPi);
    }

    // NuGet API keys (oy2[a-z0-9]{43})
    if key_lower.starts_with("oy2") && key.len() == 46 {
        return Some(ApiKeyProvider::NuGet);
    }

    // Artifactory API keys (AKC[alnum]{10+})
    if key.starts_with("AKC") && key.len() >= 13 {
        return Some(ApiKeyProvider::Artifactory);
    }

    // Docker Hub PATs (dckr_pat_[alnum]{27+})
    if key_lower.starts_with("dckr_pat_") {
        return Some(ApiKeyProvider::DockerHub);
    }

    // Telegram bot tokens ([0-9]{8,10}:[a-zA-Z0-9_-]{35})
    if patterns::network::API_KEY_TELEGRAM.is_match(key) {
        return Some(ApiKeyProvider::Telegram);
    }

    // Generic/unknown provider
    Some(ApiKeyProvider::Generic)
}

/// Check if value is an API key
///
/// Matches generic API keys and provider-specific formats (AWS, Azure, GCP, GitHub, Stripe)
#[must_use]
pub fn is_api_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_GENERIC.is_match(trimmed)
        || patterns::network::API_KEY_STRIPE.is_match(trimmed)
        || patterns::network::API_KEY_AWS_ACCESS.is_match(trimmed)
        || patterns::network::API_KEY_AWS_SECRET.is_match(trimmed)
        || patterns::network::API_KEY_AWS_SESSION.is_match(trimmed)
        || patterns::network::API_KEY_GCP.is_match(trimmed)
        || patterns::network::API_KEY_GITHUB.is_match(trimmed)
        || patterns::network::API_KEY_SQUARE.is_match(trimmed)
        || patterns::network::API_KEY_SHOPIFY.is_match(trimmed)
        || patterns::network::API_KEY_PAYPAL_BRAINTREE.is_match(trimmed)
        || patterns::network::API_KEY_MAILCHIMP.is_match(trimmed)
        || patterns::network::API_KEY_MAILGUN.is_match(trimmed)
        || patterns::network::API_KEY_RESEND.is_match(trimmed)
        || patterns::network::API_KEY_BREVO.is_match(trimmed)
        || patterns::network::API_KEY_DATABRICKS.is_match(trimmed)
        || patterns::network::API_KEY_VAULT.is_match(trimmed)
        || patterns::network::API_KEY_CLOUDFLARE_CA.is_match(trimmed)
        || patterns::network::API_KEY_NPM.is_match(trimmed)
        || patterns::network::API_KEY_PYPI.is_match(trimmed)
        || patterns::network::API_KEY_NUGET.is_match(trimmed)
        || patterns::network::API_KEY_ARTIFACTORY.is_match(trimmed)
        || patterns::network::API_KEY_DOCKER_HUB.is_match(trimmed)
        || (trimmed.len() <= MAX_AZURE_KEY_LENGTH
            && patterns::network::API_KEY_AZURE.is_match(trimmed))
}

/// Check if value is an AWS Access Key ID
///
/// AWS Access Key IDs start with "AKIA" (long-term) or "ASIA" (temporary STS)
/// followed by 16 alphanumeric characters
#[must_use]
pub fn is_aws_access_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_AWS_ACCESS.is_match(trimmed)
}

/// Check if value is an AWS Secret Access Key
///
/// AWS Secret Access Keys are 40 base64 characters
#[must_use]
pub fn is_aws_secret_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_AWS_SECRET.is_match(trimmed)
}

/// Check if value is an AWS Session Token
///
/// AWS session tokens are long Base64 strings (100+ characters) that accompany
/// temporary STS credentials (ASIA prefix access keys)
#[must_use]
pub fn is_aws_session_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_AWS_SESSION.is_match(trimmed)
}

/// Check if value is a Google Cloud Platform API key
///
/// GCP API keys start with "AIza" followed by 35 alphanumeric characters
#[must_use]
pub fn is_gcp_api_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_GCP.is_match(trimmed)
}

/// Check if value is a GitHub Personal Access Token
///
/// Matches classic tokens (ghp_, gho_, ghu_, ghs_, ghr_ + 36 chars) and
/// fine-grained PATs (github_pat_ + 22 chars + _ + 59 chars)
#[must_use]
pub fn is_github_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_GITHUB.is_match(trimmed)
}

/// Check if value is an Azure Storage Account Key
///
/// Azure keys are typically 88 base64 characters in AccountKey=... format
#[must_use]
pub fn is_azure_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_AZURE_KEY_LENGTH {
        return false;
    }
    patterns::network::API_KEY_AZURE.is_match(trimmed)
}

/// Check if value is a Stripe API key
///
/// Stripe keys start with "sk_" or "pk_" followed by "live" or "test"
#[must_use]
pub fn is_stripe_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_STRIPE.is_match(trimmed)
}

/// Check if value is a GitLab Personal Access Token
///
/// GitLab tokens start with "glpat-" (personal access token) or "gldt-" (deploy token)
#[must_use]
pub fn is_gitlab_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_GITLAB.is_match(trimmed)
}

/// Check if value is a 1Password Service Account Token
///
/// 1Password service account tokens start with "ops_" followed by base64-like characters
#[must_use]
pub fn is_onepassword_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_1PASSWORD.is_match(trimmed)
}

/// Check if value is a 1Password Vault Reference
///
/// 1Password vault references have format: op://vault/item/field or op://vault/item
#[must_use]
pub fn is_onepassword_vault_ref(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::ONEPASSWORD_VAULT_REF.is_match(trimmed)
}

/// Check if value is a Bearer token
///
/// Bearer tokens appear in Authorization headers: "Bearer <token>"
#[must_use]
pub fn is_bearer_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::BEARER_TOKEN.is_match(trimmed)
}

/// Check if value is a URL with embedded credentials
///
/// Matches URLs like: https://user:password@host.com/path
#[must_use]
pub fn is_url_with_credentials(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::URL_WITH_CREDENTIALS.is_match(trimmed)
}

/// Check if value is a Square API key
///
/// Square keys start with "sq0atp-" (OAuth access), "sq0csp-" (OAuth secret),
/// or "sq0idp-" (Application ID)
#[must_use]
pub fn is_square_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_SQUARE.is_match(trimmed)
}

/// Check if value is a Shopify API token
///
/// Shopify tokens start with "shpat_" (app access), "shpca_" (custom app),
/// "shppa_" (private app), or "shpss_" (shared secret), followed by 32 hex chars
#[must_use]
pub fn is_shopify_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_SHOPIFY.is_match(trimmed)
}

/// Check if value is a PayPal/Braintree access token
///
/// Braintree access tokens have the format:
/// `access_token$production$[a-z0-9]{16}$[a-f0-9]{32}` (or sandbox)
#[must_use]
pub fn is_paypal_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_PAYPAL_BRAINTREE.is_match(trimmed)
}

/// Check if value is a Mailchimp API key
///
/// Mailchimp keys are 32 hex characters followed by a datacenter suffix (-us1 to -us20)
#[must_use]
pub fn is_mailchimp_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_MAILCHIMP.is_match(trimmed)
}

/// Check if value is a Mailgun API key
///
/// Mailgun keys start with "key-" followed by 32 alphanumeric characters
#[must_use]
pub fn is_mailgun_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_MAILGUN.is_match(trimmed)
}

/// Check if value is a Resend API key
///
/// Resend keys start with "re_" followed by 32+ alphanumeric characters
#[must_use]
pub fn is_resend_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_RESEND.is_match(trimmed)
}

/// Check if value is a Brevo (Sendinblue) API key
///
/// Brevo keys start with "xkeysib-" followed by 64 hex characters, a dash,
/// and 16 alphanumeric characters
#[must_use]
pub fn is_brevo_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_BREVO.is_match(trimmed)
}

/// Check if value is a Databricks access token
///
/// Databricks tokens start with "dapi" followed by 32 hex characters,
/// with an optional "-N" suffix
#[must_use]
pub fn is_databricks_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_DATABRICKS.is_match(trimmed)
}

/// Check if value is a HashiCorp Vault token
///
/// Matches modern tokens (hvs.), batch tokens (b.), and legacy service tokens (s.)
#[must_use]
pub fn is_vault_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_VAULT.is_match(trimmed)
}

/// Check if value is a Cloudflare Origin CA key
///
/// Origin CA keys start with "v1.0-" followed by 24 hex characters,
/// a dash, and 146 hex characters (175+ chars total)
#[must_use]
pub fn is_cloudflare_ca_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_CLOUDFLARE_CA.is_match(trimmed)
}

/// Check if value is an NPM access token
///
/// NPM tokens start with "npm_" followed by 36 alphanumeric characters
#[must_use]
pub fn is_npm_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_NPM.is_match(trimmed)
}

/// Check if value is a PyPI API token
///
/// PyPI tokens start with "pypi-AgEIcHlwaS5vcmc" followed by 50+ base64 characters
#[must_use]
pub fn is_pypi_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_PYPI.is_match(trimmed)
}

/// Check if value is a NuGet API key
///
/// NuGet keys start with "oy2" followed by exactly 43 lowercase alphanumeric characters
#[must_use]
pub fn is_nuget_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_NUGET.is_match(trimmed)
}

/// Check if value is a JFrog Artifactory API key
///
/// Artifactory keys start with "AKC" followed by 10+ alphanumeric characters
#[must_use]
pub fn is_artifactory_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_ARTIFACTORY.is_match(trimmed)
}

/// Check if value is a Docker Hub Personal Access Token
///
/// Docker Hub PATs start with "dckr_pat_" followed by 27+ alphanumeric characters
#[must_use]
pub fn is_docker_hub_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_DOCKER_HUB.is_match(trimmed)
}

/// Check if value is a Telegram bot token
///
/// Telegram bot tokens have the format `{numeric_id}:{secret}` where
/// the numeric ID is 8-10 digits and the secret is 35 alphanumeric/dash/underscore characters.
#[must_use]
pub fn is_telegram_bot_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_TELEGRAM.is_match(trimmed)
}

/// Check if API key is a known test/development key
///
/// Detects:
/// - Keys with "test" in the environment (sk_test_, pk_test_)
/// - Keys with common test patterns (EXAMPLE, FAKE, TEST, DEMO)
/// - Documented example keys from provider documentation
/// - Sequential or repeating character patterns
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::detection::is_test_api_key;
///
/// assert!(is_test_api_key("sk_test_1234567890"));        // Stripe test key
/// assert!(is_test_api_key(&format!("AKIA{}", "IOSFODNN7EXAMPLE"))); // AWS example
/// assert!(is_test_api_key("ghp_TESTtesttesttest123456")); // Test GitHub token
/// assert!(!is_test_api_key("sk_live_realproductionkey")); // Production key
/// ```
#[must_use]
pub fn is_test_api_key(key: &str) -> bool {
    let trimmed = key.trim();
    let upper = trimmed.to_uppercase();

    // Stripe test keys (sk_test_, pk_test_, rk_test_)
    if trimmed.starts_with("sk_test_")
        || trimmed.starts_with("pk_test_")
        || trimmed.starts_with("rk_test_")
    {
        return true;
    }

    // AWS example keys from documentation (both AKIA and ASIA)
    // Constructed at runtime to avoid triggering secret scanners on known dummy keys
    let aws_examples: [String; 4] = [
        format!("AKIA{}", "IOSFODNN7EXAMPLE"),
        format!("AKIA{}", "I44QH8DHBEXAMPLE"),
        format!("ASIA{}", "IOSFODNN7EXAMPLE"),
        format!("wJalrXUtnFEMI/K7MDENG/{}", "bPxRfiCYEXAMPLEKEY"),
    ];
    for example in &aws_examples {
        if trimmed == *example {
            return true;
        }
    }

    // Contains common test keywords
    let test_keywords = ["EXAMPLE", "FAKE", "TEST", "DEMO", "SAMPLE", "DUMMY", "MOCK"];
    for keyword in &test_keywords {
        if upper.contains(keyword) {
            return true;
        }
    }

    // Sequential or repeating patterns
    if upper.contains("1234567890")
        || upper.contains("ABCDEFGH")
        || upper.contains("XXXXXXXX")
        || upper.contains("00000000")
    {
        return true;
    }

    // Square sandbox keys
    if trimmed.starts_with("sandbox-sq0") {
        return true;
    }

    // PayPal/Braintree sandbox tokens
    if trimmed.starts_with("access_token$sandbox$") {
        return true;
    }

    // Check for all same character (after prefix)
    let prefix_len =
        if trimmed.starts_with("sk_") || trimmed.starts_with("pk_") || trimmed.starts_with("rk_") {
            8 // sk_live_, pk_live_, etc.
        } else if trimmed.starts_with("ghp_")
            || trimmed.starts_with("gho_")
            || trimmed.starts_with("ghs_")
            || trimmed.starts_with("ghr_")
        {
            4
        } else if trimmed.starts_with("glpat-") || trimmed.starts_with("gldt-") {
            6
        } else if trimmed.starts_with("sq0atp-")
            || trimmed.starts_with("sq0csp-")
            || trimmed.starts_with("sq0idp-")
        {
            7
        } else if trimmed.starts_with("shpat_")
            || trimmed.starts_with("shpca_")
            || trimmed.starts_with("shppa_")
            || trimmed.starts_with("shpss_")
        {
            6
        } else if trimmed.starts_with("key-") {
            4 // Mailgun
        } else if trimmed.starts_with("re_") {
            3 // Resend
        } else if trimmed.starts_with("xkeysib-") {
            8 // Brevo
        } else if trimmed.starts_with("dapi") || trimmed.starts_with("hvs.") {
            4 // Databricks or Vault modern
        } else if trimmed.starts_with("s.") || trimmed.starts_with("b.") {
            2 // Vault legacy/batch
        } else if trimmed.starts_with("v1.0-") {
            5 // Cloudflare CA
        } else if trimmed.starts_with("npm_") {
            4 // NPM
        } else if trimmed.starts_with("pypi-") {
            5 // PyPI
        } else if trimmed.starts_with("oy2") || trimmed.starts_with("AKC") {
            3 // NuGet or Artifactory
        } else if trimmed.starts_with("dckr_pat_") {
            9 // Docker Hub
        } else {
            0
        };

    if prefix_len > 0 && prefix_len < trimmed.len() {
        let suffix = trimmed.get(prefix_len..).unwrap_or("");
        if !suffix.is_empty() {
            let first_char = suffix.chars().next().unwrap_or('x');
            if suffix.chars().all(|c| c == first_char) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_api_key_generic() {
        // Generic API key pattern expects "api_key: ..." format
        assert!(is_api_key("api_key: EXAMPLE000000000KEY01abcdef"));
        assert!(is_api_key("apikey: abcdef1234567890abcdef"));
        assert!(!is_api_key("short"));
    }

    #[test]
    fn test_is_aws_access_key() {
        // Long-term AKIA keys (constructed to avoid secret scanner false positives)
        let akia1 = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let akia2 = format!("AKIA{}", "I44QH8DHBEXAMPLE");
        assert!(is_aws_access_key(&akia1));
        assert!(is_aws_access_key(&akia2));
        // Temporary STS ASIA keys
        let asia1 = format!("ASIA{}", "IOSFODNN7EXAMPLE");
        let asia2 = format!("ASIA{}", "I44QH8DHBEXAMPLE");
        assert!(is_aws_access_key(&asia1));
        assert!(is_aws_access_key(&asia2));
        // Negative cases
        assert!(!is_aws_access_key("AKIA123")); // Too short
        assert!(!is_aws_access_key("ASIA123")); // Too short
        assert!(!is_aws_access_key("BKIAIOSFODNN7EXAMPLE")); // Wrong prefix
    }

    #[test]
    fn test_is_aws_access_key_asia_provider_detection() {
        // ASIA temporary credentials should be detected as AWS
        let asia1 = format!("ASIA{}", "IOSFODNN7EXAMPLE");
        let asia2 = format!("ASIA{}", "I44QH8DHBEXAMPLE");
        assert_eq!(detect_api_key_provider(&asia1), Some(ApiKeyProvider::Aws));
        assert_eq!(detect_api_key_provider(&asia2), Some(ApiKeyProvider::Aws));
    }

    #[test]
    fn test_is_aws_secret_key() {
        assert!(is_aws_secret_key(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ));
        assert!(!is_aws_secret_key("short"));
    }

    #[test]
    fn test_is_aws_session_token() {
        // Valid session token (100+ Base64 characters)
        let token = "FwoGZXIvYXdzEBYaDHVlTGhjaHJNTkxqayLIATCCAQIwggECMIIBAjCCAQIwggECMIIBAjCCAQIwggECabcdef";
        // Pad to 100+ chars
        let long_token = format!("{}{}", token, "A".repeat(20));
        assert!(is_aws_session_token(&long_token));
        // Too short
        assert!(!is_aws_session_token("FwoGZXIvYXdzEBYaDHVl"));
    }

    #[test]
    fn test_is_gcp_api_key() {
        assert!(is_gcp_api_key("AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"));
        assert!(!is_gcp_api_key("AIza123")); // Too short
        assert!(!is_gcp_api_key("BIzaSyDaGmWKa4JsXZ")); // Wrong prefix
    }

    #[test]
    fn test_is_github_token() {
        // Classic token prefixes
        assert!(is_github_token("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        assert!(is_github_token("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        assert!(is_github_token("ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        assert!(is_github_token("ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        assert!(is_github_token("ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        // Fine-grained PAT (github_pat_ + 22 + _ + 59)
        assert!(is_github_token(
            "github_pat_ABCDEFGHIJKLMNOPQRSTUv_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456"
        ));
        // Negative cases
        assert!(!is_github_token("ghp_short")); // Too short
        assert!(!is_github_token(
            "xyz_EXAMPLE0000000000KEY01abcdefwxyz123456"
        )); // Wrong prefix
        assert!(!is_github_token("github_pat_short_short")); // Fine-grained too short
    }

    #[test]
    fn test_detect_github_fine_grained_pat() {
        assert_eq!(
            detect_api_key_provider(
                "github_pat_ABCDEFGHIJKLMNOPQRSTUv_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456"
            ),
            Some(ApiKeyProvider::Github)
        );
    }

    #[test]
    fn test_is_azure_key() {
        assert!(is_azure_key(
            "AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/abcdefghijklmnopqrstuvwx=="
        ));
        assert!(!is_azure_key("AccountKey=short"));
    }

    #[test]
    fn test_is_stripe_key() {
        assert!(is_stripe_key(&format!(
            "sk_live_{}",
            "EXAMPLE000000000KEY01abcdef"
        )));
        assert!(is_stripe_key(&format!(
            "pk_test_{}",
            "EXAMPLE000000000KEY01abcdef"
        )));
        assert!(!is_stripe_key("sk_prod_12345")); // Wrong environment
        assert!(!is_stripe_key("xk_live_12345")); // Wrong prefix
    }

    #[test]
    fn test_is_gitlab_token() {
        assert!(is_gitlab_token("glpat-xxxxxxxxxxxxxxxxxxxx"));
        assert!(is_gitlab_token("gldt-yyyyyyyyyyyyyyyyyyyy"));
        assert!(!is_gitlab_token("glpat-short")); // Too short
        assert!(!is_gitlab_token("ghpat-xxxxxxxxxxxxxxxxxxxx")); // Wrong prefix
    }

    #[test]
    fn test_is_test_api_key_stripe_test() {
        // Stripe test keys
        assert!(is_test_api_key("sk_test_1234567890abcdefghij"));
        assert!(is_test_api_key("pk_test_1234567890abcdefghij"));
        assert!(is_test_api_key("rk_test_1234567890abcdefghij"));
    }

    #[test]
    fn test_is_test_api_key_stripe_live() {
        // Stripe live keys should NOT be test unless they contain EXAMPLE, TEST, etc.
        assert!(!is_test_api_key("sk_live_realproductionkey123"));
    }

    #[test]
    fn test_is_test_api_key_aws_example() {
        // AWS example keys from documentation
        let akia1 = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let akia2 = format!("AKIA{}", "I44QH8DHBEXAMPLE");
        assert!(is_test_api_key(&akia1));
        assert!(is_test_api_key(&akia2));
        assert!(is_test_api_key("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
    }

    #[test]
    fn test_is_test_api_key_keywords() {
        // Keys containing test keywords
        assert!(is_test_api_key("api_key_TEST_12345"));
        assert!(is_test_api_key("myDEMOapikey12345678"));
        assert!(is_test_api_key("FAKEapikey12345678901"));
        assert!(is_test_api_key("SAMPLE_KEY_1234567890"));
    }

    #[test]
    fn test_is_test_api_key_patterns() {
        // Sequential patterns
        assert!(is_test_api_key("api_key_123456789012345"));
        let akia_abc = format!("AKIA{}", "ABCDEFGHIJKLMNOP");
        assert!(is_test_api_key(&akia_abc));
    }

    #[test]
    fn test_is_onepassword_token() {
        // Valid 1Password service account tokens
        assert!(is_onepassword_token(
            "ops_eyJzaWduSW5BZGRyZXNzIjoiaHR0cHM6Ly9teS4xcGFzc3dvcmQuY29tIiwidXNlckF1dGgiOiJ5"
        ));
        assert!(!is_onepassword_token("ops_short")); // Too short
        assert!(!is_onepassword_token("opsshort")); // Missing underscore
        assert!(!is_onepassword_token("regular_token")); // Wrong prefix
    }

    #[test]
    fn test_is_onepassword_vault_ref() {
        // Valid vault references
        assert!(is_onepassword_vault_ref("op://vault/item/field"));
        assert!(is_onepassword_vault_ref("op://my-vault/my-item"));
        assert!(is_onepassword_vault_ref(
            "op://Production/Database/password"
        ));
        assert!(!is_onepassword_vault_ref("op://vault")); // Missing item
        assert!(!is_onepassword_vault_ref("https://example.com")); // Wrong protocol
    }

    #[test]
    fn test_is_bearer_token() {
        // Valid bearer tokens
        assert!(is_bearer_token(
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ));
        assert!(is_bearer_token("bearer abcdef1234567890abcdef"));
        assert!(is_bearer_token("BEARER MyLongTokenValue12345678"));
        assert!(!is_bearer_token("Bearer short")); // Too short
        assert!(!is_bearer_token("Token abc123")); // Wrong prefix
    }

    #[test]
    fn test_is_square_token() {
        // Valid Square OAuth access tokens (sq0atp- + 22+ chars)
        assert!(is_square_token(&format!(
            "sq0atp-{}",
            "ABCDEFghijklmnopqrstuv"
        )));
        // Valid Square OAuth secret (sq0csp- + 43+ chars)
        assert!(is_square_token(&format!(
            "sq0csp-{}",
            "ABCDEFghijklmnopqrstuvwxyz0123456789ABCDEFG"
        )));
        // Valid Square Application ID (sq0idp- + 22+ chars)
        assert!(is_square_token(&format!(
            "sq0idp-{}",
            "ABCDEFghijklmnopqrstuv"
        )));
        // Invalid: wrong prefix
        assert!(!is_square_token("sq1atp-ABCDEFghijklmnopqrstuv"));
        // Invalid: too short
        assert!(!is_square_token("sq0atp-short"));
    }

    #[test]
    fn test_detect_square_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("sq0atp-{}", "ABCDEFghijklmnopqrstuv")),
            Some(ApiKeyProvider::Square)
        );
        assert_eq!(
            detect_api_key_provider(&format!(
                "sq0csp-{}",
                "ABCDEFghijklmnopqrstuvwxyz0123456789ABCDEFG"
            )),
            Some(ApiKeyProvider::Square)
        );
    }

    #[test]
    fn test_is_shopify_token() {
        // Valid Shopify app access token (shpat_ + 32 hex chars)
        assert!(is_shopify_token(&format!(
            "shpat_{}",
            "abcdef1234567890abcdef1234567890"
        )));
        // Valid custom app token
        assert!(is_shopify_token(&format!(
            "shpca_{}",
            "abcdef1234567890abcdef1234567890"
        )));
        // Valid private app token
        assert!(is_shopify_token(&format!(
            "shppa_{}",
            "abcdef1234567890abcdef1234567890"
        )));
        // Valid shared secret
        assert!(is_shopify_token(&format!(
            "shpss_{}",
            "ABCDEF1234567890ABCDEF1234567890"
        )));
        // Invalid: wrong prefix
        assert!(!is_shopify_token("shpxx_abcdef1234567890abcdef1234567890"));
        // Invalid: too short
        assert!(!is_shopify_token("shpat_abcdef"));
        // Invalid: non-hex chars
        assert!(!is_shopify_token("shpat_ghijklmnopqrstuvwxyz12345678zz"));
    }

    #[test]
    fn test_detect_shopify_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("shpat_{}", "abcdef1234567890abcdef1234567890")),
            Some(ApiKeyProvider::Shopify)
        );
    }

    #[test]
    fn test_is_paypal_token() {
        // Valid Braintree production access token
        let prod_token = format!(
            "access_token$production${}${}",
            "abc1234567890xyz", "abcdef1234567890abcdef1234567890"
        );
        assert!(is_paypal_token(&prod_token));
        // Valid Braintree sandbox access token
        let sandbox_token = format!(
            "access_token$sandbox${}${}",
            "abc1234567890xyz", "abcdef1234567890abcdef1234567890"
        );
        assert!(is_paypal_token(&sandbox_token));
        // Invalid: wrong environment
        assert!(!is_paypal_token(
            "access_token$staging$abc1234567890xyz$abcdef1234567890abcdef1234567890"
        ));
        // Invalid: missing parts
        assert!(!is_paypal_token("access_token$production$short"));
    }

    #[test]
    fn test_detect_paypal_provider() {
        let token = format!(
            "access_token$production${}${}",
            "abc1234567890xyz", "abcdef1234567890abcdef1234567890"
        );
        assert_eq!(
            detect_api_key_provider(&token),
            Some(ApiKeyProvider::PayPal)
        );
    }

    #[test]
    fn test_is_test_api_key_square_sandbox() {
        assert!(is_test_api_key(&format!(
            "sandbox-sq0atp-{}",
            "ABCDEFghijklmnopqrstuv"
        )));
    }

    #[test]
    fn test_is_test_api_key_paypal_sandbox() {
        let sandbox = format!(
            "access_token$sandbox${}${}",
            "abc1234567890xyz", "abcdef1234567890abcdef1234567890"
        );
        assert!(is_test_api_key(&sandbox));
    }

    #[test]
    fn test_is_mailchimp_key() {
        // Valid Mailchimp API key (32 hex chars + datacenter suffix)
        // Constructed at runtime to avoid triggering secret scanners
        let key1 = format!("{}{}-us6", "abcdef1234567890", "abcdef1234567890");
        assert!(is_mailchimp_key(&key1));
        let key2 = format!("{}{}-us1", "0123456789abcdef", "0123456789abcdef");
        assert!(is_mailchimp_key(&key2));
        let key3 = format!("{}{}-us20", "abcdef1234567890", "abcdef1234567890");
        assert!(is_mailchimp_key(&key3));
        // Invalid: wrong suffix
        let bad_suffix = format!("{}{}-eu1", "abcdef1234567890", "abcdef1234567890");
        assert!(!is_mailchimp_key(&bad_suffix));
        // Invalid: too short hex
        assert!(!is_mailchimp_key("abcdef1234567890-us6"));
        // Invalid: non-hex chars
        assert!(!is_mailchimp_key("ghijkl1234567890ghijkl1234567890-us6"));
    }

    #[test]
    fn test_detect_mailchimp_provider() {
        let key = format!("{}{}-us6", "abcdef1234567890", "abcdef1234567890");
        assert_eq!(
            detect_api_key_provider(&key),
            Some(ApiKeyProvider::Mailchimp)
        );
    }

    #[test]
    fn test_is_mailgun_key() {
        // Valid Mailgun API key (key- + 32 alnum chars)
        assert!(is_mailgun_key(&format!(
            "key-{}",
            "ABCDEFghijklmnopqrstuv1234567890"
        )));
        // Invalid: wrong prefix
        assert!(!is_mailgun_key(&format!(
            "ky-{}",
            "ABCDEFghijklmnopqrstuv1234567890"
        )));
        // Invalid: too short
        assert!(!is_mailgun_key("key-short"));
    }

    #[test]
    fn test_detect_mailgun_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("key-{}", "ABCDEFghijklmnopqrstuv1234567890")),
            Some(ApiKeyProvider::Mailgun)
        );
    }

    #[test]
    fn test_is_resend_key() {
        // Valid Resend API key (re_ + 32+ alnum chars)
        assert!(is_resend_key(&format!(
            "re_{}",
            "ABCDEFghijklmnopqrstuv1234567890ab"
        )));
        // Invalid: wrong prefix
        assert!(!is_resend_key(&format!(
            "rx_{}",
            "ABCDEFghijklmnopqrstuv1234567890ab"
        )));
        // Invalid: too short
        assert!(!is_resend_key("re_short"));
    }

    #[test]
    fn test_detect_resend_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("re_{}", "ABCDEFghijklmnopqrstuv1234567890ab")),
            Some(ApiKeyProvider::Resend)
        );
    }

    #[test]
    fn test_is_brevo_key() {
        // Valid Brevo API key (xkeysib- + 64 hex + - + 16 alnum)
        let hex64 = "a".repeat(64);
        let alnum16 = "B".repeat(16);
        assert!(is_brevo_key(&format!("xkeysib-{hex64}-{alnum16}")));
        // Invalid: wrong prefix
        assert!(!is_brevo_key(&format!("xkeysic-{hex64}-{alnum16}")));
        // Invalid: hex too short
        let hex32 = "a".repeat(32);
        assert!(!is_brevo_key(&format!("xkeysib-{hex32}-{alnum16}")));
    }

    #[test]
    fn test_detect_brevo_provider() {
        let hex64 = "a".repeat(64);
        let alnum16 = "B".repeat(16);
        assert_eq!(
            detect_api_key_provider(&format!("xkeysib-{hex64}-{alnum16}")),
            Some(ApiKeyProvider::Brevo)
        );
    }

    #[test]
    fn test_is_databricks_token() {
        // Valid Databricks token (dapi + 32 hex)
        assert!(is_databricks_token(&format!("dapi{}", "a".repeat(32))));
        // Valid with suffix
        assert!(is_databricks_token(&format!("dapi{}-2", "a".repeat(32))));
        // Invalid: wrong prefix
        assert!(!is_databricks_token(&format!("dapx{}", "a".repeat(32))));
        // Invalid: too short
        assert!(!is_databricks_token("dapi1234"));
    }

    #[test]
    fn test_detect_databricks_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("dapi{}", "a".repeat(32))),
            Some(ApiKeyProvider::Databricks)
        );
    }

    #[test]
    fn test_is_vault_token() {
        // Valid modern token (hvs. + 24+ chars)
        assert!(is_vault_token(&format!("hvs.{}", "A".repeat(24))));
        // Valid wrapped token
        assert!(is_vault_token(&format!("hvs.CAESI{}", "B".repeat(30))));
        // Valid batch token (b. + 24+ chars)
        assert!(is_vault_token(&format!("b.{}", "A".repeat(24))));
        // Valid legacy service token (s. + exactly 24 chars)
        assert!(is_vault_token(&format!("s.{}", "A".repeat(24))));
        // Invalid: s. with wrong length (23 chars)
        assert!(!is_vault_token(&format!("s.{}", "A".repeat(23))));
        // Invalid: wrong prefix
        assert!(!is_vault_token(&format!("x.{}", "A".repeat(24))));
        // Invalid: too short hvs.
        assert!(!is_vault_token("hvs.short"));
    }

    #[test]
    fn test_detect_vault_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("hvs.{}", "A".repeat(24))),
            Some(ApiKeyProvider::HashicorpVault)
        );
        assert_eq!(
            detect_api_key_provider(&format!("s.{}", "A".repeat(24))),
            Some(ApiKeyProvider::HashicorpVault)
        );
        assert_eq!(
            detect_api_key_provider(&format!("b.{}", "A".repeat(24))),
            Some(ApiKeyProvider::HashicorpVault)
        );
    }

    #[test]
    fn test_is_cloudflare_ca_key() {
        // Valid Origin CA key (v1.0- + 24 hex + - + 146 hex)
        let key = format!("v1.0-{}-{}", "a".repeat(24), "b".repeat(146));
        assert!(is_cloudflare_ca_key(&key));
        // Invalid: too short
        assert!(!is_cloudflare_ca_key(&format!(
            "v1.0-{}-{}",
            "a".repeat(24),
            "b".repeat(10)
        )));
        // Invalid: wrong prefix
        assert!(!is_cloudflare_ca_key(&format!(
            "v2.0-{}-{}",
            "a".repeat(24),
            "b".repeat(146)
        )));
    }

    #[test]
    fn test_detect_cloudflare_provider() {
        let key = format!("v1.0-{}-{}", "a".repeat(24), "b".repeat(146));
        assert_eq!(
            detect_api_key_provider(&key),
            Some(ApiKeyProvider::Cloudflare)
        );
    }

    #[test]
    fn test_is_npm_token() {
        // Valid NPM token (npm_ + 36 alnum)
        assert!(is_npm_token(&format!("npm_{}", "A".repeat(36))));
        // Invalid: wrong prefix
        assert!(!is_npm_token(&format!("npx_{}", "A".repeat(36))));
        // Invalid: too short
        assert!(!is_npm_token("npm_short"));
    }

    #[test]
    fn test_detect_npm_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("npm_{}", "A".repeat(36))),
            Some(ApiKeyProvider::Npm)
        );
    }

    #[test]
    fn test_is_pypi_token() {
        // Valid PyPI token (pypi-AgEIcHlwaS5vcmc + 50+ base64)
        assert!(is_pypi_token(&format!(
            "pypi-AgEIcHlwaS5vcmc{}",
            "A".repeat(50)
        )));
        // Invalid: wrong prefix
        assert!(!is_pypi_token(&format!("pypi-XYZ{}", "A".repeat(50))));
        // Invalid: too short
        assert!(!is_pypi_token("pypi-AgEIcHlwaS5vcmcShort"));
    }

    #[test]
    fn test_detect_pypi_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("pypi-AgEIcHlwaS5vcmc{}", "A".repeat(50))),
            Some(ApiKeyProvider::PyPi)
        );
    }

    #[test]
    fn test_is_nuget_key() {
        // Valid NuGet key (oy2 + 43 lowercase alnum)
        assert!(is_nuget_key(&format!("oy2{}", "a".repeat(43))));
        // Invalid: wrong prefix
        assert!(!is_nuget_key(&format!("oy3{}", "a".repeat(43))));
        // Invalid: too short
        assert!(!is_nuget_key("oy2short"));
        // Invalid: uppercase chars (NuGet keys are lowercase)
        assert!(!is_nuget_key(&format!("oy2{}", "A".repeat(43))));
    }

    #[test]
    fn test_detect_nuget_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("oy2{}", "a".repeat(43))),
            Some(ApiKeyProvider::NuGet)
        );
    }

    #[test]
    fn test_is_artifactory_token() {
        // Valid Artifactory key (AKC + 10+ alnum)
        assert!(is_artifactory_token(&format!("AKC{}", "a".repeat(10))));
        assert!(is_artifactory_token(&format!("AKC{}", "B".repeat(20))));
        // Invalid: wrong prefix
        assert!(!is_artifactory_token(&format!("AKD{}", "a".repeat(10))));
        // Invalid: too short
        assert!(!is_artifactory_token("AKCshort"));
    }

    #[test]
    fn test_detect_artifactory_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("AKC{}", "a".repeat(10))),
            Some(ApiKeyProvider::Artifactory)
        );
    }

    #[test]
    fn test_is_docker_hub_token() {
        // Valid Docker Hub PAT (dckr_pat_ + 27+ alnum)
        assert!(is_docker_hub_token(&format!("dckr_pat_{}", "A".repeat(27))));
        // Invalid: wrong prefix
        assert!(!is_docker_hub_token(&format!(
            "dckr_xxx_{}",
            "A".repeat(27)
        )));
        // Invalid: too short
        assert!(!is_docker_hub_token("dckr_pat_short"));
    }

    #[test]
    fn test_detect_docker_hub_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("dckr_pat_{}", "A".repeat(27))),
            Some(ApiKeyProvider::DockerHub)
        );
    }

    #[test]
    fn test_is_telegram_bot_token() {
        // Valid: 8-digit ID + 35-char secret
        assert!(is_telegram_bot_token(&format!(
            "12345678:{}",
            "A".repeat(35)
        )));
        // Valid: 10-digit ID + 35-char secret
        assert!(is_telegram_bot_token(&format!(
            "1234567890:{}",
            "ABCDEFghij_-klmnopqrstuv01234567890"
        )));
        // Invalid: numeric prefix too short (7 digits)
        assert!(!is_telegram_bot_token(&format!(
            "1234567:{}",
            "A".repeat(35)
        )));
        // Invalid: numeric prefix too long (11 digits)
        assert!(!is_telegram_bot_token(&format!(
            "12345678901:{}",
            "A".repeat(35)
        )));
        // Invalid: secret too short
        assert!(!is_telegram_bot_token(&format!(
            "12345678:{}",
            "A".repeat(34)
        )));
        // Invalid: no colon separator
        assert!(!is_telegram_bot_token("not-a-telegram-token"));
    }

    #[test]
    fn test_detect_telegram_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("12345678:{}", "A".repeat(35))),
            Some(ApiKeyProvider::Telegram)
        );
    }

    #[test]
    fn test_is_url_with_credentials() {
        // Valid URLs with credentials
        assert!(is_url_with_credentials("https://user:password@example.com"));
        assert!(is_url_with_credentials(
            "ftp://admin:secret@ftp.example.com/path"
        ));
        assert!(is_url_with_credentials(
            "postgres://dbuser:dbpass@localhost:5432/mydb"
        ));
        assert!(!is_url_with_credentials("https://example.com")); // No credentials
        assert!(!is_url_with_credentials("user:password@example.com")); // No protocol
    }
}

//! API key detection
//!
//! Pure detection functions for various API key formats (AWS, Azure, GCP, GitHub, Stripe, etc.)
//!
//! # Module organization
//!
//! Provider-specific detection lives in per-provider submodules grouped by
//! family. Each submodule wraps a single domain (cloud, source control,
//! payments, messaging, etc.) and is independently reviewable. All
//! provider functions are re-exported flat at this level so callers can
//! continue to use them via `detection::is_aws_access_key(...)` etc.
//!
//! Cross-provider entry points stay here:
//!
//! - [`detect_api_key_provider`] — classifies an unknown key into an [`ApiKeyProvider`]
//! - [`is_api_key`] — generic "is this any kind of API key?" probe
//! - [`is_test_api_key`] — heuristic for documented example / sandbox / dev keys

mod ai;
mod aws;
mod data_platforms;
mod email_marketing;
mod generic;
mod google;
mod infrastructure;
mod messaging;
mod microsoft;
mod package_registries;
mod payments;
mod secrets_managers;
mod source_control;

pub use ai::*;
pub use aws::*;
pub use data_platforms::*;
pub use email_marketing::*;
pub use generic::*;
pub use google::*;
pub use infrastructure::*;
pub use messaging::*;
pub use microsoft::*;
pub use package_registries::*;
pub use payments::*;
pub use secrets_managers::*;
pub use source_control::*;

use super::super::super::common::patterns;
use super::types::ApiKeyProvider;

/// Maximum identifier length for single-value checks
pub(super) const MAX_IDENTIFIER_LENGTH: usize = 1_000;

/// Azure keys can be longer
pub(super) const MAX_AZURE_KEY_LENGTH: usize = 10_000;

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

    // GCP OAuth2 client secret (GOCSPX-...)
    if key.starts_with("GOCSPX-") {
        return Some(ApiKeyProvider::GcpOAuth);
    }

    // Firebase Cloud Messaging server key (AAAA... 140+ chars)
    if key.starts_with("AAAA") && key.len() >= 144 {
        return Some(ApiKeyProvider::Firebase);
    }

    // GCP Service Account JSON marker
    if key.contains("\"type\"") && key.contains("\"service_account\"") {
        return Some(ApiKeyProvider::GcpServiceAccount);
    }

    // Azure connection strings and keys
    if is_azure_connection_string(key) {
        return Some(ApiKeyProvider::Azure);
    }
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

    // Discord bot tokens or webhook URLs
    if patterns::network::API_KEY_DISCORD_BOT.is_match(key)
        || patterns::network::API_KEY_DISCORD_WEBHOOK.is_match(key)
    {
        return Some(ApiKeyProvider::Discord);
    }

    // Slack tokens (xox*, xapp-) or webhook URLs
    if key_lower.starts_with("xox") || key_lower.starts_with("xapp-") {
        return Some(ApiKeyProvider::Slack);
    }
    if patterns::network::API_KEY_SLACK_WEBHOOK.is_match(key) {
        return Some(ApiKeyProvider::Slack);
    }

    // Twilio Account SIDs (AC...) and API Key SIDs (SK...)
    if (key.starts_with("AC") || key.starts_with("SK"))
        && key.len() == 34
        && (patterns::network::API_KEY_TWILIO_SID.is_match(key)
            || patterns::network::API_KEY_TWILIO_API_KEY.is_match(key))
    {
        return Some(ApiKeyProvider::Twilio);
    }

    // SendGrid API keys (SG.{22}.{43})
    if key.starts_with("SG.") {
        return Some(ApiKeyProvider::SendGrid);
    }

    // OpenAI API keys (sk-*, sk-proj-*, org-*)
    if key.starts_with("sk-proj-") || key.starts_with("sk-") && key.contains("T3BlbkFJ") {
        return Some(ApiKeyProvider::OpenAi);
    }
    if key.starts_with("org-") && key.len() == 28 {
        return Some(ApiKeyProvider::OpenAi);
    }

    // Bitbucket Cloud App Password (ATBB...)
    if key.starts_with("ATBB") && key.len() == 36 {
        return Some(ApiKeyProvider::Bitbucket);
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
        || patterns::network::GCP_SERVICE_ACCOUNT_TYPE.is_match(trimmed)
        || patterns::network::GCP_SERVICE_ACCOUNT_EMAIL.is_match(trimmed)
        || patterns::network::GCP_OAUTH_CLIENT_SECRET.is_match(trimmed)
        || patterns::network::FIREBASE_FCM_SERVER_KEY.is_match(trimmed)
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
        || patterns::network::API_KEY_OPENAI_LEGACY.is_match(trimmed)
        || patterns::network::API_KEY_OPENAI_PROJECT.is_match(trimmed)
        || patterns::network::API_KEY_OPENAI_ORG.is_match(trimmed)
        || (trimmed.len() <= MAX_AZURE_KEY_LENGTH
            && patterns::network::API_KEY_AZURE.is_match(trimmed))
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

    // ========================================================================
    // is_api_key
    // ========================================================================

    #[test]
    fn test_is_api_key_generic() {
        // Generic API key pattern expects "api_key: ..." format
        assert!(is_api_key("api_key: EXAMPLE000000000KEY01abcdef"));
        assert!(is_api_key("apikey: abcdef1234567890abcdef"));
        assert!(!is_api_key("short"));
    }

    // ========================================================================
    // detect_api_key_provider — per-provider classification
    // ========================================================================

    #[test]
    fn test_detect_aws_asia_provider() {
        // ASIA temporary credentials should be detected as AWS
        let asia1 = format!("ASIA{}", "IOSFODNN7EXAMPLE");
        let asia2 = format!("ASIA{}", "I44QH8DHBEXAMPLE");
        assert_eq!(detect_api_key_provider(&asia1), Some(ApiKeyProvider::Aws));
        assert_eq!(detect_api_key_provider(&asia2), Some(ApiKeyProvider::Aws));
    }

    #[test]
    fn test_detect_gcp_providers() {
        assert_eq!(
            detect_api_key_provider("GOCSPX-abcdefghijklmnopqrstuvwx1234"),
            Some(ApiKeyProvider::GcpOAuth)
        );
        let fcm_key = format!("AAAA{}", "a".repeat(140));
        assert_eq!(
            detect_api_key_provider(&fcm_key),
            Some(ApiKeyProvider::Firebase)
        );
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
    fn test_detect_provider_azure_connection_string() {
        let key88 = "a".repeat(86) + "==";
        let conn = format!(
            "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey={key88};EndpointSuffix=core.windows.net"
        );
        assert_eq!(detect_api_key_provider(&conn), Some(ApiKeyProvider::Azure));
    }

    #[test]
    fn test_detect_api_key_provider_bitbucket() {
        assert_eq!(
            detect_api_key_provider("ATBBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            Some(ApiKeyProvider::Bitbucket)
        );
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
    fn test_detect_shopify_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("shpat_{}", "abcdef1234567890abcdef1234567890")),
            Some(ApiKeyProvider::Shopify)
        );
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
    fn test_detect_mailchimp_provider() {
        let key = format!("{}{}-us6", "abcdef1234567890", "abcdef1234567890");
        assert_eq!(
            detect_api_key_provider(&key),
            Some(ApiKeyProvider::Mailchimp)
        );
    }

    #[test]
    fn test_detect_mailgun_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("key-{}", "ABCDEFghijklmnopqrstuv1234567890")),
            Some(ApiKeyProvider::Mailgun)
        );
    }

    #[test]
    fn test_detect_resend_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("re_{}", "ABCDEFghijklmnopqrstuv1234567890ab")),
            Some(ApiKeyProvider::Resend)
        );
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
    fn test_detect_databricks_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("dapi{}", "a".repeat(32))),
            Some(ApiKeyProvider::Databricks)
        );
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
    fn test_detect_cloudflare_provider() {
        let key = format!("v1.0-{}-{}", "a".repeat(24), "b".repeat(146));
        assert_eq!(
            detect_api_key_provider(&key),
            Some(ApiKeyProvider::Cloudflare)
        );
    }

    #[test]
    fn test_detect_npm_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("npm_{}", "A".repeat(36))),
            Some(ApiKeyProvider::Npm)
        );
    }

    #[test]
    fn test_detect_pypi_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("pypi-AgEIcHlwaS5vcmc{}", "A".repeat(50))),
            Some(ApiKeyProvider::PyPi)
        );
    }

    #[test]
    fn test_detect_nuget_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("oy2{}", "a".repeat(43))),
            Some(ApiKeyProvider::NuGet)
        );
    }

    #[test]
    fn test_detect_artifactory_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("AKC{}", "a".repeat(10))),
            Some(ApiKeyProvider::Artifactory)
        );
    }

    #[test]
    fn test_detect_docker_hub_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("dckr_pat_{}", "A".repeat(27))),
            Some(ApiKeyProvider::DockerHub)
        );
    }

    #[test]
    fn test_detect_telegram_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("12345678:{}", "A".repeat(35))),
            Some(ApiKeyProvider::Telegram)
        );
    }

    #[test]
    fn test_detect_discord_provider() {
        // Bot token
        assert_eq!(
            detect_api_key_provider(&format!(
                "M{}.{}.{}",
                "A".repeat(23),
                "AbCdEf",
                "a".repeat(27)
            )),
            Some(ApiKeyProvider::Discord)
        );
        // Webhook URL
        assert_eq!(
            detect_api_key_provider(
                "https://discord.com/api/webhooks/123456789/abcdefABCDEF_-0123456789"
            ),
            Some(ApiKeyProvider::Discord)
        );
    }

    #[test]
    fn test_detect_slack_provider() {
        // Bot token
        assert_eq!(
            detect_api_key_provider(&format!("xoxb-{}-{}", "1".repeat(12), "A".repeat(24))),
            Some(ApiKeyProvider::Slack)
        );
        // Webhook URL
        assert_eq!(
            detect_api_key_provider(&format!(
                "https://hooks.slack.com/services/T{}/B{}/{}",
                "A".repeat(10),
                "B".repeat(10),
                "c".repeat(24)
            )),
            Some(ApiKeyProvider::Slack)
        );
    }

    #[test]
    fn test_detect_twilio_provider() {
        // Account SID
        assert_eq!(
            detect_api_key_provider(&format!("AC{}", "a".repeat(32))),
            Some(ApiKeyProvider::Twilio)
        );
        // API Key SID
        assert_eq!(
            detect_api_key_provider(&format!("SK{}", "b".repeat(32))),
            Some(ApiKeyProvider::Twilio)
        );
    }

    #[test]
    fn test_detect_sendgrid_provider() {
        assert_eq!(
            detect_api_key_provider(&format!("SG.{}.{}", "A".repeat(22), "b".repeat(43))),
            Some(ApiKeyProvider::SendGrid)
        );
    }

    #[test]
    fn test_detect_openai_provider() {
        // Legacy key
        assert_eq!(
            detect_api_key_provider(&format!("sk-{}T3BlbkFJ{}", "A".repeat(20), "B".repeat(20))),
            Some(ApiKeyProvider::OpenAi)
        );

        // Project key
        assert_eq!(
            detect_api_key_provider(&format!("sk-proj-{}", "AbCd1234".repeat(10))),
            Some(ApiKeyProvider::OpenAi)
        );

        // Organization key
        assert_eq!(
            detect_api_key_provider(&format!("org-{}", "a".repeat(24))),
            Some(ApiKeyProvider::OpenAi)
        );
    }

    // ========================================================================
    // is_test_api_key
    // ========================================================================

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
}

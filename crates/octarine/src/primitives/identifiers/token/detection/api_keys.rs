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
#[allow(clippy::indexing_slicing)]
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
        } else {
            0
        };

    if prefix_len > 0 && prefix_len < trimmed.len() {
        let suffix = &trimmed[prefix_len..];
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

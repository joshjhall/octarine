//! API key and token detection functions
//!
//! Detection for various cloud provider API keys, tokens, and JWTs.

use super::super::super::common::patterns;
use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};

use super::common::{
    MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length,
    get_full_match,
};

// ============================================================================
// JWT Detection
// ============================================================================

/// Check if value is a JWT token
#[must_use]
pub fn is_jwt(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::JWT.is_match(trimmed)
}

// ============================================================================
// API Key Detection
// ============================================================================

/// Check if value is an API key
///
/// Detects generic and provider-specific API keys:
/// - Generic API keys (32+ alphanumeric characters)
/// - AWS Access Keys (AKIA...)
/// - AWS Secret Keys (40 base64 characters)
/// - GCP API Keys (AIza...)
/// - GitHub tokens (ghp_, gho_, ghs_, ghr_)
/// - Azure Storage Keys
/// - Stripe keys (sk_, pk_)
#[must_use]
pub fn is_api_key(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::API_KEY_GENERIC.is_match(trimmed)
        || patterns::network::API_KEY_STRIPE.is_match(trimmed)
        || patterns::network::API_KEY_AWS_ACCESS.is_match(trimmed)
        || patterns::network::API_KEY_AWS_SECRET.is_match(trimmed)
        || patterns::network::API_KEY_GCP.is_match(trimmed)
        || patterns::network::API_KEY_GITHUB.is_match(trimmed)
        || patterns::network::API_KEY_AZURE.is_match(trimmed)
}

/// Check if value is an AWS Access Key ID
///
/// AWS Access Key IDs start with "AKIA" followed by 16 alphanumeric characters
#[must_use]
pub fn is_aws_access_key(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
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
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::API_KEY_AWS_SECRET.is_match(trimmed)
}

/// Check if value is a Google Cloud Platform API key
///
/// GCP API keys start with "AIza" followed by 35 alphanumeric characters
#[must_use]
pub fn is_gcp_api_key(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::API_KEY_GCP.is_match(trimmed)
}

/// Check if value is a GitHub Personal Access Token
///
/// GitHub tokens start with "ghp_", "gho_", "ghs_", or "ghr_" followed by 36+ characters
#[must_use]
pub fn is_github_token(value: &str) -> bool {
    let trimmed = value.trim();
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
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
    if exceeds_safe_length(trimmed, MAX_INPUT_LENGTH) {
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
    if exceeds_safe_length(trimmed, MAX_IDENTIFIER_LENGTH) {
        return false;
    }
    patterns::network::API_KEY_STRIPE.is_match(trimmed)
}

// ============================================================================
// Text Scanning
// ============================================================================

/// Find all API keys in text
#[must_use]
pub fn find_api_keys_in_text(text: &str) -> Vec<IdentifierMatch> {
    if exceeds_safe_length(text, MAX_INPUT_LENGTH) {
        return Vec::new();
    }

    let mut matches = Vec::new();
    for pattern in patterns::network::api_keys() {
        for capture in pattern.captures_iter(text) {
            let full_match = get_full_match(&capture);
            matches.push(IdentifierMatch::new(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::ApiKey,
                DetectionConfidence::High,
            ));
        }
    }
    deduplicate_matches(matches)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_is_api_key() {
        // AWS
        assert!(is_api_key("AKIAIOSFODNN7EXAMPLE"));
        // Stripe
        assert!(is_api_key(&format!("sk_test_{}", "EXAMPLE0000000000KEY01abcdef")));
        assert!(is_api_key(&format!("pk_live_{}", "EXAMPLE0000000000KEY01abcdef")));
        // GitHub
        assert!(is_api_key("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        // GCP
        assert!(is_api_key("AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg"));
    }

    #[test]
    fn test_is_aws_access_key() {
        assert!(is_aws_access_key("AKIAIOSFODNN7EXAMPLE"));
        assert!(is_aws_access_key("AKIA1234567890123456"));
        assert!(!is_aws_access_key("not-an-aws-key"));
        assert!(!is_aws_access_key("AKIA123")); // too short
    }

    #[test]
    fn test_is_aws_secret_key() {
        // 40 character base64-like string
        assert!(is_aws_secret_key(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ));
    }

    #[test]
    fn test_is_gcp_api_key() {
        assert!(is_gcp_api_key("AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg"));
        assert!(!is_gcp_api_key("not-a-gcp-key"));
    }

    #[test]
    fn test_is_github_token() {
        // Personal access token
        assert!(is_github_token("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        // OAuth token
        assert!(is_github_token("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        // App token
        assert!(is_github_token("ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        // Refresh token
        assert!(is_github_token("ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        assert!(!is_github_token("not-a-github-token"));
    }

    #[test]
    fn test_is_stripe_key() {
        assert!(is_stripe_key(&format!("sk_test_{}", "EXAMPLE0000000000KEY01abcdef")));
        assert!(is_stripe_key(&format!("sk_live_{}", "EXAMPLE0000000000KEY01abcdef")));
        assert!(is_stripe_key(&format!("pk_test_{}", "EXAMPLE0000000000KEY01abcdef")));
        assert!(is_stripe_key(&format!("pk_live_{}", "EXAMPLE0000000000KEY01abcdef")));
        assert!(!is_stripe_key("not-a-stripe-key"));
    }

    #[test]
    fn test_find_api_keys_in_text() {
        let text =
            &format!("AWS key: AKIAIOSFODNN7EXAMPLE and Stripe: sk_test_{}", "EXAMPLE0000000000KEY01abcdef");
        let matches = find_api_keys_in_text(text);
        assert!(!matches.is_empty()); // At least AWS key should be found
    }
}

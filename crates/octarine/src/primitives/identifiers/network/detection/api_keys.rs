//! API key and token detection functions
//!
//! Detection for various cloud provider API keys, tokens, and JWTs.
//!
//! # Architecture
//!
//! All `is_*` detection functions are re-exported from the canonical
//! implementations in `token/detection/api_keys.rs` and `token/detection/jwt.rs`.
//! This eliminates duplication and ensures security fixes propagate automatically.
//!
//! `find_api_keys_in_text` is network-specific (returns `Vec<IdentifierMatch>`)
//! and remains implemented here.

use super::super::super::common::patterns;
use super::super::super::types::{DetectionConfidence, IdentifierMatch, IdentifierType};

use super::common::{MAX_INPUT_LENGTH, deduplicate_matches, exceeds_safe_length, get_full_match};

// Re-export all is_* detection functions from the canonical token module.
// This prevents drift between network and token API key detection.
pub use super::super::super::token::{
    is_api_key, is_aws_access_key, is_aws_secret_key, is_aws_session_token, is_azure_key,
    is_bearer_token, is_gcp_api_key, is_github_token, is_gitlab_token, is_jwt,
    is_onepassword_token, is_onepassword_vault_ref, is_stripe_key, is_url_with_credentials,
};

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
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_find_api_keys_in_text() {
        let akia = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let text = &format!(
            "AWS key: {akia} and Stripe: sk_test_{}",
            "EXAMPLE0000000000KEY01abcdef"
        );
        let matches = find_api_keys_in_text(text);
        assert!(!matches.is_empty()); // At least AWS key should be found
    }

    // Verify re-exported functions are accessible and work correctly
    #[test]
    fn test_reexported_is_api_key() {
        let akia = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        assert!(is_api_key(&akia));
        let ghp = format!("ghp_{}", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        assert!(is_api_key(&ghp));
        assert!(!is_api_key("not-an-api-key"));
    }

    #[test]
    fn test_reexported_provider_specific() {
        let akia = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        assert!(is_aws_access_key(&akia));
        assert!(is_aws_secret_key(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ));
        assert!(is_gcp_api_key("AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg"));
        let ghp = format!("ghp_{}", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        assert!(is_github_token(&ghp));
        assert!(is_stripe_key(&format!(
            "sk_test_{}",
            "EXAMPLE0000000000KEY01abcdef"
        )));
    }

    // Verify the 6 previously-missing functions are now available
    #[test]
    fn test_previously_missing_functions_available() {
        // These functions were missing from the network fork — now re-exported from token
        assert!(!is_aws_session_token("not-a-session-token"));
        assert!(!is_gitlab_token("not-a-gitlab-token"));
        assert!(!is_onepassword_token("not-a-1p-token"));
        assert!(!is_onepassword_vault_ref("not-a-vault-ref"));
        assert!(!is_bearer_token("not-a-bearer-token"));
        assert!(!is_url_with_credentials("https://example.com"));
    }
}

//! Token identifier detection (primitives layer)
//!
//! Pure detection functions for authentication and authorization tokens with NO logging.
//! Uses patterns from `primitives/identifiers/common/patterns.rs`.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Module Structure
//!
//! - `types` - Token type definitions (ApiKeyProvider, JwtAlgorithm, TokenType)
//! - `jwt` - JWT token detection
//! - `api_keys` - API key detection (AWS, Azure, GCP, GitHub, Stripe, etc.)
//! - `ssh` - SSH key and fingerprint detection
//! - `session` - Session ID detection (heuristic)
//!
//! # Supported Token Types
//!
//! - **JWT**: JSON Web Tokens
//! - **API Keys**: Generic, AWS, Azure, GCP, GitHub, Stripe
//! - **Session IDs**: Session identifiers
//!
//! # Security Considerations
//!
//! - **PCI DSS**: API keys and tokens require secure handling
//! - **OWASP A02:2021**: Cryptographic failures from weak tokens
//! - **OWASP A07:2021**: Identification failures from predictable session IDs

mod api_keys;
mod jwt;
mod session;
mod ssh;
mod types;

// Re-export types
pub use types::{ApiKeyProvider, JwtAlgorithm, TokenType};

// Re-export JWT functions
pub use jwt::{detect_jwt_algorithm, is_jwt, is_test_jwt};

// Re-export API key functions
pub use api_keys::{
    detect_api_key_provider, is_api_key, is_aws_access_key, is_aws_secret_key,
    is_aws_session_token, is_azure_key, is_bearer_token, is_brevo_key, is_gcp_api_key,
    is_github_token, is_gitlab_token, is_mailchimp_key, is_mailgun_key, is_onepassword_token,
    is_onepassword_vault_ref, is_paypal_token, is_resend_key, is_shopify_token, is_square_token,
    is_stripe_key, is_test_api_key, is_url_with_credentials,
};

// Re-export SSH functions
pub use ssh::{
    is_ssh_fingerprint, is_ssh_key, is_ssh_private_key, is_ssh_public_key, is_test_ssh_key,
};

// Re-export session functions
pub use session::{is_likely_session_id, is_test_session_id};

// ============================================================================
// Unified Token Detection
// ============================================================================

/// Detect the specific type of token
///
/// Analyzes the input to determine which type of authentication/authorization token it is.
/// Checks patterns in order from most specific to most generic.
///
/// # Detection Order
///
/// 1. Platform-specific tokens (GitHub, GitLab, AWS, GCP, Azure, Stripe)
/// 2. SSH keys and fingerprints
/// 3. JWT tokens
/// 4. Generic API keys
/// 5. Session IDs (heuristic)
///
/// # Returns
///
/// * `Some(TokenType::...)` - If a token pattern is detected
/// * `None` - If no token pattern is detected
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::detection::{detect_token_type, TokenType};
///
/// // GitHub token
/// assert_eq!(
///     detect_token_type("ghp_abc123..."),
///     Some(TokenType::GitHub)
/// );
///
/// // AWS access key (AKIA + IOSFODNN7EXAMPLE)
/// // assert_eq!(detect_token_type(&akia_key), Some(TokenType::AwsAccessKey));
///
/// // SSH key
/// assert_eq!(
///     detect_token_type("ssh-rsa AAAAB3NzaC1yc2E..."),
///     Some(TokenType::SshPublicKey)
/// );
/// ```
#[must_use]
pub fn detect_token_type(value: &str) -> Option<TokenType> {
    let trimmed = value.trim();

    // Platform-specific tokens (most specific first)
    if is_github_token(trimmed) {
        return Some(TokenType::GitHub);
    }
    if is_gitlab_token(trimmed) {
        return Some(TokenType::GitLab);
    }
    if is_stripe_key(trimmed) {
        return Some(TokenType::StripeKey);
    }
    if is_square_token(trimmed) {
        return Some(TokenType::SquareToken);
    }
    if is_shopify_token(trimmed) {
        return Some(TokenType::ShopifyToken);
    }
    if is_paypal_token(trimmed) {
        return Some(TokenType::PayPalToken);
    }
    if is_mailgun_key(trimmed) {
        return Some(TokenType::MailgunToken);
    }
    if is_resend_key(trimmed) {
        return Some(TokenType::ResendToken);
    }
    if is_brevo_key(trimmed) {
        return Some(TokenType::BrevoToken);
    }
    if is_mailchimp_key(trimmed) {
        return Some(TokenType::MailchimpToken);
    }
    if is_aws_access_key(trimmed) {
        return Some(TokenType::AwsAccessKey);
    }
    if is_gcp_api_key(trimmed) {
        return Some(TokenType::GcpApiKey);
    }
    if is_azure_key(trimmed) {
        return Some(TokenType::AzureKey);
    }

    // 1Password tokens
    if is_onepassword_token(trimmed) {
        return Some(TokenType::OnePasswordServiceToken);
    }
    if is_onepassword_vault_ref(trimmed) {
        return Some(TokenType::OnePasswordVaultRef);
    }

    // Bearer tokens
    if is_bearer_token(trimmed) {
        return Some(TokenType::BearerToken);
    }

    // URL with embedded credentials
    if is_url_with_credentials(trimmed) {
        return Some(TokenType::UrlWithCredentials);
    }

    // SSH keys
    if is_ssh_private_key(trimmed) {
        return Some(TokenType::SshPrivateKey);
    }
    if is_ssh_public_key(trimmed) {
        return Some(TokenType::SshPublicKey);
    }
    if is_ssh_fingerprint(trimmed) {
        return Some(TokenType::SshFingerprint);
    }

    // JWT tokens (check before AWS secret key since JWTs have dots, AWS secrets don't)
    if is_jwt(trimmed) {
        return Some(TokenType::Jwt);
    }

    // AWS secret key (40 base64 chars - check after JWT to avoid false matches)
    if is_aws_secret_key(trimmed) {
        return Some(TokenType::AwsSecretKey);
    }

    // AWS session token (100+ base64 chars from STS)
    if is_aws_session_token(trimmed) {
        return Some(TokenType::AwsSessionToken);
    }

    // Generic API keys (less specific)
    if is_api_key(trimmed) {
        return Some(TokenType::GenericApiKey);
    }

    // Session IDs (heuristic, least specific)
    if is_likely_session_id(trimmed) {
        return Some(TokenType::SessionId);
    }

    None
}

/// Check if value is any type of token
///
/// Convenience function that returns true if any token pattern is detected.
#[must_use]
pub fn is_token_identifier(value: &str) -> bool {
    detect_token_type(value).is_some()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_detect_token_type() {
        // GitHub
        assert_eq!(
            detect_token_type("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"),
            Some(TokenType::GitHub)
        );

        // GitLab
        assert_eq!(
            detect_token_type("glpat-xxxxxxxxxxxxxxxxxxxx"),
            Some(TokenType::GitLab)
        );

        // AWS (constructed to avoid secret scanner false positives)
        let akia = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        assert_eq!(detect_token_type(&akia), Some(TokenType::AwsAccessKey));

        // Stripe
        assert_eq!(
            detect_token_type(&format!("sk_live_{}", "EXAMPLE000000000KEY01abcdef")),
            Some(TokenType::StripeKey)
        );

        // SSH
        assert_eq!(
            detect_token_type("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8..."),
            Some(TokenType::SshPublicKey)
        );

        // JWT
        assert_eq!(
            detect_token_type(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            ),
            Some(TokenType::Jwt)
        );

        // Session ID
        assert_eq!(
            detect_token_type("Ab3De8Gh2Jk5Mn9Pq4Rs7Tv0Wx3Yz6"),
            Some(TokenType::SessionId)
        );

        // Square
        assert_eq!(
            detect_token_type(&format!("sq0atp-{}", "ABCDEFghijklmnopqrstuv")),
            Some(TokenType::SquareToken)
        );

        // Shopify
        assert_eq!(
            detect_token_type(&format!("shpat_{}", "abcdef1234567890abcdef1234567890")),
            Some(TokenType::ShopifyToken)
        );

        // PayPal/Braintree
        assert_eq!(
            detect_token_type(&format!(
                "access_token$production${}${}",
                "abc1234567890xyz", "abcdef1234567890abcdef1234567890"
            )),
            Some(TokenType::PayPalToken)
        );

        // Mailchimp (constructed at runtime to avoid secret scanner)
        assert_eq!(
            detect_token_type(&format!("{}{}-us6", "abcdef1234567890", "abcdef1234567890")),
            Some(TokenType::MailchimpToken)
        );

        // Mailgun
        assert_eq!(
            detect_token_type(&format!("key-{}", "ABCDEFghijklmnopqrstuv1234567890")),
            Some(TokenType::MailgunToken)
        );

        // Resend
        assert_eq!(
            detect_token_type(&format!("re_{}", "ABCDEFghijklmnopqrstuv1234567890ab")),
            Some(TokenType::ResendToken)
        );

        // Brevo
        assert_eq!(
            detect_token_type(&format!("xkeysib-{}-{}", "a".repeat(64), "B".repeat(16))),
            Some(TokenType::BrevoToken)
        );

        // Not a token
        assert_eq!(detect_token_type("not-a-token"), None);
        assert_eq!(detect_token_type(""), None);
    }

    #[test]
    fn test_is_token_identifier() {
        // Should detect various token types
        assert!(is_token_identifier(
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        ));
        let akia = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        assert!(is_token_identifier(&akia));
        assert!(is_token_identifier(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8..."
        ));

        // Should reject non-tokens
        assert!(!is_token_identifier("not-a-token"));
        assert!(!is_token_identifier("regular text"));
        assert!(!is_token_identifier(""));
    }
}

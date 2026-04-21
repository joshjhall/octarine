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

use super::super::types::IdentifierType;

// Re-export types
pub use types::{ApiKeyProvider, JwtAlgorithm, TokenType};

// Re-export JWT functions
pub use jwt::{detect_jwt_algorithm, is_jwt, is_test_jwt};

// Re-export API key functions
pub use api_keys::{
    detect_api_key_provider, is_api_key, is_artifactory_token, is_aws_access_key,
    is_aws_secret_key, is_aws_session_token, is_azure_connection_string, is_azure_key,
    is_bearer_token, is_bitbucket_token, is_brevo_key, is_cloudflare_ca_key, is_databricks_token,
    is_discord_token, is_discord_webhook, is_docker_hub_token, is_firebase_fcm_key, is_gcp_api_key,
    is_gcp_oauth_client_secret, is_gcp_service_account, is_gcp_service_account_email,
    is_github_token, is_gitlab_token, is_mailchimp_key, is_mailgun_key, is_npm_token, is_nuget_key,
    is_onepassword_token, is_onepassword_vault_ref, is_openai_key, is_paypal_token, is_pypi_token,
    is_resend_key, is_sendgrid_key, is_shopify_token, is_slack_token, is_slack_webhook,
    is_square_token, is_stripe_key, is_telegram_bot_token, is_test_api_key, is_twilio_account_sid,
    is_twilio_api_key_sid, is_url_with_credentials, is_vault_token,
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
    if is_bitbucket_token(trimmed) {
        return Some(TokenType::BitbucketToken);
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
    if is_databricks_token(trimmed) {
        return Some(TokenType::DatabricksToken);
    }
    if is_vault_token(trimmed) {
        return Some(TokenType::VaultToken);
    }
    if is_cloudflare_ca_key(trimmed) {
        return Some(TokenType::CloudflareOriginCaKey);
    }
    if is_npm_token(trimmed) {
        return Some(TokenType::NpmToken);
    }
    if is_pypi_token(trimmed) {
        return Some(TokenType::PyPiToken);
    }
    if is_nuget_key(trimmed) {
        return Some(TokenType::NuGetKey);
    }
    if is_artifactory_token(trimmed) {
        return Some(TokenType::ArtifactoryToken);
    }
    if is_docker_hub_token(trimmed) {
        return Some(TokenType::DockerHubToken);
    }
    if is_telegram_bot_token(trimmed) {
        return Some(TokenType::TelegramToken);
    }
    if is_discord_token(trimmed) || is_discord_webhook(trimmed) {
        return Some(TokenType::DiscordToken);
    }
    if is_slack_token(trimmed) || is_slack_webhook(trimmed) {
        return Some(TokenType::SlackToken);
    }
    if is_twilio_account_sid(trimmed) || is_twilio_api_key_sid(trimmed) {
        return Some(TokenType::TwilioToken);
    }
    if is_sendgrid_key(trimmed) {
        return Some(TokenType::SendGridToken);
    }
    if is_openai_key(trimmed) {
        return Some(TokenType::OpenAiKey);
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

/// Detect token identifier type (dual-API contract).
///
/// Companion to [`is_token_identifier`] that returns the matched
/// `IdentifierType`. Internally dispatches via [`detect_token_type`] and
/// maps the richer `TokenType` enum to the cross-domain `IdentifierType`:
///
/// - Dedicated variants (`Jwt`, `GitHub` → `GitHubToken`, `GitLab` →
///   `GitLabToken`, `AwsAccessKey`, `AwsSessionToken`, `SessionId`,
///   `SshKey`, `OnePasswordToken`, `OnePasswordVaultRef`, `BearerToken`,
///   `UrlWithCredentials`) map directly.
/// - `AwsSecretKey` maps to `HighEntropyString` — AWS secrets have no
///   dedicated variant and match the `From<IdentifierType>` bridge
///   fallback in `observe/pii/types.rs`.
/// - All other provider-specific tokens (Stripe, Square, Shopify, Mailgun,
///   Discord, Slack, Telegram, OpenAI, etc.) map to `ApiKey`.
#[must_use]
pub fn detect_token_identifier(value: &str) -> Option<IdentifierType> {
    let token_type = detect_token_type(value)?;
    Some(match token_type {
        TokenType::Jwt => IdentifierType::Jwt,
        TokenType::GitHub => IdentifierType::GitHubToken,
        TokenType::GitLab => IdentifierType::GitLabToken,
        TokenType::AwsAccessKey => IdentifierType::AwsAccessKey,
        TokenType::AwsSessionToken => IdentifierType::AwsSessionToken,
        TokenType::SessionId => IdentifierType::SessionId,
        TokenType::UrlWithCredentials => IdentifierType::UrlWithCredentials,
        TokenType::SshPrivateKey | TokenType::SshPublicKey | TokenType::SshFingerprint => {
            IdentifierType::SshKey
        }
        TokenType::OnePasswordServiceToken => IdentifierType::OnePasswordToken,
        TokenType::OnePasswordVaultRef => IdentifierType::OnePasswordVaultRef,
        TokenType::BearerToken => IdentifierType::BearerToken,
        // AWS secret keys have no dedicated variant; HighEntropyString
        // matches the observe/pii/types.rs bridge fallback.
        TokenType::AwsSecretKey => IdentifierType::HighEntropyString,
        // All remaining provider-specific tokens collapse to the generic
        // ApiKey variant.
        TokenType::GcpApiKey
        | TokenType::AzureKey
        | TokenType::StripeKey
        | TokenType::GenericApiKey
        | TokenType::SquareToken
        | TokenType::PayPalToken
        | TokenType::ShopifyToken
        | TokenType::MailchimpToken
        | TokenType::MailgunToken
        | TokenType::ResendToken
        | TokenType::BrevoToken
        | TokenType::DatabricksToken
        | TokenType::VaultToken
        | TokenType::CloudflareOriginCaKey
        | TokenType::NpmToken
        | TokenType::PyPiToken
        | TokenType::NuGetKey
        | TokenType::ArtifactoryToken
        | TokenType::DockerHubToken
        | TokenType::TelegramToken
        | TokenType::DiscordToken
        | TokenType::SlackToken
        | TokenType::TwilioToken
        | TokenType::SendGridToken
        | TokenType::OpenAiKey
        | TokenType::BitbucketToken => IdentifierType::ApiKey,
    })
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

        // Databricks
        assert_eq!(
            detect_token_type(&format!("dapi{}", "a".repeat(32))),
            Some(TokenType::DatabricksToken)
        );

        // Vault
        assert_eq!(
            detect_token_type(&format!("hvs.{}", "A".repeat(24))),
            Some(TokenType::VaultToken)
        );

        // Cloudflare Origin CA
        assert_eq!(
            detect_token_type(&format!("v1.0-{}-{}", "a".repeat(24), "b".repeat(146))),
            Some(TokenType::CloudflareOriginCaKey)
        );

        // NPM
        assert_eq!(
            detect_token_type(&format!("npm_{}", "A".repeat(36))),
            Some(TokenType::NpmToken)
        );

        // PyPI
        assert_eq!(
            detect_token_type(&format!("pypi-AgEIcHlwaS5vcmc{}", "A".repeat(50))),
            Some(TokenType::PyPiToken)
        );

        // NuGet
        assert_eq!(
            detect_token_type(&format!("oy2{}", "a".repeat(43))),
            Some(TokenType::NuGetKey)
        );

        // Artifactory
        assert_eq!(
            detect_token_type(&format!("AKC{}", "a".repeat(10))),
            Some(TokenType::ArtifactoryToken)
        );

        // Docker Hub
        assert_eq!(
            detect_token_type(&format!("dckr_pat_{}", "A".repeat(27))),
            Some(TokenType::DockerHubToken)
        );

        // Telegram
        assert_eq!(
            detect_token_type(&format!("12345678:{}", "A".repeat(35))),
            Some(TokenType::TelegramToken)
        );

        // Discord bot token
        assert_eq!(
            detect_token_type(&format!(
                "M{}.{}.{}",
                "A".repeat(23),
                "AbCdEf",
                "a".repeat(27)
            )),
            Some(TokenType::DiscordToken)
        );

        // Discord webhook URL
        assert_eq!(
            detect_token_type(
                "https://discord.com/api/webhooks/123456789/abcdefABCDEF_-0123456789"
            ),
            Some(TokenType::DiscordToken)
        );

        // Slack bot token
        assert_eq!(
            detect_token_type(&format!("xoxb-{}-{}", "1".repeat(12), "A".repeat(24))),
            Some(TokenType::SlackToken)
        );

        // Twilio Account SID
        assert_eq!(
            detect_token_type(&format!("AC{}", "a".repeat(32))),
            Some(TokenType::TwilioToken)
        );

        // SendGrid
        assert_eq!(
            detect_token_type(&format!("SG.{}.{}", "A".repeat(22), "b".repeat(43))),
            Some(TokenType::SendGridToken)
        );

        // OpenAI
        assert_eq!(
            detect_token_type(&format!("sk-{}T3BlbkFJ{}", "A".repeat(20), "B".repeat(20))),
            Some(TokenType::OpenAiKey)
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

    #[test]
    fn test_detect_token_identifier() {
        // Dedicated mappings (tokens constructed at runtime to avoid
        // triggering secret scanners on literal high-entropy strings).
        let ghp = format!("{}{}", "ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        assert_eq!(
            detect_token_identifier(&ghp),
            Some(IdentifierType::GitHubToken)
        );
        assert_eq!(
            detect_token_identifier("glpat-xxxxxxxxxxxxxxxxxxxx"),
            Some(IdentifierType::GitLabToken)
        );
        let akia = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        assert_eq!(
            detect_token_identifier(&akia),
            Some(IdentifierType::AwsAccessKey)
        );
        let jwt = format!(
            "{}.{}.{}",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        );
        assert_eq!(detect_token_identifier(&jwt), Some(IdentifierType::Jwt));
        assert_eq!(
            detect_token_identifier("Ab3De8Gh2Jk5Mn9Pq4Rs7Tv0Wx3Yz6"),
            Some(IdentifierType::SessionId)
        );

        // SSH keys/fingerprints map to dedicated SshKey variant
        assert_eq!(
            detect_token_identifier("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8..."),
            Some(IdentifierType::SshKey)
        );

        // 1Password tokens and vault references
        let op_token = format!(
            "ops_{}",
            "eyJzaWduSW5BZGRyZXNzIjoiaHR0cHM6Ly9teS4xcGFzc3dvcmQuY29tIiwidXNlckF1dGgiOiJ5"
        );
        assert_eq!(
            detect_token_identifier(&op_token),
            Some(IdentifierType::OnePasswordToken)
        );
        assert_eq!(
            detect_token_identifier("op://Production/Database/password"),
            Some(IdentifierType::OnePasswordVaultRef)
        );

        // Bearer tokens
        assert_eq!(
            detect_token_identifier(&format!(
                "Bearer {}",
                "abcdefghijklmnopqrstuvwxyz0123456789"
            )),
            Some(IdentifierType::BearerToken)
        );

        // URLs with embedded credentials
        assert_eq!(
            detect_token_identifier("https://user:pass@example.com/path"),
            Some(IdentifierType::UrlWithCredentials)
        );

        // Provider-specific tokens collapse to ApiKey
        assert_eq!(
            detect_token_identifier(&format!("sk_live_{}", "EXAMPLE000000000KEY01abcdef")),
            Some(IdentifierType::ApiKey)
        );
        assert_eq!(
            detect_token_identifier(&format!("shpat_{}", "abcdef1234567890abcdef1234567890")),
            Some(IdentifierType::ApiKey)
        );

        // Non-tokens
        assert_eq!(detect_token_identifier("not-a-token"), None);
        assert_eq!(detect_token_identifier(""), None);
    }
}

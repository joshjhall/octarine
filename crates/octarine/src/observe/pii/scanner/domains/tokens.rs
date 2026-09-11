//! Token, secret, and credential scanning (API keys, JWT, passwords, etc.)
//!
//! Part of the PII scanner domain split (issue #411).
//!
//! Credential detection (passwords, PINs, security answers, passphrases,
//! connection strings) deliberately lives here rather than in a separate
//! `credentials` module, unlike the sibling `redactor/` layout: the credential
//! checks share `scan_tokens`'s `provider_matched` suppression state, and
//! threading that across a module boundary is where a silent detection
//! regression would hide.

use super::super::super::types::PiiType;
use crate::primitives::identifiers::{
    CredentialIdentifierBuilder, TokenIdentifierBuilder, TokenType,
};

/// Scan for tokens and secrets (API keys, JWT, passwords, etc.)
pub(super) fn scan_tokens(text: &str, pii_types: &mut Vec<PiiType>) {
    let token = TokenIdentifierBuilder::new();

    // Provider-specific token attribution. Iterate whitespace-split words and
    // dispatch through detect_token_type so each provider gets its own PiiType
    // variant (issue #97). Suppress the generic ApiKey emission when any
    // provider matched — it is reserved for unrecognized api-key-shaped input.
    let mut provider_matched = false;
    for word in text.split_whitespace() {
        // Strip surrounding shell punctuation (quotes, commas, parens, colons,
        // semicolons) but preserve characters that appear inside provider
        // tokens: `-` `_` `.` (separators) and `=` (base64 padding, e.g.
        // Azure `AccountKey=...==`).
        let trimmed = word.trim_matches(|c: char| {
            !c.is_alphanumeric() && c != '-' && c != '_' && c != '.' && c != '='
        });
        if trimmed.is_empty() {
            continue;
        }
        if let Some(token_type) = token.detect_token_type(trimmed)
            && let Some(pii) = token_type_to_pii(token_type)
        {
            pii_types.push(pii);
            provider_matched = true;
        }
    }

    // Generic ApiKey fallback: only when no provider-specific match.
    if !provider_matched
        && (token.is_api_key(text) || token.redact_api_keys_in_text(text).as_ref() != text)
    {
        pii_types.push(PiiType::ApiKey);
    }

    // JWT
    if token.is_jwt(text) || token.redact_jwts_in_text(text).as_ref() != text {
        pii_types.push(PiiType::Jwt);
    }

    // Session IDs
    if token.is_likely_session_id(text) {
        pii_types.push(PiiType::SessionId);
    }

    // SSH keys
    if token.is_ssh_key(text) || token.redact_ssh_keys_in_text(text).as_ref() != text {
        pii_types.push(PiiType::SshKey);
    }

    // 1Password tokens
    if token.is_onepassword_token(text) {
        pii_types.push(PiiType::OnePasswordToken);
    }

    // 1Password vault references
    if token.is_onepassword_vault_ref(text) {
        pii_types.push(PiiType::OnePasswordVaultRef);
    }

    // Bearer tokens
    if token.is_bearer_token(text) {
        pii_types.push(PiiType::BearerToken);
    }

    // URLs with credentials
    if token.is_url_with_credentials(text) {
        pii_types.push(PiiType::UrlWithCredentials);
    }

    // Credentials
    let credential = CredentialIdentifierBuilder::new();

    // Connection strings with credentials (MSSQL, JDBC, database URLs)
    if credential.is_connection_string_with_credentials(text) {
        pii_types.push(PiiType::ConnectionString);
    }

    // Framework-style credentials (Django, Rails YAML, .env, Docker Compose).
    // Mapped to ConnectionString since they identify the same kind of secret —
    // database access credentials in application configuration.
    if credential.is_framework_credential_present(text)
        && !pii_types.contains(&PiiType::ConnectionString)
    {
        pii_types.push(PiiType::ConnectionString);
    }

    if credential.is_passwords_present(text) {
        pii_types.push(PiiType::Password);
    }
    if credential.is_pins_present(text) {
        pii_types.push(PiiType::Pin);
    }
    if credential.is_security_answers_present(text) {
        pii_types.push(PiiType::SecurityAnswer);
    }
    if credential.is_passphrases_present(text) {
        pii_types.push(PiiType::Passphrase);
    }
}

/// Map a detected `TokenType` to the corresponding provider-specific
/// `PiiType` variant.
///
/// Returns `None` for token types that are already handled by sibling
/// dispatches in `scan_tokens` (Jwt, SessionId, SshKey*, OnePassword*,
/// BearerToken, UrlWithCredentials) so they are not double-emitted, and for
/// `GenericApiKey` (handled by the trailing fallback). `AwsSecretKey` maps
/// to `ApiKey` because AWS secret keys are 40 base64 chars and
/// indistinguishable from random high-entropy strings — a dedicated variant
/// would create false positives.
fn token_type_to_pii(t: TokenType) -> Option<PiiType> {
    Some(match t {
        TokenType::GitHub => PiiType::GitHubToken,
        TokenType::GitLab => PiiType::GitLabToken,
        TokenType::BitbucketToken => PiiType::BitbucketToken,
        TokenType::AwsAccessKey => PiiType::AwsAccessKey,
        TokenType::AwsSessionToken => PiiType::AwsSessionToken,
        TokenType::AwsSecretKey => PiiType::ApiKey,
        TokenType::GcpApiKey => PiiType::GcpApiKey,
        TokenType::AzureKey => PiiType::AzureKey,
        TokenType::StripeKey => PiiType::StripeKey,
        TokenType::SquareToken => PiiType::SquareToken,
        TokenType::ShopifyToken => PiiType::ShopifyToken,
        TokenType::PayPalToken => PiiType::PayPalToken,
        TokenType::MailchimpToken => PiiType::MailchimpToken,
        TokenType::MailgunToken => PiiType::MailgunToken,
        TokenType::ResendToken => PiiType::ResendToken,
        TokenType::BrevoToken => PiiType::BrevoToken,
        TokenType::DatabricksToken => PiiType::DatabricksToken,
        TokenType::VaultToken => PiiType::VaultToken,
        TokenType::CloudflareOriginCaKey => PiiType::CloudflareOriginCaKey,
        TokenType::NpmToken => PiiType::NpmToken,
        TokenType::PyPiToken => PiiType::PyPiToken,
        TokenType::NuGetKey => PiiType::NuGetKey,
        TokenType::ArtifactoryToken => PiiType::ArtifactoryToken,
        TokenType::DockerHubToken => PiiType::DockerHubToken,
        TokenType::TelegramToken => PiiType::TelegramToken,
        TokenType::SendGridToken => PiiType::SendGridToken,
        TokenType::OpenAiKey => PiiType::OpenAiKey,
        TokenType::DiscordToken => PiiType::DiscordToken,
        TokenType::SlackToken => PiiType::SlackToken,
        TokenType::TwilioToken => PiiType::TwilioToken,
        TokenType::HerokuToken => PiiType::HerokuToken,
        TokenType::LinearToken => PiiType::LinearToken,
        TokenType::DopplerToken => PiiType::DopplerToken,
        TokenType::NetlifyToken => PiiType::NetlifyToken,
        TokenType::FlyIoToken => PiiType::FlyIoToken,
        TokenType::RenderToken => PiiType::RenderToken,
        TokenType::PlanetScaleToken => PiiType::PlanetScaleToken,
        TokenType::SupabaseToken => PiiType::SupabaseToken,
        // Already handled by sibling dispatches in scan_tokens — return
        // None to avoid double-emission.
        TokenType::Jwt
        | TokenType::SessionId
        | TokenType::UrlWithCredentials
        | TokenType::SshPrivateKey
        | TokenType::SshPublicKey
        | TokenType::SshFingerprint
        | TokenType::OnePasswordServiceToken
        | TokenType::OnePasswordVaultRef
        | TokenType::BearerToken
        // Generic api-key shape — emit ApiKey via the trailing fallback so
        // it is suppressed when a provider-specific match exists in the
        // same text.
        | TokenType::GenericApiKey => return None,
    })
}

/// Coarse pre-filter for the token domain.
///
/// Keeps the trailing lowercase-`password` heuristic: it catches
/// `password=`/`password:` text that the builder predicates alone miss.
pub(super) fn is_token_present(text: &str) -> bool {
    let token = TokenIdentifierBuilder::new();
    if token.is_token_identifier(text)
        || token.is_jwt(text)
        || token.is_api_key(text)
        || token.is_ssh_key(text)
        || token.is_onepassword_token(text)
        || token.is_onepassword_vault_ref(text)
        || token.is_bearer_token(text)
        || token.is_url_with_credentials(text)
    {
        return true;
    }

    // Password detection
    text.to_lowercase().contains("password")
        && (text.contains('=') || text.contains(':') || text.contains(' '))
}

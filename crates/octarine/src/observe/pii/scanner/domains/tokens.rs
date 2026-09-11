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
/// Independent token predicates: each is a self-contained "is this present?"
/// check that pushes one `PiiType`. Table-driven so the checks stay a flat
/// list rather than a branch chain (issue #411).
type TokenCheck = fn(&TokenIdentifierBuilder, &str) -> bool;
const TOKEN_CHECKS: &[(TokenCheck, PiiType)] = &[
    (
        |t, text| t.is_jwt(text) || t.redact_jwts_in_text(text).as_ref() != text,
        PiiType::Jwt,
    ),
    (
        TokenIdentifierBuilder::is_likely_session_id,
        PiiType::SessionId,
    ),
    (
        |t, text| t.is_ssh_key(text) || t.redact_ssh_keys_in_text(text).as_ref() != text,
        PiiType::SshKey,
    ),
    (
        TokenIdentifierBuilder::is_onepassword_token,
        PiiType::OnePasswordToken,
    ),
    (
        TokenIdentifierBuilder::is_onepassword_vault_ref,
        PiiType::OnePasswordVaultRef,
    ),
    (
        TokenIdentifierBuilder::is_bearer_token,
        PiiType::BearerToken,
    ),
    (
        TokenIdentifierBuilder::is_url_with_credentials,
        PiiType::UrlWithCredentials,
    ),
];

/// Independent credential predicates, same shape as [`TOKEN_CHECKS`].
///
/// Covers only the checks that run AFTER the connection-string pair in
/// [`scan_tokens`]; the connection-string and framework-credential checks stay
/// inline because the framework one is conditional on `ConnectionString` not
/// already having been pushed, and their relative position is load-bearing for
/// the order of the emitted `PiiType`s.
type CredentialCheck = fn(&CredentialIdentifierBuilder, &str) -> bool;
const CREDENTIAL_CHECKS: &[(CredentialCheck, PiiType)] = &[
    (
        CredentialIdentifierBuilder::is_passwords_present,
        PiiType::Password,
    ),
    (CredentialIdentifierBuilder::is_pins_present, PiiType::Pin),
    (
        CredentialIdentifierBuilder::is_security_answers_present,
        PiiType::SecurityAnswer,
    ),
    (
        CredentialIdentifierBuilder::is_passphrases_present,
        PiiType::Passphrase,
    ),
];

/// Attribute provider-specific tokens word by word.
///
/// Iterates whitespace-split words and dispatches through `detect_token_type`
/// so each provider gets its own `PiiType` variant (issue #97).
///
/// Returns `true` if any provider matched, which suppresses the generic
/// `ApiKey` emission in [`scan_tokens`] — that variant is reserved for
/// unrecognized api-key-shaped input.
fn scan_provider_tokens(
    token: &TokenIdentifierBuilder,
    text: &str,
    pii_types: &mut Vec<PiiType>,
) -> bool {
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

    provider_matched
}

/// Scan for tokens and secrets (API keys, JWT, passwords, etc.)
pub(super) fn scan_tokens(text: &str, pii_types: &mut Vec<PiiType>) {
    let token = TokenIdentifierBuilder::new();

    let provider_matched = scan_provider_tokens(&token, text, pii_types);

    // Generic ApiKey fallback: only when no provider-specific match.
    if !provider_matched
        && (token.is_api_key(text) || token.redact_api_keys_in_text(text).as_ref() != text)
    {
        pii_types.push(PiiType::ApiKey);
    }

    for &(check, pii_type) in TOKEN_CHECKS {
        if check(&token, text) {
            pii_types.push(pii_type);
        }
    }

    let credential = CredentialIdentifierBuilder::new();

    // Connection strings with credentials (MSSQL, JDBC, database URLs)
    if credential.is_connection_string_with_credentials(text) {
        pii_types.push(PiiType::ConnectionString);
    }

    // Framework-style credentials (Django, Rails YAML, .env, Docker Compose).
    // Mapped to ConnectionString since they identify the same kind of secret —
    // database access credentials in application configuration. Conditional on
    // ConnectionString not already being present, so it stays out of the table
    // above and keeps its original position in the push order.
    if credential.is_framework_credential_present(text)
        && !pii_types.contains(&PiiType::ConnectionString)
    {
        pii_types.push(PiiType::ConnectionString);
    }

    for &(check, pii_type) in CREDENTIAL_CHECKS {
        if check(&credential, text) {
            pii_types.push(pii_type);
        }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    /// The trim closure must preserve base64 `=` padding while stripping a
    /// wrapping comma — an Azure `AccountKey=...==` inside a shell-ish line is
    /// the case the closure's comment calls out.
    ///
    /// Asserts on the provider variant specifically: a trim that ate the `=`
    /// padding would no longer match the Azure shape, so `AzureKey` is the
    /// element that disappears.
    #[test]
    fn test_provider_token_wrapped_in_punctuation_is_still_detected() {
        // Exactly 88 base64 chars ending in `==`, the length the Azure
        // pattern requires. Strip that padding and it is 86 chars and no
        // longer matches — which is what makes this input discriminating
        // rather than decorative.
        let bare = "AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwx==";
        let wrapped = format!("\"{bare}\",");

        let mut bare_types = Vec::new();
        scan_tokens(bare, &mut bare_types);
        assert!(
            bare_types.contains(&PiiType::AzureKey),
            "precondition: bare Azure key should be attributed, got {bare_types:?}"
        );

        let mut wrapped_types = Vec::new();
        scan_tokens(&wrapped, &mut wrapped_types);
        assert!(
            wrapped_types.contains(&PiiType::AzureKey),
            "wrapping punctuation lost the Azure attribution: {wrapped_types:?} \
             (the trim closure must strip the quote/comma but keep the `==` padding)"
        );
        assert_eq!(
            bare_types, wrapped_types,
            "wrapping punctuation changed detection: bare={bare_types:?} wrapped={wrapped_types:?}"
        );
    }

    /// Words that trim away to nothing must hit the `is_empty` guard rather
    /// than panicking or emitting a match.
    #[test]
    fn test_punctuation_only_words_are_skipped() {
        let mut pii_types = Vec::new();
        scan_tokens(" , ;; () \"\" :: ", &mut pii_types);
        assert!(
            pii_types.is_empty(),
            "punctuation-only input produced {pii_types:?}"
        );
    }

    /// Every table row must be reachable: a check wired to the wrong predicate
    /// would emit the wrong `PiiType` here.
    #[test]
    fn test_token_check_table_emits_its_mapped_type() {
        let token = TokenIdentifierBuilder::new();
        let sample = "Bearer abcdefghijklmnopqrstuvwxyz0123456789";
        let matched: Vec<PiiType> = TOKEN_CHECKS
            .iter()
            .filter(|(check, _)| check(&token, sample))
            .map(|(_, pii)| *pii)
            .collect();
        assert!(
            matched.contains(&PiiType::BearerToken),
            "bearer sample matched {matched:?}, expected BearerToken among them"
        );
    }

    /// The framework-credential check must not double-push `ConnectionString`
    /// when the connection-string check already emitted it.
    #[test]
    fn test_connection_string_is_not_double_emitted() {
        let text = "DATABASE_URL=postgres://admin:s3cr3tpassword@db.example.com:5432/appdb";
        let mut pii_types = Vec::new();
        scan_tokens(text, &mut pii_types);
        let count = pii_types
            .iter()
            .filter(|p| **p == PiiType::ConnectionString)
            .count();
        assert!(
            count <= 1,
            "ConnectionString emitted {count} times: {pii_types:?}"
        );
    }
}

//! Token identifier sanitization (primitives layer)
//!
//! Pure sanitization functions for token identifiers with NO logging.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Security Considerations
//!
//! Token sanitization is critical for:
//! - **PCI DSS**: Redacting API keys in logs
//! - **OWASP A01:2021**: Preventing token exposure
//! - **Compliance**: SOC2, HIPAA logging requirements
//!
//! # Functions Overview
//!
//! - **Individual redaction**: `redact_jwt()`, `redact_api_key()`, `redact_session_id()`, etc.
//! - **Text redaction**: `redact_jwts_in_text()`, `redact_api_keys_in_text()`, etc.
//! - **Masking**: `mask_jwt()`, `mask_api_key()`, `mask_session_id()`, etc.

use super::super::types::IdentifierMatch;
use super::{detection, redaction};
use crate::primitives::data::tokens::RedactionTokenCore;
use std::borrow::Cow;

// Re-export redaction strategies for convenience
pub use redaction::{
    ApiKeyRedactionStrategy, JwtRedactionStrategy, SessionIdRedactionStrategy,
    SshFingerprintRedactionStrategy, SshKeyRedactionStrategy, TextRedactionPolicy,
};

// ============================================================================
// Individual Redaction Functions (NEW)
// ============================================================================

/// Redact a single JWT
///
/// Applies strategy-based redaction to a JWT token.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::{redact_jwt, JwtRedactionStrategy};
///
/// let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
/// let redacted = redact_jwt(jwt, JwtRedactionStrategy::Token);
/// assert_eq!(redacted, "[JWT]");
/// ```
#[must_use]
pub fn redact_jwt(jwt: &str, strategy: JwtRedactionStrategy) -> String {
    if matches!(strategy, JwtRedactionStrategy::Skip) {
        return jwt.to_string();
    }

    let is_valid = detection::is_jwt(jwt);

    match strategy {
        JwtRedactionStrategy::Skip => jwt.to_string(),
        JwtRedactionStrategy::ShowAlgorithm => {
            if !is_valid {
                return RedactionTokenCore::Jwt.into();
            }
            // Try to extract algorithm (would need detect_jwt_algorithm after move)
            // For now, just use token
            RedactionTokenCore::Jwt.into()
        }
        JwtRedactionStrategy::ShowHeader => {
            if !is_valid {
                return RedactionTokenCore::Jwt.into();
            }
            if let Some(dot_pos) = jwt.find('.') {
                format!("{}....", &jwt[..dot_pos])
            } else {
                RedactionTokenCore::Jwt.into()
            }
        }
        JwtRedactionStrategy::Token => RedactionTokenCore::Jwt.into(),
        JwtRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        JwtRedactionStrategy::Asterisks => {
            if is_valid {
                "*".repeat(jwt.len())
            } else {
                RedactionTokenCore::Jwt.into()
            }
        }
        JwtRedactionStrategy::Hashes => {
            if is_valid {
                "#".repeat(jwt.len())
            } else {
                RedactionTokenCore::Jwt.into()
            }
        }
    }
}

/// Redact a single API key
///
/// Applies strategy-based redaction to an API key.
#[must_use]
pub fn redact_api_key(key: &str, strategy: ApiKeyRedactionStrategy) -> String {
    if matches!(strategy, ApiKeyRedactionStrategy::Skip) {
        return key.to_string();
    }

    let is_valid = detection::is_api_key(key);

    match strategy {
        ApiKeyRedactionStrategy::Skip => key.to_string(),
        ApiKeyRedactionStrategy::ShowProvider => {
            // Check provider patterns first (even for invalid keys)
            if key.starts_with("sk_") || key.starts_with("pk_") || key.starts_with("rk_") {
                RedactionTokenCore::StripeKey.into()
            } else if key.starts_with("AKIA") {
                RedactionTokenCore::AwsKey.into()
            } else if key.starts_with("ghp_")
                || key.starts_with("gho_")
                || key.starts_with("ghs_")
                || key.starts_with("ghr_")
            {
                RedactionTokenCore::GithubToken.into()
            } else if key.starts_with("AIza") {
                RedactionTokenCore::GcpKey.into()
            } else if key.starts_with("GOCSPX-") {
                RedactionTokenCore::GcpOAuthSecret.into()
            } else if key.starts_with("AAAA") && key.len() >= 144 {
                RedactionTokenCore::FirebaseFcmKey.into()
            } else if key.contains("\"service_account\"") {
                RedactionTokenCore::GcpServiceAccount.into()
            } else if !is_valid {
                RedactionTokenCore::ApiKey.into()
            } else {
                // Valid but unknown provider
                RedactionTokenCore::ApiKey.into()
            }
        }
        ApiKeyRedactionStrategy::ShowPrefix => {
            // Try to show prefix even for invalid keys
            if let Some(pos) = key.rfind('_') {
                if pos < key.len() {
                    format!("{}****", &key[..=pos])
                } else {
                    RedactionTokenCore::ApiKey.into()
                }
            } else if key.len() >= 8 {
                format!("{}****", &key[..8])
            } else if !is_valid {
                RedactionTokenCore::ApiKey.into()
            } else {
                // Valid but no underscore and too short
                RedactionTokenCore::ApiKey.into()
            }
        }
        ApiKeyRedactionStrategy::Mask => mask_api_key(key),
        ApiKeyRedactionStrategy::Token => RedactionTokenCore::ApiKey.into(),
        ApiKeyRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        ApiKeyRedactionStrategy::Asterisks => {
            if is_valid {
                "*".repeat(key.len())
            } else {
                RedactionTokenCore::ApiKey.into()
            }
        }
        ApiKeyRedactionStrategy::Hashes => {
            if is_valid {
                "#".repeat(key.len())
            } else {
                RedactionTokenCore::ApiKey.into()
            }
        }
    }
}

/// Redact a single session ID
///
/// Applies strategy-based redaction to a session identifier.
#[must_use]
pub fn redact_session_id(session_id: &str, strategy: SessionIdRedactionStrategy) -> String {
    if matches!(strategy, SessionIdRedactionStrategy::Skip) {
        return session_id.to_string();
    }

    let is_valid = detection::is_likely_session_id(session_id);

    match strategy {
        SessionIdRedactionStrategy::Skip => session_id.to_string(),
        SessionIdRedactionStrategy::ShowPrefix => {
            if !is_valid {
                return RedactionTokenCore::Session.into();
            }
            if session_id.len() >= 8 {
                format!("{}****", &session_id[..8])
            } else {
                RedactionTokenCore::Session.into()
            }
        }
        SessionIdRedactionStrategy::Token => RedactionTokenCore::Session.into(),
        SessionIdRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        SessionIdRedactionStrategy::Asterisks => {
            if is_valid {
                "*".repeat(session_id.len())
            } else {
                RedactionTokenCore::Session.into()
            }
        }
        SessionIdRedactionStrategy::Hashes => {
            if is_valid {
                "#".repeat(session_id.len())
            } else {
                RedactionTokenCore::Session.into()
            }
        }
    }
}

/// Redact a single SSH key
///
/// Applies strategy-based redaction to an SSH key (public or private).
#[must_use]
pub fn redact_ssh_key(key: &str, strategy: SshKeyRedactionStrategy) -> String {
    if matches!(strategy, SshKeyRedactionStrategy::Skip) {
        return key.to_string();
    }

    let is_valid = detection::is_ssh_key(key);

    match strategy {
        SshKeyRedactionStrategy::Skip => key.to_string(),
        SshKeyRedactionStrategy::ShowType => {
            if !is_valid {
                return RedactionTokenCore::SshKey.into();
            }
            // Extract key type from beginning
            if key.starts_with("ssh-rsa ") {
                "<ssh-rsa>".to_string()
            } else if key.starts_with("ssh-ed25519 ") {
                "<ssh-ed25519>".to_string()
            } else if key.starts_with("ecdsa-sha2-nistp256 ") {
                "<ecdsa-sha2-nistp256>".to_string()
            } else if key.starts_with("ecdsa-sha2-nistp384 ") {
                "<ecdsa-sha2-nistp384>".to_string()
            } else if key.starts_with("ecdsa-sha2-nistp521 ") {
                "<ecdsa-sha2-nistp521>".to_string()
            } else if key.contains("BEGIN RSA PRIVATE KEY") {
                RedactionTokenCore::RsaPrivateKey.into()
            } else if key.contains("BEGIN OPENSSH PRIVATE KEY") {
                RedactionTokenCore::OpensshPrivateKey.into()
            } else {
                RedactionTokenCore::SshKey.into()
            }
        }
        SshKeyRedactionStrategy::ShowFingerprint => {
            // Would need fingerprint calculation - use token for now
            RedactionTokenCore::SshKey.into()
        }
        SshKeyRedactionStrategy::Token => RedactionTokenCore::SshKey.into(),
        SshKeyRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        SshKeyRedactionStrategy::Asterisks => {
            if is_valid {
                "*".repeat(key.len().min(100)) // Cap asterisks for long keys
            } else {
                RedactionTokenCore::SshKey.into()
            }
        }
        SshKeyRedactionStrategy::Hashes => {
            if is_valid {
                "#".repeat(key.len().min(100)) // Cap hashes for long keys
            } else {
                RedactionTokenCore::SshKey.into()
            }
        }
    }
}

/// Redact a single SSH fingerprint
///
/// Applies strategy-based redaction to an SSH fingerprint.
#[must_use]
pub fn redact_ssh_fingerprint(
    fingerprint: &str,
    strategy: SshFingerprintRedactionStrategy,
) -> String {
    if matches!(strategy, SshFingerprintRedactionStrategy::Skip) {
        return fingerprint.to_string();
    }

    let is_valid = detection::is_ssh_fingerprint(fingerprint);

    match strategy {
        SshFingerprintRedactionStrategy::Skip => fingerprint.to_string(),
        SshFingerprintRedactionStrategy::ShowType => {
            if !is_valid {
                return RedactionTokenCore::SshFingerprint.into();
            }
            if fingerprint.starts_with("MD5:") {
                "<MD5>".to_string()
            } else if fingerprint.starts_with("SHA256:") {
                "<SHA256>".to_string()
            } else {
                RedactionTokenCore::SshFingerprint.into()
            }
        }
        SshFingerprintRedactionStrategy::Token => RedactionTokenCore::SshFingerprint.into(),
        SshFingerprintRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        SshFingerprintRedactionStrategy::Asterisks => {
            if is_valid {
                "*".repeat(fingerprint.len())
            } else {
                RedactionTokenCore::SshFingerprint.into()
            }
        }
        SshFingerprintRedactionStrategy::Hashes => {
            if is_valid {
                "#".repeat(fingerprint.len())
            } else {
                RedactionTokenCore::SshFingerprint.into()
            }
        }
    }
}

// Provider-specific convenience functions
/// Redact AWS access key
#[must_use]
pub fn redact_aws_key(key: &str, strategy: ApiKeyRedactionStrategy) -> String {
    redact_api_key(key, strategy)
}

/// Redact GitHub token
#[must_use]
pub fn redact_github_token(token: &str, strategy: ApiKeyRedactionStrategy) -> String {
    redact_api_key(token, strategy)
}

/// Redact Stripe key
#[must_use]
pub fn redact_stripe_key(key: &str, strategy: ApiKeyRedactionStrategy) -> String {
    redact_api_key(key, strategy)
}

/// Redact GCP API key
#[must_use]
pub fn redact_gcp_key(key: &str, strategy: ApiKeyRedactionStrategy) -> String {
    redact_api_key(key, strategy)
}

/// Redact Azure key
#[must_use]
pub fn redact_azure_key(key: &str, strategy: ApiKeyRedactionStrategy) -> String {
    redact_api_key(key, strategy)
}

/// Redact AWS session token
#[must_use]
pub fn redact_aws_session_token(token: &str, strategy: ApiKeyRedactionStrategy) -> String {
    redact_api_key(token, strategy)
}

// ============================================================================
// Text Redaction Functions
// ============================================================================

/// Redact all JWTs in text
///
/// Scans text and redacts all detected JWTs according to policy.
#[must_use]
pub fn redact_jwts_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_jwt_strategy();
    if matches!(strategy, JwtRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    // Use detection to find JWTs
    let mut result = text.to_string();

    // Simple pattern matching for JWTs (three base64url parts separated by dots)
    // This is a simplified approach - proper implementation would use detection layer
    for word in text.split_whitespace() {
        if detection::is_jwt(word) {
            let redacted = redact_jwt(word, strategy);
            result = result.replacen(word, &redacted, 1);
        }
    }

    if result == text {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(result)
    }
}

/// Redact all API keys in text
///
/// Scans text and redacts all detected API keys according to policy.
#[must_use]
pub fn redact_api_keys_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_api_key_strategy();
    if matches!(strategy, ApiKeyRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    // Simple word-based scanning
    let mut result = text.to_string();
    for word in text.split_whitespace() {
        if detection::is_api_key(word) {
            let redacted = redact_api_key(word, strategy);
            result = result.replacen(word, &redacted, 1);
        }
    }

    if result == text {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(result)
    }
}

/// Redact all session IDs in text
///
/// Scans text and redacts all detected session IDs according to policy.
#[must_use]
pub fn redact_session_ids_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_session_id_strategy();
    if matches!(strategy, SessionIdRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();
    for word in text.split_whitespace() {
        if detection::is_likely_session_id(word) {
            let redacted = redact_session_id(word, strategy);
            result = result.replacen(word, &redacted, 1);
        }
    }

    if result == text {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(result)
    }
}

/// Redact all SSH keys in text
///
/// Scans text and redacts all detected SSH keys according to policy.
#[must_use]
pub fn redact_ssh_keys_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_ssh_key_strategy();
    if matches!(strategy, SshKeyRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();

    // Check for SSH public keys (single line)
    for line in text.lines() {
        if detection::is_ssh_public_key(line) {
            let redacted = redact_ssh_key(line, strategy);
            result = result.replacen(line, &redacted, 1);
        }
    }

    if result == text {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(result)
    }
}

/// Redact all tokens in text
///
/// Scans text and redacts all token types (JWTs, API keys, session IDs, SSH keys).
#[must_use]
pub fn redact_all_tokens_in_text(text: &str, policy: TextRedactionPolicy) -> String {
    let mut result = text.to_string();

    // Redact JWTs
    result = redact_jwts_in_text(&result, policy).into_owned();

    // Redact API keys
    result = redact_api_keys_in_text(&result, policy).into_owned();

    // Redact session IDs
    result = redact_session_ids_in_text(&result, policy).into_owned();

    // Redact SSH keys
    result = redact_ssh_keys_in_text(&result, policy).into_owned();

    result
}

// ============================================================================
// Masking Functions (Convenience Wrappers)
// ============================================================================

/// Mask JWT (show header only)
///
/// Convenience wrapper that shows only the JWT header.
#[must_use]
pub fn mask_jwt(jwt: &str) -> String {
    redact_jwt(jwt, JwtRedactionStrategy::ShowHeader)
}

/// Mask API key (show first 12 characters)
///
/// Convenience wrapper that shows first 12 characters then masks rest.
#[must_use]
pub fn mask_api_key(key: &str) -> String {
    // Use detection layer first
    if !detection::is_api_key(key) {
        return RedactionTokenCore::ApiKey.into();
    }

    if key.len() < 12 {
        return RedactionTokenCore::ApiKey.into();
    }

    // Show first 12 characters (typically includes prefix like "sk_live_")
    format!("{}***", &key[..12])
}

/// Mask session ID (show first 8 characters)
///
/// Convenience wrapper that shows first 8 characters then masks rest.
#[must_use]
pub fn mask_session_id(session_id: &str) -> String {
    redact_session_id(session_id, SessionIdRedactionStrategy::ShowPrefix)
}

/// Mask SSH key (show key type only)
///
/// Convenience wrapper that shows only the SSH key type.
#[must_use]
pub fn mask_ssh_key(key: &str) -> String {
    redact_ssh_key(key, SshKeyRedactionStrategy::ShowType)
}

// Provider-specific masking conveniences
/// Mask AWS access key
#[must_use]
pub fn mask_aws_key(key: &str) -> String {
    mask_api_key(key)
}

/// Mask GitHub token
#[must_use]
pub fn mask_github_token(token: &str) -> String {
    mask_api_key(token)
}

/// Mask Stripe key
#[must_use]
pub fn mask_stripe_key(key: &str) -> String {
    mask_api_key(key)
}

/// Mask GCP API key
#[must_use]
pub fn mask_gcp_key(key: &str) -> String {
    mask_api_key(key)
}

/// Mask Azure key
#[must_use]
pub fn mask_azure_key(key: &str) -> String {
    mask_api_key(key)
}

/// Mask AWS session token
#[must_use]
pub fn mask_aws_session_token(token: &str) -> String {
    mask_api_key(token)
}

/// Mask Square API key
#[must_use]
pub fn mask_square_token(key: &str) -> String {
    mask_api_key(key)
}

/// Mask Shopify API token
#[must_use]
pub fn mask_shopify_token(token: &str) -> String {
    mask_api_key(token)
}

/// Mask PayPal/Braintree access token
#[must_use]
pub fn mask_paypal_token(token: &str) -> String {
    mask_api_key(token)
}

/// Mask Mailchimp API key
#[must_use]
pub fn mask_mailchimp_key(key: &str) -> String {
    mask_api_key(key)
}

/// Mask Mailgun API key
#[must_use]
pub fn mask_mailgun_key(key: &str) -> String {
    mask_api_key(key)
}

/// Mask Resend API key
#[must_use]
pub fn mask_resend_key(key: &str) -> String {
    mask_api_key(key)
}

/// Mask Brevo API key
#[must_use]
pub fn mask_brevo_key(key: &str) -> String {
    mask_api_key(key)
}

/// Mask Databricks access token
#[must_use]
pub fn mask_databricks_token(token: &str) -> String {
    mask_api_key(token)
}

/// Mask HashiCorp Vault token
#[must_use]
pub fn mask_vault_token(token: &str) -> String {
    mask_api_key(token)
}

/// Mask Cloudflare Origin CA key
#[must_use]
pub fn mask_cloudflare_ca_key(key: &str) -> String {
    mask_api_key(key)
}

/// Mask NPM access token
#[must_use]
pub fn mask_npm_token(token: &str) -> String {
    mask_api_key(token)
}

/// Mask PyPI API token
#[must_use]
pub fn mask_pypi_token(token: &str) -> String {
    mask_api_key(token)
}

/// Mask NuGet API key
#[must_use]
pub fn mask_nuget_key(key: &str) -> String {
    mask_api_key(key)
}

/// Mask Artifactory API key
#[must_use]
pub fn mask_artifactory_token(token: &str) -> String {
    mask_api_key(token)
}

/// Mask Docker Hub PAT
#[must_use]
pub fn mask_docker_hub_token(token: &str) -> String {
    mask_api_key(token)
}

/// Mask Telegram bot token, preserving the numeric ID prefix
///
/// Format: `{numeric_id}:{secret}` → `{numeric_id}:****`
#[must_use]
pub fn mask_telegram_bot_token(token: &str) -> String {
    let trimmed = token.trim();
    match trimmed.split_once(':') {
        Some((id, _secret)) if !id.is_empty() => format!("{id}:****"),
        _ => "[TELEGRAM_TOKEN]".to_string(),
    }
}

/// Mask SendGrid API key, preserving the `SG.` prefix and first 4 chars
///
/// Format: `SG.{seg1}.{seg2}` → `SG.{first4}****`
#[must_use]
pub fn mask_sendgrid_key(key: &str) -> String {
    let trimmed = key.trim();
    if let Some(rest) = trimmed.strip_prefix("SG.") {
        let preview_len = rest.len().min(4);
        let preview = rest.get(..preview_len).unwrap_or_default();
        format!("SG.{preview}****")
    } else {
        "[SENDGRID_KEY]".to_string()
    }
}

/// Mask Twilio Account SID, preserving the `AC` prefix and first 4 hex chars
///
/// Format: `AC{32 hex}` → `ACabcd****`
#[must_use]
pub fn mask_twilio_account_sid(sid: &str) -> String {
    let trimmed = sid.trim();
    if let Some(rest) = trimmed.strip_prefix("AC") {
        let preview_len = rest.len().min(4);
        let preview = rest.get(..preview_len).unwrap_or_default();
        format!("AC{preview}****")
    } else {
        "[TWILIO_SID]".to_string()
    }
}

/// Mask Twilio API Key SID, preserving the `SK` prefix and first 4 hex chars
///
/// Format: `SK{32 hex}` → `SKabcd****`
#[must_use]
pub fn mask_twilio_api_key_sid(sid: &str) -> String {
    let trimmed = sid.trim();
    if let Some(rest) = trimmed.strip_prefix("SK") {
        let preview_len = rest.len().min(4);
        let preview = rest.get(..preview_len).unwrap_or_default();
        format!("SK{preview}****")
    } else {
        "[TWILIO_API_KEY]".to_string()
    }
}

/// Mask Slack token, preserving the type prefix (xoxb-, xoxp-, xapp-, etc.)
///
/// Format: `{prefix}-{rest}` → `{prefix}-****`
#[must_use]
pub fn mask_slack_token(token: &str) -> String {
    let trimmed = token.trim();
    match trimmed.split_once('-') {
        Some((prefix, _rest)) if prefix.starts_with("xox") || prefix.starts_with("xapp") => {
            format!("{prefix}-****")
        }
        _ => "[SLACK_TOKEN]".to_string(),
    }
}

/// Mask Slack webhook URL, preserving the domain and masking service path segments
///
/// Format: `https://hooks.slack.com/services/T.../B.../...` → `https://hooks.slack.com/services/****`
#[must_use]
pub fn mask_slack_webhook(url: &str) -> String {
    let trimmed = url.trim();
    match trimmed.strip_prefix("https://hooks.slack.com/services/") {
        Some(rest) if !rest.is_empty() => "https://hooks.slack.com/services/****".to_string(),
        _ => "[SLACK_WEBHOOK]".to_string(),
    }
}

/// Mask Discord bot token, preserving the first segment (base64 user ID)
///
/// Format: `{user_id_b64}.{timestamp}.{hmac}` → `{user_id_b64}.****`
#[must_use]
pub fn mask_discord_token(token: &str) -> String {
    let trimmed = token.trim();
    match trimmed.split_once('.') {
        Some((first_segment, _rest))
            if first_segment.starts_with('M') || first_segment.starts_with('N') =>
        {
            format!("{first_segment}.****")
        }
        _ => "[DISCORD_TOKEN]".to_string(),
    }
}

/// Mask Discord webhook URL, preserving the domain and webhook ID
///
/// Format: `https://discord(app)?.com/api/webhooks/{id}/{token}` → `...webhooks/{id}/****`
#[must_use]
pub fn mask_discord_webhook(url: &str) -> String {
    let trimmed = url.trim();
    let after_webhooks = trimmed
        .strip_prefix("https://discord.com/api/webhooks/")
        .or_else(|| trimmed.strip_prefix("https://discordapp.com/api/webhooks/"));
    match after_webhooks {
        Some(rest) if !rest.is_empty() => {
            let domain = if trimmed.starts_with("https://discordapp.com") {
                "https://discordapp.com"
            } else {
                "https://discord.com"
            };
            match rest.split_once('/') {
                Some((id, _token)) if !id.is_empty() => {
                    format!("{domain}/api/webhooks/{id}/****")
                }
                _ => format!("{domain}/api/webhooks/****"),
            }
        }
        _ => "[DISCORD_WEBHOOK]".to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== Individual Redaction Tests - JWT =====

    #[test]
    fn test_redact_jwt_token() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert_eq!(redact_jwt(jwt, JwtRedactionStrategy::Token), "[JWT]");
    }

    #[test]
    fn test_redact_jwt_show_header() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let result = redact_jwt(jwt, JwtRedactionStrategy::ShowHeader);
        assert!(result.starts_with("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        assert!(result.contains("...."));
    }

    // ===== Individual Redaction Tests - API Keys =====

    #[test]
    fn test_redact_api_key_show_prefix() {
        let key = "sk_live_1234567890abcdef";
        let result = redact_api_key(key, ApiKeyRedactionStrategy::ShowPrefix);
        assert!(result.starts_with("sk_live_"));
        assert!(result.contains("****"));
    }

    #[test]
    fn test_redact_api_key_show_provider() {
        assert_eq!(
            redact_api_key("sk_live_123", ApiKeyRedactionStrategy::ShowProvider),
            "[STRIPE_KEY]"
        );
        assert_eq!(
            redact_api_key(
                &format!("AKIA{}", "1234567890ABCDEF"),
                ApiKeyRedactionStrategy::ShowProvider
            ),
            "[AWS_KEY]"
        );
        assert_eq!(
            redact_api_key(
                "ghp_1234567890abcdef",
                ApiKeyRedactionStrategy::ShowProvider
            ),
            "[GITHUB_TOKEN]"
        );
    }

    // ===== Individual Redaction Tests - Session IDs =====

    #[test]
    fn test_redact_session_id_show_prefix() {
        let session = "a1b2c3d4e5f6g7h8i9j0";
        let result = redact_session_id(session, SessionIdRedactionStrategy::ShowPrefix);
        assert_eq!(result, "a1b2c3d4****");
    }

    #[test]
    fn test_redact_session_id_token() {
        let session = "a1b2c3d4e5f6g7h8i9j0";
        assert_eq!(
            redact_session_id(session, SessionIdRedactionStrategy::Token),
            "[SESSION]"
        );
    }

    // ===== Individual Redaction Tests - SSH Keys =====

    #[test]
    fn test_redact_ssh_key_show_type() {
        let key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...";
        assert_eq!(
            redact_ssh_key(key, SshKeyRedactionStrategy::ShowType),
            "<ssh-rsa>"
        );
    }

    #[test]
    fn test_redact_ssh_key_token() {
        let key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...";
        assert_eq!(
            redact_ssh_key(key, SshKeyRedactionStrategy::Token),
            "[SSH_KEY]"
        );
    }

    // ===== Text Redaction Tests =====

    #[test]
    fn test_redact_api_keys_in_text() {
        let text = &format!("My key is sk_live_{} here", "EXAMPLE000000000KEY01abcdef");
        let redacted = redact_api_keys_in_text(text, TextRedactionPolicy::Complete);
        assert!(redacted.contains("[API_KEY]"));
        assert!(!redacted.contains("sk_live"));
    }

    #[test]
    fn test_redact_all_tokens_in_text() {
        let text = &format!(
            "JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c and key sk_live_{}",
            "EXAMPLE000000000KEY01abcdef"
        );
        let redacted = redact_all_tokens_in_text(text, TextRedactionPolicy::Complete);
        assert!(redacted.contains("[JWT]"));
        assert!(redacted.contains("[API_KEY]"));
    }

    // ===== Masking Tests =====

    #[test]
    fn test_mask_api_key() {
        let key = format!("sk_live_{}", "EXAMPLE000000000KEY01abcdef");
        assert_eq!(mask_api_key(&key), "sk_live_EXAM***");

        // Short key
        let short_key = "short";
        assert_eq!(mask_api_key(short_key), "[API_KEY]");
    }

    #[test]
    fn test_mask_session_id() {
        let session = "a1b2c3d4e5f6g7h8i9j0";
        assert_eq!(mask_session_id(session), "a1b2c3d4****");
    }

    #[test]
    fn test_mask_discord_token() {
        // Valid: preserves first segment (base64 user ID)
        let token = format!("M{}.{}.{}", "A".repeat(23), "AbCdEf", "a".repeat(27));
        assert_eq!(
            mask_discord_token(&token),
            format!("M{}.****", "A".repeat(23))
        );

        // Valid: starts with N
        let token_n = format!("N{}.{}.{}", "B".repeat(25), "X1y2Z3", "b".repeat(30));
        assert_eq!(
            mask_discord_token(&token_n),
            format!("N{}.****", "B".repeat(25))
        );

        // Malformed: wrong prefix
        assert_eq!(mask_discord_token("invalid.token.here"), "[DISCORD_TOKEN]");

        // Malformed: empty
        assert_eq!(mask_discord_token(""), "[DISCORD_TOKEN]");
    }

    #[test]
    fn test_mask_discord_webhook() {
        // Valid webhook
        assert_eq!(
            mask_discord_webhook(
                "https://discord.com/api/webhooks/123456789/abcdefABCDEF_-0123456789"
            ),
            "https://discord.com/api/webhooks/123456789/****"
        );

        // Valid with discordapp.com
        assert_eq!(
            mask_discord_webhook("https://discordapp.com/api/webhooks/987654321/tokenvalue123"),
            "https://discordapp.com/api/webhooks/987654321/****"
        );

        // Malformed: wrong domain
        assert_eq!(
            mask_discord_webhook("https://example.com/api/webhooks/123/abc"),
            "[DISCORD_WEBHOOK]"
        );

        // Malformed: empty
        assert_eq!(mask_discord_webhook(""), "[DISCORD_WEBHOOK]");
    }

    #[test]
    fn test_mask_slack_token() {
        // Valid: bot token preserves prefix
        assert_eq!(
            mask_slack_token(&format!("xoxb-{}-{}", "1".repeat(12), "A".repeat(24))),
            "xoxb-****"
        );

        // Valid: user token
        assert_eq!(
            mask_slack_token(&format!("xoxp-{}-{}", "2".repeat(12), "B".repeat(32))),
            "xoxp-****"
        );

        // Valid: app token
        assert_eq!(
            mask_slack_token(&format!("xapp-{}-{}", "3".repeat(10), "C".repeat(20))),
            "xapp-****"
        );

        // Malformed: wrong prefix
        assert_eq!(mask_slack_token("invalid-token"), "[SLACK_TOKEN]");

        // Malformed: empty
        assert_eq!(mask_slack_token(""), "[SLACK_TOKEN]");
    }

    #[test]
    fn test_mask_slack_webhook() {
        // Valid webhook
        assert_eq!(
            mask_slack_webhook(&format!(
                "https://hooks.slack.com/services/T{}/B{}/{}",
                "A".repeat(10),
                "B".repeat(10),
                "c".repeat(24)
            )),
            "https://hooks.slack.com/services/****"
        );

        // Whitespace trimmed
        assert_eq!(
            mask_slack_webhook("  https://hooks.slack.com/services/TABC/BBCD/xyz  "),
            "https://hooks.slack.com/services/****"
        );

        // Malformed: wrong domain
        assert_eq!(
            mask_slack_webhook("https://example.com/services/T/B/x"),
            "[SLACK_WEBHOOK]"
        );

        // Malformed: empty
        assert_eq!(mask_slack_webhook(""), "[SLACK_WEBHOOK]");
    }

    #[test]
    fn test_mask_twilio_account_sid() {
        // Valid: preserves AC prefix + first 4 hex chars
        let sid = format!("AC{}", "a".repeat(32));
        assert_eq!(mask_twilio_account_sid(&sid), "ACaaaa****");

        // Whitespace trimmed
        let padded = format!("  AC{}  ", "b".repeat(32));
        assert_eq!(mask_twilio_account_sid(&padded), "ACbbbb****");

        // Malformed: wrong prefix
        assert_eq!(mask_twilio_account_sid("AB1234"), "[TWILIO_SID]");

        // Malformed: empty string
        assert_eq!(mask_twilio_account_sid(""), "[TWILIO_SID]");
    }

    #[test]
    fn test_mask_twilio_api_key_sid() {
        // Valid: preserves SK prefix + first 4 hex chars
        let sid = format!("SK{}", "c".repeat(32));
        assert_eq!(mask_twilio_api_key_sid(&sid), "SKcccc****");

        // Malformed: wrong prefix
        assert_eq!(mask_twilio_api_key_sid("SL1234"), "[TWILIO_API_KEY]");

        // Malformed: empty string
        assert_eq!(mask_twilio_api_key_sid(""), "[TWILIO_API_KEY]");
    }

    #[test]
    fn test_mask_sendgrid_key() {
        // Valid key: preserves SG. prefix and first 4 chars
        let key = format!("SG.{}.{}", "A".repeat(22), "b".repeat(43));
        assert_eq!(mask_sendgrid_key(&key), "SG.AAAA****");

        // Whitespace trimmed
        let padded = format!("  SG.{}.{}  ", "X".repeat(22), "y".repeat(43));
        assert_eq!(mask_sendgrid_key(&padded), "SG.XXXX****");

        // Malformed: wrong prefix
        assert_eq!(mask_sendgrid_key("XX.something"), "[SENDGRID_KEY]");

        // Malformed: empty string
        assert_eq!(mask_sendgrid_key(""), "[SENDGRID_KEY]");
    }

    #[test]
    fn test_mask_telegram_bot_token() {
        // Valid token: preserves numeric ID, masks secret
        let token = format!("123456789:{}", "A".repeat(35));
        assert_eq!(mask_telegram_bot_token(&token), "123456789:****");

        // Whitespace trimmed
        let padded = format!("  123456789:{}  ", "B".repeat(35));
        assert_eq!(mask_telegram_bot_token(&padded), "123456789:****");

        // Malformed: no colon
        assert_eq!(mask_telegram_bot_token("not-a-token"), "[TELEGRAM_TOKEN]");

        // Malformed: empty string
        assert_eq!(mask_telegram_bot_token(""), "[TELEGRAM_TOKEN]");
    }
}

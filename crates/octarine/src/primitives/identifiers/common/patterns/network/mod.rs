//! Network identification patterns (per-category submodules)
//!
//! Split from the original 825-LOC `network.rs` into three submodules grouped
//! by category. Public surface is preserved via `pub use` re-exports of the
//! inner sub-modules so call sites continue to reference e.g.
//! `patterns::network::JWT`, `patterns::network::API_KEY_GITHUB`,
//! `patterns::network::email::STANDARD`.
//!
//! # Pattern Categories
//!
//! - **`contact_patterns`**: `email`, `phone`, `username` (sub-modules).
//! - **`identifier_patterns`**: UUIDs (v4/v5/any), MAC addresses, IPv4/IPv6,
//!   domain, hostname, port, generic phone, JWT, SSH keys / fingerprints.
//! - **`credential_patterns`**: URLs, API keys (AWS, GCP, Azure, GitHub,
//!   GitLab, Stripe, Slack, OpenAI, Vault, etc.), bearer tokens, vault
//!   references, and connection-string secrets.

mod contact_patterns;
mod credential_patterns;
mod identifier_patterns;

// Sub-modules (callers reference e.g. `network::email::STANDARD`).
pub(crate) use contact_patterns::{email, phone, username};

// Top-level statics re-exported flat (callers reference e.g. `network::JWT`,
// `network::API_KEY_GITHUB`, `network::SSH_PUBLIC_KEY`, etc.).
pub use credential_patterns::*;
pub use identifier_patterns::*;

use once_cell::sync::Lazy;
use regex::Regex;

/// Patterns matching UUIDs — version 4, version 5, and any RFC 4122 version (1-5).
pub fn uuids() -> Vec<&'static Regex> {
    vec![&*UUID_V4, &*UUID_V5, &*UUID_ANY]
}

/// Patterns matching MAC addresses in colon, hyphen, and Cisco dot-separated formats.
pub fn macs() -> Vec<&'static Regex> {
    vec![&*MAC_COLON, &*MAC_HYPHEN, &*MAC_DOT]
}

/// Patterns matching IP addresses — IPv4, IPv6, and labeled IPv4 (`IP: 1.2.3.4`).
pub fn ips() -> Vec<&'static Regex> {
    vec![&*IPV4, &*IPV6, &*IPV4_LABELED]
}

/// Patterns matching URLs — HTTP/HTTPS, FTP, WebSocket (wss/ws), and a generic protocol fallback.
pub fn urls() -> Vec<&'static Regex> {
    vec![&*URL_HTTP, &*URL_FTP, &*URL_WSS, &*URL_WS, &*URL_GENERIC]
}

/// Patterns matching API keys, tokens, and connection-string secrets across
/// major cloud, SaaS, and developer platforms (AWS, GCP, Azure, GitHub,
/// GitLab, Stripe, Slack, OpenAI, Vault, and many others — see the
/// individual `API_KEY_*` constants for the full list).
pub fn api_keys() -> Vec<&'static Regex> {
    vec![
        &*API_KEY_GENERIC,
        &*API_KEY_STRIPE,
        &*API_KEY_AWS_ACCESS,
        &*API_KEY_AWS_SECRET,
        &*API_KEY_GCP,
        &*GCP_SERVICE_ACCOUNT_TYPE,
        &*GCP_SERVICE_ACCOUNT_EMAIL,
        &*GCP_OAUTH_CLIENT_SECRET,
        &*FIREBASE_FCM_SERVER_KEY,
        &*API_KEY_GITHUB,
        &*API_KEY_GITLAB,
        &*API_KEY_AZURE,
        &*API_KEY_1PASSWORD,
        &*API_KEY_SQUARE,
        &*API_KEY_SHOPIFY,
        &*API_KEY_PAYPAL_BRAINTREE,
        &*API_KEY_MAILCHIMP,
        &*API_KEY_MAILGUN,
        &*API_KEY_RESEND,
        &*API_KEY_BREVO,
        &*API_KEY_DATABRICKS,
        &*API_KEY_VAULT,
        &*API_KEY_CLOUDFLARE_CA,
        &*API_KEY_NPM,
        &*API_KEY_PYPI,
        &*API_KEY_NUGET,
        &*API_KEY_ARTIFACTORY,
        &*API_KEY_DOCKER_HUB,
        &*API_KEY_TELEGRAM,
        &*API_KEY_DISCORD_BOT,
        &*API_KEY_DISCORD_WEBHOOK,
        &*API_KEY_SLACK,
        &*API_KEY_SLACK_WEBHOOK,
        &*API_KEY_TWILIO_SID,
        &*API_KEY_TWILIO_API_KEY,
        &*API_KEY_SENDGRID,
        &*API_KEY_OPENAI_LEGACY,
        &*API_KEY_OPENAI_PROJECT,
        &*API_KEY_OPENAI_ORG,
        &*ONEPASSWORD_VAULT_REF,
        &*BEARER_TOKEN,
    ]
}

/// Patterns matching SSH key material — public keys (rsa/ed25519/ecdsa/dss),
/// MD5 and SHA-256 fingerprints, and private-key PEM headers.
pub fn ssh_keys() -> Vec<&'static Regex> {
    vec![
        &*SSH_PUBLIC_KEY,
        &*SSH_FINGERPRINT_MD5,
        &*SSH_FINGERPRINT_SHA256,
        &*SSH_PRIVATE_KEY_HEADER,
    ]
}

/// All network patterns from this module — UUIDs, MAC addresses, IPs, URLs
/// (incl. URLs with embedded credentials), international phone numbers, JWTs,
/// API keys for every supported platform, OAuth/bearer tokens, database
/// connection strings, and SSH key material.
pub fn all() -> Vec<&'static Regex> {
    vec![
        &*UUID_V4,
        &*UUID_V5,
        &*UUID_ANY,
        &*MAC_COLON,
        &*MAC_HYPHEN,
        &*MAC_DOT,
        &*IPV4,
        &*IPV6,
        &*IPV4_LABELED,
        &*URL_HTTP,
        &*URL_FTP,
        &*URL_WSS,
        &*URL_WS,
        &*URL_GENERIC,
        &*URL_WITH_CREDENTIALS,
        &*PHONE_INTL,
        &*JWT,
        &*API_KEY_GENERIC,
        &*API_KEY_STRIPE,
        &*API_KEY_AWS_ACCESS,
        &*API_KEY_AWS_SECRET,
        &*API_KEY_GCP,
        &*API_KEY_GITHUB,
        &*API_KEY_GITLAB,
        &*API_KEY_AZURE,
        &*API_KEY_1PASSWORD,
        &*API_KEY_SQUARE,
        &*API_KEY_SHOPIFY,
        &*API_KEY_PAYPAL_BRAINTREE,
        &*API_KEY_MAILCHIMP,
        &*API_KEY_MAILGUN,
        &*API_KEY_RESEND,
        &*API_KEY_BREVO,
        &*API_KEY_DATABRICKS,
        &*API_KEY_VAULT,
        &*API_KEY_CLOUDFLARE_CA,
        &*API_KEY_NPM,
        &*API_KEY_PYPI,
        &*API_KEY_NUGET,
        &*API_KEY_ARTIFACTORY,
        &*API_KEY_DOCKER_HUB,
        &*API_KEY_TELEGRAM,
        &*API_KEY_DISCORD_BOT,
        &*API_KEY_DISCORD_WEBHOOK,
        &*API_KEY_SLACK,
        &*API_KEY_SLACK_WEBHOOK,
        &*API_KEY_TWILIO_SID,
        &*API_KEY_TWILIO_API_KEY,
        &*API_KEY_SENDGRID,
        &*API_KEY_OPENAI_LEGACY,
        &*API_KEY_OPENAI_PROJECT,
        &*API_KEY_OPENAI_ORG,
        &*ONEPASSWORD_VAULT_REF,
        &*BEARER_TOKEN,
        &*SSH_PUBLIC_KEY,
        &*SSH_FINGERPRINT_MD5,
        &*SSH_FINGERPRINT_SHA256,
        &*SSH_PRIVATE_KEY_HEADER,
    ]
}

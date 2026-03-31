//! Network identification patterns
//!
//! Regex patterns for network identifiers including UUIDs, MAC addresses, IP addresses,
//! URLs, phone numbers, emails, usernames, JWTs, and API keys.

// SAFETY: All regex patterns in this module are hardcoded and verified at compile time.
#![allow(clippy::expect_used)]

use once_cell::sync::Lazy;
use regex::Regex;

pub mod email {
    use super::*;

    /// Standard email pattern (for text scanning)
    /// Example: "user@example.com"
    pub static STANDARD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Exact email pattern (for validation)
    /// Example: "user@example.com"
    pub static EXACT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*STANDARD]
    }
}
pub mod phone {
    use super::*;

    /// US phone with country code
    /// Example: "+1-555-123-4567"
    pub static WITH_COUNTRY_CODE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\+1[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")
            .expect("BUG: Invalid regex pattern")
    });

    /// US phone with parentheses
    /// Example: "(555) 123-4567"
    pub static WITH_PARENS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\(\d{3}\)\s*\d{3}[-.\s]?\d{4}").expect("BUG: Invalid regex pattern")
    });

    /// US phone standard format
    /// Example: "555-123-4567"
    pub static STANDARD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b").expect("BUG: Invalid regex pattern")
    });

    /// International format (generic 10+ digits with optional +)
    /// Example: "+44 20 7946 0958"
    pub static INTERNATIONAL: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\+?\d{1,3}[-.\s]?\d{1,14}").expect("BUG: Invalid regex pattern"));

    /// E.164 format (exact match for validation)
    /// Example: "+15551234567"
    pub static E164_EXACT: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\+[1-9]\d{1,14}$").expect("BUG: Invalid regex pattern"));

    /// US phone exact match (for validation)
    /// Example: "(555) 123-4567", "555-123-4567"
    pub static US_EXACT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^(\+1[-.\s]?)?(\([0-9]{3}\)|[0-9]{3})[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$")
            .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*WITH_COUNTRY_CODE, &*WITH_PARENS, &*STANDARD]
    }
}

pub mod username {
    use super::*;

    /// Standard username pattern (alphanumeric with underscore, dot, dash)
    /// Example: "john_doe", "user.name", "test-user"
    pub static STANDARD: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_.-]{3,32}$").expect("BUG: Invalid regex pattern"));
}

// UUID patterns
/// UUID v4 pattern (random UUIDs)
/// Example: "550e8400-e29b-41d4-a716-446655440000"
pub static UUID_V4: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
    )
    .expect("BUG: Invalid regex pattern")
});

/// UUID v5 pattern (namespace-based SHA-1 UUIDs)
/// Example: "550e8400-e29b-41d4-5716-446655440000"
pub static UUID_V5: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-5[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
    )
    .expect("BUG: Invalid regex pattern")
});

/// UUID any version pattern (versions 1-5)
/// Example: "550e8400-e29b-41d4-a716-446655440000"
pub static UUID_ANY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
    )
    .expect("BUG: Invalid regex pattern")
});

// MAC address patterns
/// MAC address with colons
/// Example: "00:1B:44:11:3A:B7"
pub static MAC_COLON: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}").expect("BUG: Invalid regex pattern")
});

/// MAC address with hyphens
/// Example: "00-1B-44-11-3A-B7"
pub static MAC_HYPHEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}").expect("BUG: Invalid regex pattern")
});

/// MAC address with dots (Cisco format)
/// Example: "001B.4411.3AB7"
pub static MAC_DOT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}")
        .expect("BUG: Invalid regex pattern")
});

// IP address patterns
/// IPv4 address
/// Example: "192.168.1.1"
pub static IPV4: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    )
    .expect("BUG: Invalid regex pattern")
});

/// IPv6 address (simplified pattern)
/// Example: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
pub static IPV6: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1|::)")
        .expect("BUG: Invalid regex pattern")
});

/// IPv4 with label
/// Example: "IP: 192.168.1.1"
pub static IPV4_LABELED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i:ip[\s:-]*address?[\s:-]*)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
        .expect("BUG: Invalid regex pattern")
});

// URL patterns
/// HTTP/HTTPS URL
/// Example: "https://example.com/path"
pub static URL_HTTP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"https?://[^\s]+").expect("BUG: Invalid regex pattern"));

/// FTP URL
/// Example: "ftp://ftp.example.com"
pub static URL_FTP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"ftp://[^\s]+").expect("BUG: Invalid regex pattern"));

/// Generic URL with protocol
/// Example: "protocol://host.com"
pub static URL_GENERIC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[a-z][a-z0-9+.-]*://[^\s]+").expect("BUG: Invalid regex pattern"));

/// WebSocket URL (secure)
/// Example: "wss://example.com/socket"
pub static URL_WSS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"wss://[^\s]+").expect("BUG: Invalid regex pattern"));

/// WebSocket URL (insecure)
/// Example: "ws://localhost:8080/stream"
pub static URL_WS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"ws://[^\s]+").expect("BUG: Invalid regex pattern"));

// Domain and hostname patterns
/// Domain name (without protocol)
/// Example: "example.com", "sub.domain.co.uk"
/// Pattern: Must have at least one dot and valid TLD (2-63 chars)
pub static DOMAIN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")
        .expect("BUG: Invalid regex pattern")
});

/// Hostname (with optional port)
/// Example: "server01", "db-primary:5432", "cache-node-3"
/// Pattern: Alphanumeric + hyphens, 1-63 chars, optional :port
pub static HOSTNAME: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?::\d{1,5})?\b")
        .expect("BUG: Invalid regex pattern")
});

/// Port number (standalone or with colon)
/// Example: ":8080", ":443", ":3000"
pub static PORT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r":([1-9]\d{0,4})\b").expect("BUG: Invalid regex pattern"));

// Phone patterns
/// International phone with country code
/// Example: "+1-555-123-4567"
pub static PHONE_INTL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\+[1-9]\d{0,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}")
        .expect("BUG: Invalid regex pattern")
});

// JWT pattern
/// JWT token (base64url.base64url.base64url)
/// Example: "eyJhbGc...iOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI...iJ9.SflKxwR...J8WQ4"
pub static JWT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\b")
        .expect("BUG: Invalid regex pattern")
});

// API key patterns
/// Generic API key pattern (alphanumeric with dashes/underscores)
/// Example: "sk_test_0000000000KEY01"
pub static API_KEY_GENERIC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i:api[-_]?key|token)[\s:=]+[a-zA-Z0-9_-]{20,}")
        .expect("BUG: Invalid regex pattern")
});

/// Stripe API key pattern
/// Example: "sk_live_0000000000KEY01"
pub static API_KEY_STRIPE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}").expect("BUG: Invalid regex pattern")
});

/// AWS Access Key ID pattern (long-term AKIA and temporary STS ASIA)
/// Example: "AKIA" + "IOSFODNN7EXAMPLE", "ASIA" + "JEXAMPLEXEG2JICEA"
pub static API_KEY_AWS_ACCESS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").expect("BUG: Invalid regex pattern"));

/// AWS Secret Access Key pattern (40 base64 characters)
/// Example: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
pub static API_KEY_AWS_SECRET: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9/+=]{40}").expect("BUG: Invalid regex pattern"));

/// AWS Session Token pattern (long Base64 string from STS)
/// These accompany temporary ASIA credentials and are typically 100+ characters
pub static API_KEY_AWS_SESSION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9/+=]{100,}").expect("BUG: Invalid regex pattern"));

/// Google Cloud Platform API key pattern
/// Example: "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"
pub static API_KEY_GCP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").expect("BUG: Invalid regex pattern"));

/// GitHub Personal Access Token patterns
/// Formats: ghp_ (personal), gho_ (OAuth), ghu_ (user-to-server), ghs_ (server-to-server), ghr_ (refresh)
/// Also matches fine-grained PATs: github_pat_{22}_{59}
/// Example: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
pub static API_KEY_GITHUB: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:\bgh[prsou]_[a-zA-Z0-9]{36,}\b|\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b)")
        .expect("BUG: Invalid regex pattern")
});

/// GitLab Personal Access Token patterns
/// Formats: glpat- (personal access token), gldt- (deploy token)
/// Example: "glpat-xxxxxxxxxxxxxxxxxxxx"
pub static API_KEY_GITLAB: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:glpat|gldt)-[a-zA-Z0-9_-]{20,}\b").expect("BUG: Invalid regex pattern")
});

/// Azure Storage Account Key pattern (base64, 88 characters)
/// Example: "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=..."
pub static API_KEY_AZURE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i:AccountKey)=([A-Za-z0-9+/=]{88})").expect("BUG: Invalid regex pattern")
});

/// 1Password Service Account Token pattern
/// Example: "ops_eyJzaWduSW5BZGRyZXNzIjoi..."
pub static API_KEY_1PASSWORD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bops_[A-Za-z0-9_-]{50,}\b").expect("BUG: Invalid regex pattern"));

/// Square API key patterns (OAuth access token, OAuth secret, Application ID)
/// Formats: sq0atp-{22}, sq0csp-{43}, sq0idp-{22} (and sandbox- prefixed variants)
/// Example: "sq0atp-" + "ABCDEFghijklmnopqrstuv"
pub static API_KEY_SQUARE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bsq0(?:atp|csp|idp)-[a-zA-Z0-9_-]{22,}\b").expect("BUG: Invalid regex pattern")
});

/// Shopify API access token patterns
/// Formats: shpat_{32hex}, shpca_{32hex}, shppa_{32hex}, shpss_{32hex}
/// Example: "shpat_" + "abcdef1234567890abcdef1234567890"
pub static API_KEY_SHOPIFY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b").expect("BUG: Invalid regex pattern")
});

/// PayPal/Braintree access token pattern
/// Format: access_token$production$[a-z0-9]{16}$[a-f0-9]{32}
/// Example: "access_token$production$abc1234567890xyz$abcdef1234567890abcdef1234567890ab"
pub static API_KEY_PAYPAL_BRAINTREE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\baccess_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}\b")
        .expect("BUG: Invalid regex pattern")
});

/// Mailchimp API key pattern
/// Format: [a-f0-9]{32}-us[0-9]{1,2} (32 hex chars + datacenter suffix)
/// Example: "[32 hex chars]-us6"
pub static API_KEY_MAILCHIMP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[a-f0-9]{32}-us[0-9]{1,2}\b").expect("BUG: Invalid regex pattern"));

/// Mailgun API key pattern
/// Format: key-[a-zA-Z0-9]{32}
/// Example: "key-ABCDEFghijklmnopqrstuv1234567890"
pub static API_KEY_MAILGUN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bkey-[a-zA-Z0-9]{32}\b").expect("BUG: Invalid regex pattern"));

/// Resend API key pattern
/// Format: re_[a-zA-Z0-9]{32,}
/// Example: "re_ABCDEFghijklmnopqrstuv1234567890ab"
pub static API_KEY_RESEND: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bre_[a-zA-Z0-9]{32,}\b").expect("BUG: Invalid regex pattern"));

/// Brevo (Sendinblue) API key pattern
/// Format: xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}
/// Example: "xkeysib-<64hex>-<16alnum>"
pub static API_KEY_BREVO: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bxkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}\b").expect("BUG: Invalid regex pattern")
});

/// Databricks access token pattern
/// Format: dapi[a-f0-9]{32} with optional -[0-9] suffix
/// Example: "dapi" + 32 hex chars
pub static API_KEY_DATABRICKS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bdapi[a-f0-9]{32}(?:-[0-9])?\b").expect("BUG: Invalid regex pattern")
});

/// HashiCorp Vault token pattern (modern hvs., batch b., legacy service s.)
/// Formats: hvs.[24+ chars], b.[24+ chars], s.[exactly 24 chars]
/// Example: "hvs." + 24+ alnum chars
pub static API_KEY_VAULT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:hvs\.[a-zA-Z0-9_-]{24,}|b\.[a-zA-Z0-9]{24,}|s\.[a-zA-Z0-9]{24})\b")
        .expect("BUG: Invalid regex pattern")
});

/// Cloudflare Origin CA key pattern
/// Format: v1.0-[24 hex]-[146 hex]
/// Example: "v1.0-" + 24 hex + "-" + 146 hex (175+ chars total)
pub static API_KEY_CLOUDFLARE_CA: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b").expect("BUG: Invalid regex pattern")
});

/// NPM access token pattern
/// Format: npm_[a-zA-Z0-9]{36}
/// Example: "npm_" + 36 alnum chars
pub static API_KEY_NPM: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bnpm_[a-zA-Z0-9]{36}\b").expect("BUG: Invalid regex pattern"));

/// PyPI API token pattern
/// Format: pypi-AgEIcHlwaS5vcmc[base64]{50+}
/// Example: "pypi-AgEIcHlwaS5vcmc" + 50+ base64 chars
pub static API_KEY_PYPI: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b").expect("BUG: Invalid regex pattern")
});

/// NuGet API key pattern
/// Format: oy2[a-z0-9]{43}
/// Example: "oy2" + 43 lowercase alnum chars
pub static API_KEY_NUGET: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\boy2[a-z0-9]{43}\b").expect("BUG: Invalid regex pattern"));

/// JFrog Artifactory API key pattern
/// Format: AKC[a-zA-Z0-9]{10,}
/// Example: "AKC" + 10+ alnum chars
pub static API_KEY_ARTIFACTORY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bAKC[a-zA-Z0-9]{10,}\b").expect("BUG: Invalid regex pattern"));

/// Docker Hub Personal Access Token pattern
/// Format: dckr_pat_[a-zA-Z0-9_-]{27,}
/// Example: "dckr_pat_" + 27+ alnum chars
pub static API_KEY_DOCKER_HUB: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bdckr_pat_[a-zA-Z0-9_-]{27,}\b").expect("BUG: Invalid regex pattern")
});

/// Telegram bot token pattern
/// Format: [0-9]{8,10}:[a-zA-Z0-9_-]{35}
/// Example: "123456789:ABCDEFGHIJKLmnopqrstuvwxyz0123456789"
pub static API_KEY_TELEGRAM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b").expect("BUG: Invalid regex pattern")
});

/// Discord bot token pattern
/// Format: [MN][A-Za-z\d]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}
/// (example omitted — GitHub push protection flags realistic patterns)
pub static API_KEY_DISCORD_BOT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b")
        .expect("BUG: Invalid regex pattern")
});

/// Discord webhook URL pattern
/// Format: https://discord(app)?.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+
/// Example: "https://discord.com/api/webhooks/123456789/abcdef..."
pub static API_KEY_DISCORD_WEBHOOK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+")
        .expect("BUG: Invalid regex pattern")
});

/// Slack token pattern (matches bot, user, config, and legacy xox* formats)
/// Formats: xoxb-..., xoxp-..., xoxe.xoxp-..., xoxs-..., xoxa-..., xapp-...
/// (examples omitted — GitHub push protection flags realistic patterns)
pub static API_KEY_SLACK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:xox[bpseari]|xapp)-[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]+)*\b")
        .expect("BUG: Invalid regex pattern")
});

/// Slack webhook URL pattern
/// Format: https://hooks.slack.com/services/T.../B.../...
pub static API_KEY_SLACK_WEBHOOK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+")
        .expect("BUG: Invalid regex pattern")
});

/// Twilio Account SID pattern
/// Format: AC[a-f0-9]{32}
pub static API_KEY_TWILIO_SID: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bAC[a-f0-9]{32}\b").expect("BUG: Invalid regex pattern"));

/// Twilio API Key SID pattern
/// Format: SK[a-f0-9]{32}
pub static API_KEY_TWILIO_API_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bSK[a-f0-9]{32}\b").expect("BUG: Invalid regex pattern"));

/// SendGrid API key pattern
/// Format: SG.[a-zA-Z0-9_-]{22}.[a-zA-Z0-9_-]{43}
pub static API_KEY_SENDGRID: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b").expect("BUG: Invalid regex pattern")
});

/// 1Password Vault Reference pattern
/// Example: "op://vault/item/field" or "op://vault/item"
pub static ONEPASSWORD_VAULT_REF: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bop://[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)?\b")
        .expect("BUG: Invalid regex pattern")
});

/// Bearer Token pattern (Authorization header)
/// Example: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
/// Also matches: "bearer abc123token", "Authorization: Bearer xyz"
pub static BEARER_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i:bearer)\s+[A-Za-z0-9_-]{20,}").expect("BUG: Invalid regex pattern")
});

/// URL with embedded credentials pattern
/// Example: "https://user:password@example.com/path"
pub static URL_WITH_CREDENTIALS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[a-z][a-z0-9+.-]*://[^:@\s]+:[^@\s]+@[^\s]+").expect("BUG: Invalid regex pattern")
});

/// MSSQL connection string with credentials (key-value format)
/// Example: "Server=db.example.com;Database=mydb;Password=secret123"
pub static CONNECTION_STRING_MSSQL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:Server|Data Source)=[^;]+;(?:[^;]+;)*(?:Password|Pwd)=[^;\s]+")
        .expect("BUG: Invalid regex pattern")
});

/// JDBC connection string with password parameter
/// Example: "jdbc:postgresql://host:5432/db?user=admin&password=secret"
pub static CONNECTION_STRING_JDBC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)jdbc:[a-z:]+//[^\s?]+\?[^\s]*password=[^\s&]+")
        .expect("BUG: Invalid regex pattern")
});

/// Database URL connection string (URL-based with credentials)
/// Matches postgres://, mysql://, mongodb://, redis://, amqp://, mqtt://
pub static CONNECTION_STRING_DB_URL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mqtt)s?://[^:@\s]+:[^@\s]+@[^\s]+",
    )
    .expect("BUG: Invalid regex pattern")
});

// SSH key patterns
/// SSH public key pattern
/// Formats: ssh-rsa, ssh-ed25519, ssh-ecdsa, ssh-dss
/// Example: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... user@host"
pub static SSH_PUBLIC_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bssh-(rsa|ed25519|ecdsa|dss)\s+[A-Za-z0-9+/]+=*(?:\s+\S+)?\b")
        .expect("BUG: Invalid regex pattern")
});

/// SSH fingerprint MD5 format
/// Example: "16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48"
pub static SSH_FINGERPRINT_MD5: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:[0-9a-f]{2}:){15}[0-9a-f]{2}\b").expect("BUG: Invalid regex pattern")
});

/// SSH fingerprint SHA256 format
/// Example: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"
pub static SSH_FINGERPRINT_SHA256: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bSHA256:[A-Za-z0-9+/]{43}=?\b").expect("BUG: Invalid regex pattern")
});

/// SSH private key header pattern
/// Matches various private key formats: RSA, DSA, EC, OPENSSH
/// Example: "-----BEGIN RSA PRIVATE KEY-----"
pub static SSH_PRIVATE_KEY_HEADER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|ENCRYPTED)?\s*PRIVATE\s+KEY-----")
        .expect("BUG: Invalid regex pattern")
});

pub fn uuids() -> Vec<&'static Regex> {
    vec![&*UUID_V4, &*UUID_V5, &*UUID_ANY]
}

pub fn macs() -> Vec<&'static Regex> {
    vec![&*MAC_COLON, &*MAC_HYPHEN, &*MAC_DOT]
}

pub fn ips() -> Vec<&'static Regex> {
    vec![&*IPV4, &*IPV6, &*IPV4_LABELED]
}

pub fn urls() -> Vec<&'static Regex> {
    vec![&*URL_HTTP, &*URL_FTP, &*URL_WSS, &*URL_WS, &*URL_GENERIC]
}

pub fn api_keys() -> Vec<&'static Regex> {
    vec![
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
        &*ONEPASSWORD_VAULT_REF,
        &*BEARER_TOKEN,
    ]
}

pub fn ssh_keys() -> Vec<&'static Regex> {
    vec![
        &*SSH_PUBLIC_KEY,
        &*SSH_FINGERPRINT_MD5,
        &*SSH_FINGERPRINT_SHA256,
        &*SSH_PRIVATE_KEY_HEADER,
    ]
}

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
        &*ONEPASSWORD_VAULT_REF,
        &*BEARER_TOKEN,
        &*SSH_PUBLIC_KEY,
        &*SSH_FINGERPRINT_MD5,
        &*SSH_FINGERPRINT_SHA256,
        &*SSH_PRIVATE_KEY_HEADER,
    ]
}

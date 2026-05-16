//! URL, API key, OAuth/bearer token, and connection-string patterns
//!
//! Patterns for secrets and credentials transported over the network —
//! cloud and SaaS API keys (AWS, GCP, Azure, GitHub, GitLab, Stripe, etc.),
//! bearer tokens, vault references, URLs with embedded credentials, and
//! database/MSSQL/JDBC connection strings.

#![allow(clippy::expect_used)]
// SAFETY: All regex patterns in this module are hardcoded and verified at compile time.

use once_cell::sync::Lazy;
use regex::Regex;

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

/// GCP Service Account JSON detection — matches the "type": "service_account" field
/// Example: `"type": "service_account"`
pub static GCP_SERVICE_ACCOUNT_TYPE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#""type"\s*:\s*"service_account""#).expect("BUG: Invalid regex pattern")
});

/// GCP Service Account email pattern
/// Example: "my-svc@my-project.iam.gserviceaccount.com"
pub static GCP_SERVICE_ACCOUNT_EMAIL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com")
        .expect("BUG: Invalid regex pattern")
});

/// GCP OAuth2 client secret pattern
/// Example: "GOCSPX-abcdefghijklmnopqrstuvwxyz"
pub static GCP_OAUTH_CLIENT_SECRET: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bGOCSPX-[a-zA-Z0-9_-]{28}\b").expect("BUG: Invalid regex pattern"));

/// Firebase Cloud Messaging server key pattern
/// Example: "AAAAxxxxxx..." (140+ chars after AAAA prefix)
pub static FIREBASE_FCM_SERVER_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bAAAA[a-zA-Z0-9_-]{140,}\b").expect("BUG: Invalid regex pattern"));

/// GitHub Personal Access Token patterns
/// Formats: ghp_ (personal), gho_ (OAuth), ghu_ (user-to-server), ghs_ (server-to-server), ghr_ (refresh)
/// Also matches fine-grained PATs: github_pat_{22}_{59}
/// Example: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
pub static API_KEY_GITHUB: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:\bgh[prsou]_[a-zA-Z0-9]{36,}\b|\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b)")
        .expect("BUG: Invalid regex pattern")
});

/// GitLab token patterns
/// Formats: glpat- (personal), gldt- (deploy), glptt- (pipeline trigger),
/// glcbt- (CI job), glrt- (runner), glft- (feed), glsoat- (SCIM), glimt- (incoming mail)
/// Example: "glpat-xxxxxxxxxxxxxxxxxxxx", "glrt-xxxxxxxxxxxxxxxxxxxx"
pub static API_KEY_GITLAB: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:glpat|gldt|glptt|glcbt|glrt|glft|glsoat|glimt)-[a-zA-Z0-9_-]{20,}\b")
        .expect("BUG: Invalid regex pattern")
});

/// Bitbucket Cloud App Password
/// Format: ATBB + 32 alphanumeric characters
/// Example: "ATBBabcdefghijklmnopqrstuvwxyz012345"
pub static API_KEY_BITBUCKET: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bATBB[a-zA-Z0-9]{32}\b").expect("BUG: Invalid regex pattern"));

/// Azure Storage Account Key pattern (base64, 88 characters)
/// Example: "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=..."
pub static API_KEY_AZURE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i:AccountKey)=([A-Za-z0-9+/=]{88})").expect("BUG: Invalid regex pattern")
});

/// Azure Storage Account connection string
/// Example: "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc...==;EndpointSuffix=core.windows.net"
pub static AZURE_STORAGE_CONN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]{3,24};AccountKey=[A-Za-z0-9+/=]{88};EndpointSuffix=[^\s;]+")
        .expect("BUG: Invalid regex pattern")
});

/// Azure Service Bus / Event Hub connection string
/// Example: "Endpoint=sb://mybus.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=abc...=="
pub static AZURE_SERVICE_BUS_CONN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)Endpoint=sb://[a-z0-9-]+\.servicebus\.windows\.net/?;SharedAccessKeyName=[^;\s]+;SharedAccessKey=[A-Za-z0-9+/=]{44}")
        .expect("BUG: Invalid regex pattern")
});

/// Azure Cosmos DB connection string
/// Example: "AccountEndpoint=https://mydb.documents.azure.com:443/;AccountKey=abc...=="
pub static AZURE_COSMOS_CONN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)AccountEndpoint=https://[a-z0-9-]+\.documents\.azure\.com:\d+/?;AccountKey=[A-Za-z0-9+/=]{88}")
        .expect("BUG: Invalid regex pattern")
});

/// Azure SQL connection string with password
/// Example: "Server=tcp:myserver.database.windows.net,1433;...Password=secret123"
pub static AZURE_SQL_CONN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)Server=tcp:[a-z0-9-]+\.database\.windows\.net[^;]*;(?:[^;]+;)*(?:Password|Pwd)=[^;\s]+")
        .expect("BUG: Invalid regex pattern")
});

/// Azure App Configuration connection string
/// Example: "Endpoint=https://myconfig.azconfig.io;Id=abc;Secret=def...=="
pub static AZURE_APP_CONFIG_CONN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)Endpoint=https://[a-z0-9-]+\.azconfig\.io;Id=[^;\s]+;Secret=[A-Za-z0-9+/=]+")
        .expect("BUG: Invalid regex pattern")
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

/// OpenAI legacy API key pattern
/// Format: sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}
pub static API_KEY_OPENAI_LEGACY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b")
        .expect("BUG: Invalid regex pattern")
});

/// OpenAI project API key pattern
/// Format: sk-proj-[a-zA-Z0-9_-]{80,}
pub static API_KEY_OPENAI_PROJECT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bsk-proj-[a-zA-Z0-9_-]{80,}\b").expect("BUG: Invalid regex pattern")
});

/// OpenAI organization key pattern
/// Format: org-[a-zA-Z0-9]{24}
pub static API_KEY_OPENAI_ORG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\borg-[a-zA-Z0-9]{24}\b").expect("BUG: Invalid regex pattern"));

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

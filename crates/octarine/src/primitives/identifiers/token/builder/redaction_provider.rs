//! Provider-specific redaction methods for `TokenIdentifierBuilder`
//!
//! AWS, GitHub, Stripe, GCP, Azure, Square, Shopify, PayPal, Mailchimp,
//! Mailgun, Resend, Brevo, Databricks, Vault, Cloudflare, NPM, PyPI, NuGet,
//! Artifactory, Docker Hub, Telegram, SendGrid, Twilio, Slack, Discord.

use crate::primitives::identifiers::token::{redaction, sanitization};

use super::TokenIdentifierBuilder;

impl TokenIdentifierBuilder {
    // =========================================================================
    // Provider-Specific Redaction (AWS)
    // =========================================================================

    /// Redact AWS key (show provider by default)
    ///
    /// Example: "AKIA..." → "<AWS-KEY>"
    pub fn redact_aws_key(&self, key: &str) -> String {
        sanitization::redact_aws_key(key, redaction::ApiKeyRedactionStrategy::ShowProvider)
    }

    /// Mask AWS key (convenience wrapper)
    pub fn mask_aws_key(&self, key: &str) -> String {
        sanitization::mask_aws_key(key)
    }

    // =========================================================================
    // Provider-Specific Redaction (AWS Session Token)
    // =========================================================================

    /// Redact AWS session token (show provider by default)
    pub fn redact_aws_session_token(&self, token: &str) -> String {
        sanitization::redact_aws_session_token(
            token,
            redaction::ApiKeyRedactionStrategy::ShowProvider,
        )
    }

    /// Mask AWS session token (convenience wrapper)
    pub fn mask_aws_session_token(&self, token: &str) -> String {
        sanitization::mask_aws_session_token(token)
    }

    // =========================================================================
    // Provider-Specific Redaction (GitHub)
    // =========================================================================

    /// Redact GitHub token (show provider by default)
    ///
    /// Example: "ghp_..." → "<GITHUB-TOKEN>"
    pub fn redact_github_token(&self, token: &str) -> String {
        sanitization::redact_github_token(token, redaction::ApiKeyRedactionStrategy::ShowProvider)
    }

    /// Mask GitHub token (convenience wrapper)
    pub fn mask_github_token(&self, token: &str) -> String {
        sanitization::mask_github_token(token)
    }

    // =========================================================================
    // Provider-Specific Redaction (Stripe)
    // =========================================================================

    /// Redact Stripe key (show prefix by default)
    ///
    /// Example: "sk_live_..." → "sk_live_****"
    pub fn redact_stripe_key(&self, key: &str) -> String {
        sanitization::redact_stripe_key(key, redaction::ApiKeyRedactionStrategy::ShowPrefix)
    }

    /// Mask Stripe key (convenience wrapper)
    pub fn mask_stripe_key(&self, key: &str) -> String {
        sanitization::mask_stripe_key(key)
    }

    // =========================================================================
    // Provider-Specific Redaction (GCP)
    // =========================================================================

    /// Redact GCP key (show provider by default)
    ///
    /// Example: "AIza..." → "<GCP-KEY>"
    pub fn redact_gcp_key(&self, key: &str) -> String {
        sanitization::redact_gcp_key(key, redaction::ApiKeyRedactionStrategy::ShowProvider)
    }

    /// Mask GCP key (convenience wrapper)
    pub fn mask_gcp_key(&self, key: &str) -> String {
        sanitization::mask_gcp_key(key)
    }

    // =========================================================================
    // Provider-Specific Redaction (Azure)
    // =========================================================================

    /// Redact Azure key (show provider by default)
    ///
    /// Example: "..." → "<AZURE-KEY>"
    pub fn redact_azure_key(&self, key: &str) -> String {
        sanitization::redact_azure_key(key, redaction::ApiKeyRedactionStrategy::ShowProvider)
    }

    /// Mask Azure key (convenience wrapper)
    pub fn mask_azure_key(&self, key: &str) -> String {
        sanitization::mask_azure_key(key)
    }

    // =========================================================================
    // Provider-Specific Masking (Square, Shopify, PayPal, etc.)
    // =========================================================================

    /// Mask Square API key (convenience wrapper)
    pub fn mask_square_token(&self, key: &str) -> String {
        sanitization::mask_square_token(key)
    }

    /// Mask Shopify API token (convenience wrapper)
    pub fn mask_shopify_token(&self, token: &str) -> String {
        sanitization::mask_shopify_token(token)
    }

    /// Mask PayPal/Braintree access token (convenience wrapper)
    pub fn mask_paypal_token(&self, token: &str) -> String {
        sanitization::mask_paypal_token(token)
    }

    /// Mask Mailchimp API key (convenience wrapper)
    pub fn mask_mailchimp_key(&self, key: &str) -> String {
        sanitization::mask_mailchimp_key(key)
    }

    /// Mask Mailgun API key (convenience wrapper)
    pub fn mask_mailgun_key(&self, key: &str) -> String {
        sanitization::mask_mailgun_key(key)
    }

    /// Mask Resend API key (convenience wrapper)
    pub fn mask_resend_key(&self, key: &str) -> String {
        sanitization::mask_resend_key(key)
    }

    /// Mask Brevo API key (convenience wrapper)
    pub fn mask_brevo_key(&self, key: &str) -> String {
        sanitization::mask_brevo_key(key)
    }

    /// Mask Databricks access token (convenience wrapper)
    pub fn mask_databricks_token(&self, token: &str) -> String {
        sanitization::mask_databricks_token(token)
    }

    /// Mask HashiCorp Vault token (convenience wrapper)
    pub fn mask_vault_token(&self, token: &str) -> String {
        sanitization::mask_vault_token(token)
    }

    /// Mask Cloudflare Origin CA key (convenience wrapper)
    pub fn mask_cloudflare_ca_key(&self, key: &str) -> String {
        sanitization::mask_cloudflare_ca_key(key)
    }

    /// Mask NPM access token (convenience wrapper)
    pub fn mask_npm_token(&self, token: &str) -> String {
        sanitization::mask_npm_token(token)
    }

    /// Mask PyPI API token (convenience wrapper)
    pub fn mask_pypi_token(&self, token: &str) -> String {
        sanitization::mask_pypi_token(token)
    }

    /// Mask NuGet API key (convenience wrapper)
    pub fn mask_nuget_key(&self, key: &str) -> String {
        sanitization::mask_nuget_key(key)
    }

    /// Mask Artifactory API key (convenience wrapper)
    pub fn mask_artifactory_token(&self, token: &str) -> String {
        sanitization::mask_artifactory_token(token)
    }

    /// Mask Docker Hub PAT (convenience wrapper)
    pub fn mask_docker_hub_token(&self, token: &str) -> String {
        sanitization::mask_docker_hub_token(token)
    }

    /// Mask Telegram bot token (convenience wrapper)
    pub fn mask_telegram_bot_token(&self, token: &str) -> String {
        sanitization::mask_telegram_bot_token(token)
    }

    /// Mask SendGrid API key (convenience wrapper)
    pub fn mask_sendgrid_key(&self, key: &str) -> String {
        sanitization::mask_sendgrid_key(key)
    }

    /// Mask Twilio Account SID (convenience wrapper)
    pub fn mask_twilio_account_sid(&self, sid: &str) -> String {
        sanitization::mask_twilio_account_sid(sid)
    }

    /// Mask Twilio API Key SID (convenience wrapper)
    pub fn mask_twilio_api_key_sid(&self, sid: &str) -> String {
        sanitization::mask_twilio_api_key_sid(sid)
    }

    /// Mask Slack token (convenience wrapper)
    pub fn mask_slack_token(&self, token: &str) -> String {
        sanitization::mask_slack_token(token)
    }

    /// Mask Slack webhook URL (convenience wrapper)
    pub fn mask_slack_webhook(&self, url: &str) -> String {
        sanitization::mask_slack_webhook(url)
    }

    /// Mask Discord bot token (convenience wrapper)
    pub fn mask_discord_token(&self, token: &str) -> String {
        sanitization::mask_discord_token(token)
    }

    /// Mask Discord webhook URL (convenience wrapper)
    pub fn mask_discord_webhook(&self, url: &str) -> String {
        sanitization::mask_discord_webhook(url)
    }
}

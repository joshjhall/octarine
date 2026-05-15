//! Provider-specific redaction and masking — AWS, GitHub, Stripe, GCP,
//! Azure, Square, Shopify, PayPal, Mailchimp, Mailgun, Resend, Brevo,
//! Databricks, Vault, Cloudflare, NPM, PyPI, NuGet, Artifactory, Docker
//! Hub, Telegram, SendGrid, Twilio, Slack, Discord.

use super::*;

impl TokenBuilder {
    /// Redact AWS key
    #[must_use]
    pub fn redact_aws_key(&self, key: &str) -> String {
        self.inner.redact_aws_key(key)
    }

    /// Mask AWS key
    #[must_use]
    pub fn mask_aws_key(&self, key: &str) -> String {
        self.inner.mask_aws_key(key)
    }

    /// Redact AWS session token
    #[must_use]
    pub fn redact_aws_session_token(&self, token: &str) -> String {
        self.inner.redact_aws_session_token(token)
    }

    /// Mask AWS session token
    #[must_use]
    pub fn mask_aws_session_token(&self, token: &str) -> String {
        self.inner.mask_aws_session_token(token)
    }

    /// Redact GitHub token
    #[must_use]
    pub fn redact_github_token(&self, token: &str) -> String {
        self.inner.redact_github_token(token)
    }

    /// Mask GitHub token
    #[must_use]
    pub fn mask_github_token(&self, token: &str) -> String {
        self.inner.mask_github_token(token)
    }

    /// Redact Stripe key
    #[must_use]
    pub fn redact_stripe_key(&self, key: &str) -> String {
        self.inner.redact_stripe_key(key)
    }

    /// Mask Stripe key
    #[must_use]
    pub fn mask_stripe_key(&self, key: &str) -> String {
        self.inner.mask_stripe_key(key)
    }

    /// Redact GCP key
    #[must_use]
    pub fn redact_gcp_key(&self, key: &str) -> String {
        self.inner.redact_gcp_key(key)
    }

    /// Mask GCP key
    #[must_use]
    pub fn mask_gcp_key(&self, key: &str) -> String {
        self.inner.mask_gcp_key(key)
    }

    /// Redact Azure key
    #[must_use]
    pub fn redact_azure_key(&self, key: &str) -> String {
        self.inner.redact_azure_key(key)
    }

    /// Mask Azure key
    #[must_use]
    pub fn mask_azure_key(&self, key: &str) -> String {
        self.inner.mask_azure_key(key)
    }

    /// Mask Square API key
    #[must_use]
    pub fn mask_square_token(&self, key: &str) -> String {
        self.inner.mask_square_token(key)
    }

    /// Mask Shopify API token
    #[must_use]
    pub fn mask_shopify_token(&self, token: &str) -> String {
        self.inner.mask_shopify_token(token)
    }

    /// Mask PayPal/Braintree access token
    #[must_use]
    pub fn mask_paypal_token(&self, token: &str) -> String {
        self.inner.mask_paypal_token(token)
    }

    /// Mask Mailchimp API key
    #[must_use]
    pub fn mask_mailchimp_key(&self, key: &str) -> String {
        self.inner.mask_mailchimp_key(key)
    }

    /// Mask Mailgun API key
    #[must_use]
    pub fn mask_mailgun_key(&self, key: &str) -> String {
        self.inner.mask_mailgun_key(key)
    }

    /// Mask Resend API key
    #[must_use]
    pub fn mask_resend_key(&self, key: &str) -> String {
        self.inner.mask_resend_key(key)
    }

    /// Mask Brevo API key
    #[must_use]
    pub fn mask_brevo_key(&self, key: &str) -> String {
        self.inner.mask_brevo_key(key)
    }

    /// Mask Databricks access token
    #[must_use]
    pub fn mask_databricks_token(&self, token: &str) -> String {
        self.inner.mask_databricks_token(token)
    }

    /// Mask HashiCorp Vault token
    #[must_use]
    pub fn mask_vault_token(&self, token: &str) -> String {
        self.inner.mask_vault_token(token)
    }

    /// Mask Cloudflare Origin CA key
    #[must_use]
    pub fn mask_cloudflare_ca_key(&self, key: &str) -> String {
        self.inner.mask_cloudflare_ca_key(key)
    }

    /// Mask NPM access token
    #[must_use]
    pub fn mask_npm_token(&self, token: &str) -> String {
        self.inner.mask_npm_token(token)
    }

    /// Mask PyPI API token
    #[must_use]
    pub fn mask_pypi_token(&self, token: &str) -> String {
        self.inner.mask_pypi_token(token)
    }

    /// Mask NuGet API key
    #[must_use]
    pub fn mask_nuget_key(&self, key: &str) -> String {
        self.inner.mask_nuget_key(key)
    }

    /// Mask Artifactory API key
    #[must_use]
    pub fn mask_artifactory_token(&self, token: &str) -> String {
        self.inner.mask_artifactory_token(token)
    }

    /// Mask Docker Hub PAT
    #[must_use]
    pub fn mask_docker_hub_token(&self, token: &str) -> String {
        self.inner.mask_docker_hub_token(token)
    }

    /// Mask Telegram bot token
    #[must_use]
    pub fn mask_telegram_bot_token(&self, token: &str) -> String {
        self.inner.mask_telegram_bot_token(token)
    }

    /// Mask SendGrid API key
    #[must_use]
    pub fn mask_sendgrid_key(&self, key: &str) -> String {
        self.inner.mask_sendgrid_key(key)
    }

    /// Mask Twilio Account SID
    #[must_use]
    pub fn mask_twilio_account_sid(&self, sid: &str) -> String {
        self.inner.mask_twilio_account_sid(sid)
    }

    /// Mask Twilio API Key SID
    #[must_use]
    pub fn mask_twilio_api_key_sid(&self, sid: &str) -> String {
        self.inner.mask_twilio_api_key_sid(sid)
    }

    /// Mask Slack token
    #[must_use]
    pub fn mask_slack_token(&self, token: &str) -> String {
        self.inner.mask_slack_token(token)
    }

    /// Mask Slack webhook URL
    #[must_use]
    pub fn mask_slack_webhook(&self, url: &str) -> String {
        self.inner.mask_slack_webhook(url)
    }

    /// Mask Discord bot token
    #[must_use]
    pub fn mask_discord_token(&self, token: &str) -> String {
        self.inner.mask_discord_token(token)
    }

    /// Mask Discord webhook URL
    #[must_use]
    pub fn mask_discord_webhook(&self, url: &str) -> String {
        self.inner.mask_discord_webhook(url)
    }
}

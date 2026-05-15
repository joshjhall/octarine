//! Detection methods — `is_*` predicates and token-type detection.
//!
//! Includes provider-specific predicates (AWS, GCP, GitHub, Stripe, etc.)
//! and the cross-domain token-type detection helpers.

use super::*;

impl TokenBuilder {
    /// Check if value is a JWT token
    #[must_use]
    pub fn is_jwt(&self, value: &str) -> bool {
        self.inner.is_jwt(value)
    }

    /// Check if value is an API key
    #[must_use]
    pub fn is_api_key(&self, value: &str) -> bool {
        self.inner.is_api_key(value)
    }

    /// Check if value is an AWS Access Key
    #[must_use]
    pub fn is_aws_access_key(&self, value: &str) -> bool {
        self.inner.is_aws_access_key(value)
    }

    /// Check if value is an AWS Secret Key
    #[must_use]
    pub fn is_aws_secret_key(&self, value: &str) -> bool {
        self.inner.is_aws_secret_key(value)
    }

    /// Check if value is an AWS Session Token (STS temporary credential)
    #[must_use]
    pub fn is_aws_session_token(&self, value: &str) -> bool {
        self.inner.is_aws_session_token(value)
    }

    /// Check if value is a GCP API key
    #[must_use]
    pub fn is_gcp_api_key(&self, value: &str) -> bool {
        self.inner.is_gcp_api_key(value)
    }

    /// Check if value is a GitHub token
    #[must_use]
    pub fn is_github_token(&self, value: &str) -> bool {
        self.inner.is_github_token(value)
    }

    /// Check if value is an Azure key
    #[must_use]
    pub fn is_azure_key(&self, value: &str) -> bool {
        self.inner.is_azure_key(value)
    }

    /// Check if value is a Stripe key
    #[must_use]
    pub fn is_stripe_key(&self, value: &str) -> bool {
        self.inner.is_stripe_key(value)
    }

    /// Check if value is a Square API key
    #[must_use]
    pub fn is_square_token(&self, value: &str) -> bool {
        self.inner.is_square_token(value)
    }

    /// Check if value is a Shopify API token
    #[must_use]
    pub fn is_shopify_token(&self, value: &str) -> bool {
        self.inner.is_shopify_token(value)
    }

    /// Check if value is a PayPal/Braintree access token
    #[must_use]
    pub fn is_paypal_token(&self, value: &str) -> bool {
        self.inner.is_paypal_token(value)
    }

    /// Check if value is a Mailchimp API key
    #[must_use]
    pub fn is_mailchimp_key(&self, value: &str) -> bool {
        self.inner.is_mailchimp_key(value)
    }

    /// Check if value is a Mailgun API key
    #[must_use]
    pub fn is_mailgun_key(&self, value: &str) -> bool {
        self.inner.is_mailgun_key(value)
    }

    /// Check if value is a Resend API key
    #[must_use]
    pub fn is_resend_key(&self, value: &str) -> bool {
        self.inner.is_resend_key(value)
    }

    /// Check if value is a Brevo API key
    #[must_use]
    pub fn is_brevo_key(&self, value: &str) -> bool {
        self.inner.is_brevo_key(value)
    }

    /// Check if value is a Databricks access token
    #[must_use]
    pub fn is_databricks_token(&self, value: &str) -> bool {
        self.inner.is_databricks_token(value)
    }

    /// Check if value is a HashiCorp Vault token
    #[must_use]
    pub fn is_vault_token(&self, value: &str) -> bool {
        self.inner.is_vault_token(value)
    }

    /// Check if value is a Cloudflare Origin CA key
    #[must_use]
    pub fn is_cloudflare_ca_key(&self, value: &str) -> bool {
        self.inner.is_cloudflare_ca_key(value)
    }

    /// Check if value is an NPM access token
    #[must_use]
    pub fn is_npm_token(&self, value: &str) -> bool {
        self.inner.is_npm_token(value)
    }

    /// Check if value is a PyPI API token
    #[must_use]
    pub fn is_pypi_token(&self, value: &str) -> bool {
        self.inner.is_pypi_token(value)
    }

    /// Check if value is a NuGet API key
    #[must_use]
    pub fn is_nuget_key(&self, value: &str) -> bool {
        self.inner.is_nuget_key(value)
    }

    /// Check if value is an Artifactory API key
    #[must_use]
    pub fn is_artifactory_token(&self, value: &str) -> bool {
        self.inner.is_artifactory_token(value)
    }

    /// Check if value is a Docker Hub PAT
    #[must_use]
    pub fn is_docker_hub_token(&self, value: &str) -> bool {
        self.inner.is_docker_hub_token(value)
    }

    /// Check if value is a Telegram bot token
    #[must_use]
    pub fn is_telegram_bot_token(&self, value: &str) -> bool {
        self.inner.is_telegram_bot_token(value)
    }

    /// Check if value is a SendGrid API key
    #[must_use]
    pub fn is_sendgrid_key(&self, value: &str) -> bool {
        self.inner.is_sendgrid_key(value)
    }

    /// Check if value is a Twilio Account SID
    #[must_use]
    pub fn is_twilio_account_sid(&self, value: &str) -> bool {
        self.inner.is_twilio_account_sid(value)
    }

    /// Check if value is a Twilio API Key SID
    #[must_use]
    pub fn is_twilio_api_key_sid(&self, value: &str) -> bool {
        self.inner.is_twilio_api_key_sid(value)
    }

    /// Check if value is a Slack token (any format)
    #[must_use]
    pub fn is_slack_token(&self, value: &str) -> bool {
        self.inner.is_slack_token(value)
    }

    /// Check if value is a Slack webhook URL
    #[must_use]
    pub fn is_slack_webhook(&self, value: &str) -> bool {
        self.inner.is_slack_webhook(value)
    }

    /// Check if value is a Discord bot token
    #[must_use]
    pub fn is_discord_token(&self, value: &str) -> bool {
        self.inner.is_discord_token(value)
    }

    /// Check if value is a Discord webhook URL
    #[must_use]
    pub fn is_discord_webhook(&self, value: &str) -> bool {
        self.inner.is_discord_webhook(value)
    }

    /// Check if value is a GitLab token
    #[must_use]
    pub fn is_gitlab_token(&self, value: &str) -> bool {
        self.inner.is_gitlab_token(value)
    }

    /// Check if value is a 1Password service account token
    #[must_use]
    pub fn is_onepassword_token(&self, value: &str) -> bool {
        self.inner.is_onepassword_token(value)
    }

    /// Check if value is a 1Password vault reference
    #[must_use]
    pub fn is_onepassword_vault_ref(&self, value: &str) -> bool {
        self.inner.is_onepassword_vault_ref(value)
    }

    /// Check if value is a Bearer token
    #[must_use]
    pub fn is_bearer_token(&self, value: &str) -> bool {
        self.inner.is_bearer_token(value)
    }

    /// Check if value is a URL with embedded credentials
    #[must_use]
    pub fn is_url_with_credentials(&self, value: &str) -> bool {
        self.inner.is_url_with_credentials(value)
    }

    /// Check if value is an SSH public key
    #[must_use]
    pub fn is_ssh_public_key(&self, value: &str) -> bool {
        self.inner.is_ssh_public_key(value)
    }

    /// Check if value is an SSH private key
    #[must_use]
    pub fn is_ssh_private_key(&self, value: &str) -> bool {
        self.inner.is_ssh_private_key(value)
    }

    /// Check if value is an SSH fingerprint
    #[must_use]
    pub fn is_ssh_fingerprint(&self, value: &str) -> bool {
        self.inner.is_ssh_fingerprint(value)
    }

    /// Check if value is an SSH key or fingerprint
    #[must_use]
    pub fn is_ssh_key(&self, value: &str) -> bool {
        self.inner.is_ssh_key(value)
    }

    /// Check if value looks like a session ID (heuristic)
    #[must_use]
    pub fn is_likely_session_id(&self, value: &str) -> bool {
        self.inner.is_likely_session_id(value)
    }

    /// Detect the specific type of token
    #[must_use]
    pub fn detect_token_type(&self, value: &str) -> Option<TokenType> {
        self.inner.detect_token_type(value)
    }

    /// Check if value is any type of token
    #[must_use]
    pub fn is_token_identifier(&self, value: &str) -> bool {
        self.inner.is_token_identifier(value)
    }

    /// Detect token identifier type (dual-API contract).
    ///
    /// Companion to [`Self::is_token_identifier`] that returns the matched
    /// `IdentifierType`. Unlike [`Self::detect_token_type`], the result uses
    /// the cross-domain `IdentifierType` enum so tokens can be compared with
    /// identifiers from other domains (network, personal, financial, etc.).
    #[must_use]
    pub fn detect_token_identifier(&self, value: &str) -> Option<IdentifierType> {
        self.inner.detect_token_identifier(value)
    }
}

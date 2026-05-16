//! Detection methods for `TokenIdentifierBuilder`
//!
//! All `is_*` and `detect_*` methods that classify a string as a particular
//! kind of token without modifying it. Mirrors the per-section split landed
//! in the Layer 3 builder (#335).

use crate::primitives::identifiers::token::detection;
use crate::primitives::identifiers::types::IdentifierType;

use super::TokenIdentifierBuilder;

impl TokenIdentifierBuilder {
    /// Check if value is a JWT token
    pub fn is_jwt(&self, value: &str) -> bool {
        detection::is_jwt(value)
    }

    /// Check if value is an API key
    pub fn is_api_key(&self, value: &str) -> bool {
        detection::is_api_key(value)
    }

    /// Check if value is an AWS Access Key
    pub fn is_aws_access_key(&self, value: &str) -> bool {
        detection::is_aws_access_key(value)
    }

    /// Check if value is an AWS Secret Key
    pub fn is_aws_secret_key(&self, value: &str) -> bool {
        detection::is_aws_secret_key(value)
    }

    /// Check if value is an AWS Session Token (STS temporary credential)
    pub fn is_aws_session_token(&self, value: &str) -> bool {
        detection::is_aws_session_token(value)
    }

    /// Check if value is a GCP API key
    pub fn is_gcp_api_key(&self, value: &str) -> bool {
        detection::is_gcp_api_key(value)
    }

    /// Check if value is a GitHub token
    pub fn is_github_token(&self, value: &str) -> bool {
        detection::is_github_token(value)
    }

    /// Check if value is an Azure key
    pub fn is_azure_key(&self, value: &str) -> bool {
        detection::is_azure_key(value)
    }

    /// Check if value is an Azure connection string (Storage, Service Bus, Cosmos DB, SQL, App Config)
    pub fn is_azure_connection_string(&self, value: &str) -> bool {
        detection::is_azure_connection_string(value)
    }

    /// Check if value is a Stripe key
    pub fn is_stripe_key(&self, value: &str) -> bool {
        detection::is_stripe_key(value)
    }

    /// Check if value is a Square API key
    pub fn is_square_token(&self, value: &str) -> bool {
        detection::is_square_token(value)
    }

    /// Check if value is a Shopify API token
    pub fn is_shopify_token(&self, value: &str) -> bool {
        detection::is_shopify_token(value)
    }

    /// Check if value is a PayPal/Braintree access token
    pub fn is_paypal_token(&self, value: &str) -> bool {
        detection::is_paypal_token(value)
    }

    /// Check if value is a Mailchimp API key
    pub fn is_mailchimp_key(&self, value: &str) -> bool {
        detection::is_mailchimp_key(value)
    }

    /// Check if value is a Mailgun API key
    pub fn is_mailgun_key(&self, value: &str) -> bool {
        detection::is_mailgun_key(value)
    }

    /// Check if value is a Resend API key
    pub fn is_resend_key(&self, value: &str) -> bool {
        detection::is_resend_key(value)
    }

    /// Check if value is a Brevo API key
    pub fn is_brevo_key(&self, value: &str) -> bool {
        detection::is_brevo_key(value)
    }

    /// Check if value is a Databricks access token
    pub fn is_databricks_token(&self, value: &str) -> bool {
        detection::is_databricks_token(value)
    }

    /// Check if value is a HashiCorp Vault token
    pub fn is_vault_token(&self, value: &str) -> bool {
        detection::is_vault_token(value)
    }

    /// Check if value is a Cloudflare Origin CA key
    pub fn is_cloudflare_ca_key(&self, value: &str) -> bool {
        detection::is_cloudflare_ca_key(value)
    }

    /// Check if value is an NPM access token
    pub fn is_npm_token(&self, value: &str) -> bool {
        detection::is_npm_token(value)
    }

    /// Check if value is a PyPI API token
    pub fn is_pypi_token(&self, value: &str) -> bool {
        detection::is_pypi_token(value)
    }

    /// Check if value is a NuGet API key
    pub fn is_nuget_key(&self, value: &str) -> bool {
        detection::is_nuget_key(value)
    }

    /// Check if value is an Artifactory API key
    pub fn is_artifactory_token(&self, value: &str) -> bool {
        detection::is_artifactory_token(value)
    }

    /// Check if value is a Docker Hub PAT
    pub fn is_docker_hub_token(&self, value: &str) -> bool {
        detection::is_docker_hub_token(value)
    }

    /// Check if value is a Telegram bot token
    pub fn is_telegram_bot_token(&self, value: &str) -> bool {
        detection::is_telegram_bot_token(value)
    }

    /// Check if value is a SendGrid API key
    pub fn is_sendgrid_key(&self, value: &str) -> bool {
        detection::is_sendgrid_key(value)
    }

    /// Check if value is an OpenAI API key
    pub fn is_openai_key(&self, value: &str) -> bool {
        detection::is_openai_key(value)
    }

    /// Check if value is a Twilio Account SID
    pub fn is_twilio_account_sid(&self, value: &str) -> bool {
        detection::is_twilio_account_sid(value)
    }

    /// Check if value is a Twilio API Key SID
    pub fn is_twilio_api_key_sid(&self, value: &str) -> bool {
        detection::is_twilio_api_key_sid(value)
    }

    /// Check if value is a Slack token (any format)
    pub fn is_slack_token(&self, value: &str) -> bool {
        detection::is_slack_token(value)
    }

    /// Check if value is a Slack webhook URL
    pub fn is_slack_webhook(&self, value: &str) -> bool {
        detection::is_slack_webhook(value)
    }

    /// Check if value is a Discord bot token
    pub fn is_discord_token(&self, value: &str) -> bool {
        detection::is_discord_token(value)
    }

    /// Check if value is a Discord webhook URL
    pub fn is_discord_webhook(&self, value: &str) -> bool {
        detection::is_discord_webhook(value)
    }

    /// Check if value is a GitLab token
    pub fn is_gitlab_token(&self, value: &str) -> bool {
        detection::is_gitlab_token(value)
    }

    /// Check if value is a Bitbucket Cloud App Password
    pub fn is_bitbucket_token(&self, value: &str) -> bool {
        detection::is_bitbucket_token(value)
    }

    /// Check if value is a 1Password service account token
    pub fn is_onepassword_token(&self, value: &str) -> bool {
        detection::is_onepassword_token(value)
    }

    /// Check if value is a 1Password vault reference (op://vault/item/field)
    pub fn is_onepassword_vault_ref(&self, value: &str) -> bool {
        detection::is_onepassword_vault_ref(value)
    }

    /// Check if value is a Bearer token
    pub fn is_bearer_token(&self, value: &str) -> bool {
        detection::is_bearer_token(value)
    }

    /// Check if value is a URL with embedded credentials
    pub fn is_url_with_credentials(&self, value: &str) -> bool {
        detection::is_url_with_credentials(value)
    }

    /// Check if value is an SSH public key
    pub fn is_ssh_public_key(&self, value: &str) -> bool {
        detection::is_ssh_public_key(value)
    }

    /// Check if value is an SSH private key
    pub fn is_ssh_private_key(&self, value: &str) -> bool {
        detection::is_ssh_private_key(value)
    }

    /// Check if value is an SSH fingerprint
    pub fn is_ssh_fingerprint(&self, value: &str) -> bool {
        detection::is_ssh_fingerprint(value)
    }

    /// Check if value is an SSH key or fingerprint
    pub fn is_ssh_key(&self, value: &str) -> bool {
        detection::is_ssh_key(value)
    }

    /// Check if value looks like a session ID (heuristic)
    pub fn is_likely_session_id(&self, value: &str) -> bool {
        detection::is_likely_session_id(value)
    }

    /// Detect the specific type of token
    ///
    /// Returns the token type if detected, or None if not a recognized token
    pub fn detect_token_type(&self, value: &str) -> Option<detection::TokenType> {
        detection::detect_token_type(value)
    }

    /// Check if value is any type of token
    pub fn is_token_identifier(&self, value: &str) -> bool {
        detection::is_token_identifier(value)
    }

    /// Detect token identifier type (dual-API contract).
    ///
    /// Companion to [`Self::is_token_identifier`] that returns the matched
    /// `IdentifierType` (see [`detection::detect_token_identifier`] for the
    /// `TokenType` → `IdentifierType` mapping).
    pub fn detect_token_identifier(&self, value: &str) -> Option<IdentifierType> {
        detection::detect_token_identifier(value)
    }
}

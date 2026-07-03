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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    fn builder() -> TokenIdentifierBuilder {
        TokenIdentifierBuilder::new()
    }

    // A known-valid Stripe key (matches the API_KEY_STRIPE pattern), reused
    // from the sanitization test suite. Split to avoid secret scanners.
    fn stripe_key() -> String {
        format!("sk_live_{}", "EXAMPLE000000000KEY01abcdef")
    }

    // ========================================================================
    // Provider redaction with ShowProvider — prefix-driven, so the expected
    // token is fully determined by the key's leading bytes (RFC-style prefixes).
    // ========================================================================

    #[test]
    fn test_redact_aws_key_show_provider() {
        let b = builder();
        // AKIA-prefixed access keys map to the AWS provider token.
        let key = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        assert_eq!(b.redact_aws_key(&key), "[AWS_KEY]");
    }

    #[test]
    fn test_redact_github_token_show_provider() {
        let b = builder();
        // ghp_ (and gho_/ghs_/ghr_) prefixes map to the GitHub token.
        let token = format!("ghp_{}", "0123456789abcdefghij0123456789abcdef");
        assert_eq!(b.redact_github_token(&token), "[GITHUB_TOKEN]");
    }

    #[test]
    fn test_redact_gcp_key_show_provider() {
        let b = builder();
        let key = format!("AIza{}", "0123456789abcdefghij0123456789abcde");
        assert_eq!(b.redact_gcp_key(&key), "[GCP_KEY]");
    }

    #[test]
    fn test_redact_azure_key_show_provider_falls_back_to_generic() {
        let b = builder();
        // Azure keys have no distinct textual prefix, so ShowProvider yields
        // the generic API key token.
        let key = "0123456789abcdef0123456789abcdef";
        assert_eq!(b.redact_azure_key(key), "[API_KEY]");
    }

    #[test]
    fn test_redact_aws_session_token_show_provider() {
        let b = builder();
        // Session tokens are not AKIA-prefixed; ShowProvider yields generic.
        let token = "0123456789abcdefghijklmnopqrstuvwxyz";
        assert_eq!(b.redact_aws_session_token(token), "[API_KEY]");
    }

    #[test]
    fn test_redact_stripe_key_show_prefix() {
        let b = builder();
        // Stripe uses ShowPrefix by default: everything through the final
        // underscore is retained, the secret body is masked with ****.
        assert_eq!(b.redact_stripe_key(&stripe_key()), "sk_live_****");
    }

    // ========================================================================
    // mask_* backed by mask_api_key — first 12 chars shown, rest "***"
    // ========================================================================

    #[test]
    fn test_mask_api_key_backed_valid_shows_prefix() {
        let b = builder();
        // First 12 chars of "sk_live_EXAMPLE..." then "***".
        assert_eq!(b.mask_stripe_key(&stripe_key()), "sk_live_EXAM***");
    }

    #[test]
    fn test_mask_api_key_backed_invalid_returns_token() {
        let b = builder();
        // Non-key input is not recognized; masking returns the type token.
        assert_eq!(b.mask_aws_key("not-a-key"), "[API_KEY]");
        assert_eq!(b.mask_gcp_key("short"), "[API_KEY]");
    }

    // ========================================================================
    // Structured provider masks — format-preserving, no detection required.
    // ========================================================================

    #[test]
    fn test_mask_telegram_bot_token() {
        let b = builder();
        // Numeric id retained, secret masked.
        assert_eq!(
            b.mask_telegram_bot_token("123456789:AAExampleSecretTokenBody"),
            "123456789:****"
        );
        // No colon => sentinel.
        assert_eq!(b.mask_telegram_bot_token("nocolon"), "[TELEGRAM_TOKEN]");
    }

    #[test]
    fn test_mask_sendgrid_key() {
        let b = builder();
        // SG. prefix + first 4 of the body.
        assert_eq!(b.mask_sendgrid_key("SG.abcdEFGH.ijklMNOP"), "SG.abcd****");
        assert_eq!(b.mask_sendgrid_key("notprefixed"), "[SENDGRID_KEY]");
    }

    #[test]
    fn test_mask_twilio_sids() {
        let b = builder();
        assert_eq!(
            b.mask_twilio_account_sid(&format!("AC{}", "0123456789abcdef0123456789abcdef")),
            "AC0123****"
        );
        assert_eq!(
            b.mask_twilio_api_key_sid(&format!("SK{}", "0123456789abcdef0123456789abcdef")),
            "SK0123****"
        );
        assert_eq!(b.mask_twilio_account_sid("XX123"), "[TWILIO_SID]");
    }

    #[test]
    fn test_mask_slack_token_and_webhook() {
        let b = builder();
        assert_eq!(b.mask_slack_token("xoxb-123-456-secret"), "xoxb-****");
        assert_eq!(b.mask_slack_token("xapp-1-abc"), "xapp-****");
        assert_eq!(b.mask_slack_token("random-token"), "[SLACK_TOKEN]");

        assert_eq!(
            b.mask_slack_webhook("https://hooks.slack.com/services/T00/B00/XXXX"),
            "https://hooks.slack.com/services/****"
        );
        assert_eq!(
            b.mask_slack_webhook("https://example.com/x"),
            "[SLACK_WEBHOOK]"
        );
    }

    #[test]
    fn test_mask_discord_token_and_webhook() {
        let b = builder();
        // Discord bot tokens start with M or N; first segment retained.
        assert_eq!(
            b.mask_discord_token("MTAxaBcDeF.GhIjKl.MnOpQrStUv"),
            "MTAxaBcDeF.****"
        );
        assert_eq!(
            b.mask_discord_token("invalid.token.here"),
            "[DISCORD_TOKEN]"
        );

        assert_eq!(
            b.mask_discord_webhook("https://discord.com/api/webhooks/12345/abcdeToken"),
            "https://discord.com/api/webhooks/12345/****"
        );
        assert_eq!(
            b.mask_discord_webhook("https://discordapp.com/api/webhooks/999/tok"),
            "https://discordapp.com/api/webhooks/999/****"
        );
        assert_eq!(
            b.mask_discord_webhook("https://x.com/y"),
            "[DISCORD_WEBHOOK]"
        );
    }

    // ========================================================================
    // Remaining mask_api_key-backed wrappers exercise the full public surface.
    // For an unrecognized input they must all return the generic token; this
    // guards against a wrapper accidentally calling the wrong sanitizer.
    // ========================================================================

    #[test]
    fn test_generic_masks_on_invalid_input() {
        let b = builder();
        let invalid = "x";
        for masked in [
            b.mask_github_token(invalid),
            b.mask_azure_key(invalid),
            b.mask_aws_session_token(invalid),
            b.mask_square_token(invalid),
            b.mask_shopify_token(invalid),
            b.mask_paypal_token(invalid),
            b.mask_mailchimp_key(invalid),
            b.mask_mailgun_key(invalid),
            b.mask_resend_key(invalid),
            b.mask_brevo_key(invalid),
            b.mask_databricks_token(invalid),
            b.mask_vault_token(invalid),
            b.mask_cloudflare_ca_key(invalid),
            b.mask_npm_token(invalid),
            b.mask_pypi_token(invalid),
            b.mask_nuget_key(invalid),
            b.mask_artifactory_token(invalid),
            b.mask_docker_hub_token(invalid),
        ] {
            assert_eq!(masked, "[API_KEY]");
        }
    }
}

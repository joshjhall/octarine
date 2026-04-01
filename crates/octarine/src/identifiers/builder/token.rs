//! Token identifier builder with observability
//!
//! Wraps `primitives::identifiers::TokenIdentifierBuilder` with observe instrumentation.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.

use std::borrow::Cow;

use crate::observe::Problem;
use crate::primitives::identifiers::{
    ApiKeyProvider, ApiKeyRedactionStrategy, JwtAlgorithm, JwtMetadata, JwtRedactionStrategy,
    SessionIdRedactionStrategy, SshFingerprintRedactionStrategy, SshKeyRedactionStrategy,
    TokenIdentifierBuilder, TokenTextPolicy, TokenType,
};

/// Token identifier builder with observability
#[derive(Debug, Clone, Copy, Default)]
pub struct TokenBuilder {
    inner: TokenIdentifierBuilder,
    emit_events: bool,
}

impl TokenBuilder {
    /// Create a new TokenBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: TokenIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: TokenIdentifierBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ============================================================================
    // Detection Methods
    // ============================================================================

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

    // ============================================================================
    // Validation Methods
    //
    // Naming convention:
    // - `is_*` returns `bool` (detection layer only)
    // - `validate_*` returns `Result<T, E>` (validation with error details)
    // ============================================================================

    /// Validate JWT token format (returns Result)
    pub fn validate_jwt(&self, token: &str) -> Result<(), Problem> {
        self.inner.validate_jwt(token)
    }

    /// Validate JWT algorithm security (returns Result with algorithm)
    pub fn validate_jwt_algorithm(
        &self,
        token: &str,
        allow_hmac: bool,
    ) -> Result<JwtAlgorithm, Problem> {
        self.inner.validate_jwt_algorithm(token, allow_hmac)
    }

    /// Detect JWT algorithm from token
    pub fn detect_jwt_algorithm(&self, token: &str) -> Result<JwtAlgorithm, Problem> {
        self.inner.detect_jwt_algorithm(token)
    }

    /// Validate API key format (returns Result with provider)
    pub fn validate_api_key(
        &self,
        key: &str,
        min: usize,
        max: usize,
    ) -> Result<ApiKeyProvider, Problem> {
        self.inner.validate_api_key(key, min, max)
    }

    /// Validate session ID format (returns Result)
    pub fn validate_session_id(
        &self,
        session_id: &str,
        min: usize,
        max: usize,
    ) -> Result<(), Problem> {
        self.inner.validate_session_id(session_id, min, max)
    }

    // ============================================================================
    // Conversion Methods
    // ============================================================================

    /// Extract metadata from JWT header
    pub fn extract_jwt_metadata(&self, token: &str) -> Result<JwtMetadata, Problem> {
        self.inner.extract_jwt_metadata(token)
    }

    /// Parse JWT header and return raw JSON
    pub fn parse_jwt_header(&self, token: &str) -> Result<serde_json::Value, Problem> {
        self.inner.parse_jwt_header(token)
    }

    /// Extract algorithm string from JWT header
    pub fn extract_jwt_algorithm_string(&self, token: &str) -> Result<String, Problem> {
        self.inner.extract_jwt_algorithm_string(token)
    }

    /// Extract token type from JWT header
    pub fn extract_jwt_type(&self, token: &str) -> Result<Option<String>, Problem> {
        self.inner.extract_jwt_type(token)
    }

    // ============================================================================
    // JWT Redaction
    // ============================================================================

    /// Redact JWT token (show algorithm by default)
    #[must_use]
    pub fn redact_jwt(&self, token: &str) -> String {
        self.inner.redact_jwt(token)
    }

    /// Redact JWT token with custom strategy
    #[must_use]
    pub fn redact_jwt_with_strategy(&self, token: &str, strategy: JwtRedactionStrategy) -> String {
        self.inner.redact_jwt_with_strategy(token, strategy)
    }

    /// Mask JWT token (convenience wrapper)
    #[must_use]
    pub fn mask_jwt(&self, token: &str) -> String {
        self.inner.mask_jwt(token)
    }

    /// Redact JWTs in text
    #[must_use]
    pub fn redact_jwts_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.inner.redact_jwts_in_text(text)
    }

    /// Redact JWTs in text with custom policy
    #[must_use]
    pub fn redact_jwts_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: TokenTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_jwts_in_text_with_policy(text, policy)
    }

    // ============================================================================
    // API Key Redaction
    // ============================================================================

    /// Redact API key (show prefix by default)
    #[must_use]
    pub fn redact_api_key(&self, key: &str) -> String {
        self.inner.redact_api_key(key)
    }

    /// Redact API key with custom strategy
    #[must_use]
    pub fn redact_api_key_with_strategy(
        &self,
        key: &str,
        strategy: ApiKeyRedactionStrategy,
    ) -> String {
        self.inner.redact_api_key_with_strategy(key, strategy)
    }

    /// Mask API key (convenience wrapper)
    #[must_use]
    pub fn mask_api_key(&self, key: &str) -> String {
        self.inner.mask_api_key(key)
    }

    /// Redact API keys in text
    #[must_use]
    pub fn redact_api_keys_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.inner.redact_api_keys_in_text(text)
    }

    /// Redact API keys in text with custom policy
    #[must_use]
    pub fn redact_api_keys_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: TokenTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_api_keys_in_text_with_policy(text, policy)
    }

    // ============================================================================
    // Session ID Redaction
    // ============================================================================

    /// Redact session ID (show prefix by default)
    #[must_use]
    pub fn redact_session_id(&self, session_id: &str) -> String {
        self.inner.redact_session_id(session_id)
    }

    /// Redact session ID with custom strategy
    #[must_use]
    pub fn redact_session_id_with_strategy(
        &self,
        session_id: &str,
        strategy: SessionIdRedactionStrategy,
    ) -> String {
        self.inner
            .redact_session_id_with_strategy(session_id, strategy)
    }

    /// Mask session ID (convenience wrapper)
    #[must_use]
    pub fn mask_session_id(&self, session_id: &str) -> String {
        self.inner.mask_session_id(session_id)
    }

    /// Redact session IDs in text
    #[must_use]
    pub fn redact_session_ids_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.inner.redact_session_ids_in_text(text)
    }

    /// Redact session IDs in text with custom policy
    #[must_use]
    pub fn redact_session_ids_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: TokenTextPolicy,
    ) -> Cow<'a, str> {
        self.inner
            .redact_session_ids_in_text_with_policy(text, policy)
    }

    // ============================================================================
    // SSH Key Redaction
    // ============================================================================

    /// Redact SSH key (show type by default)
    #[must_use]
    pub fn redact_ssh_key(&self, key: &str) -> String {
        self.inner.redact_ssh_key(key)
    }

    /// Redact SSH key with custom strategy
    #[must_use]
    pub fn redact_ssh_key_with_strategy(
        &self,
        key: &str,
        strategy: SshKeyRedactionStrategy,
    ) -> String {
        self.inner.redact_ssh_key_with_strategy(key, strategy)
    }

    /// Mask SSH key (convenience wrapper)
    #[must_use]
    pub fn mask_ssh_key(&self, key: &str) -> String {
        self.inner.mask_ssh_key(key)
    }

    /// Redact SSH keys in text
    #[must_use]
    pub fn redact_ssh_keys_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.inner.redact_ssh_keys_in_text(text)
    }

    /// Redact SSH keys in text with custom policy
    #[must_use]
    pub fn redact_ssh_keys_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: TokenTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_ssh_keys_in_text_with_policy(text, policy)
    }

    // ============================================================================
    // SSH Fingerprint Redaction
    // ============================================================================

    /// Redact SSH fingerprint (show type by default)
    #[must_use]
    pub fn redact_ssh_fingerprint(&self, fingerprint: &str) -> String {
        self.inner.redact_ssh_fingerprint(fingerprint)
    }

    /// Redact SSH fingerprint with custom strategy
    #[must_use]
    pub fn redact_ssh_fingerprint_with_strategy(
        &self,
        fingerprint: &str,
        strategy: SshFingerprintRedactionStrategy,
    ) -> String {
        self.inner
            .redact_ssh_fingerprint_with_strategy(fingerprint, strategy)
    }

    // ============================================================================
    // Provider-Specific Redaction
    // ============================================================================

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

    // ============================================================================
    // Comprehensive Text Redaction
    // ============================================================================

    /// Redact all token types in text using default Complete policy
    #[must_use]
    pub fn redact_all_in_text(&self, text: &str) -> String {
        self.inner.redact_all_in_text(text)
    }

    /// Redact all token types in text with explicit policy
    ///
    /// # Arguments
    ///
    /// * `text` - The text to scan for token identifiers
    /// * `policy` - The redaction policy to apply
    #[must_use]
    pub fn redact_all_in_text_with_policy(&self, text: &str, policy: TokenTextPolicy) -> String {
        self.inner.redact_all_in_text_with_policy(text, policy)
    }

    // ============================================================================
    // Test Data Detection Methods
    // ============================================================================

    /// Check if JWT is a known test/development token
    #[must_use]
    pub fn is_test_jwt(&self, jwt: &str) -> bool {
        self.inner.is_test_jwt(jwt)
    }

    /// Check if API key is a known test/development key
    #[must_use]
    pub fn is_test_api_key(&self, key: &str) -> bool {
        self.inner.is_test_api_key(key)
    }

    /// Check if session ID is a known test/development ID
    #[must_use]
    pub fn is_test_session_id(&self, session_id: &str) -> bool {
        self.inner.is_test_session_id(session_id)
    }

    /// Check if SSH key or fingerprint is a known test/example
    #[must_use]
    pub fn is_test_ssh_key(&self, ssh_key: &str) -> bool {
        self.inner.is_test_ssh_key(ssh_key)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = TokenBuilder::new();
        assert!(builder.emit_events);

        let silent = TokenBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = TokenBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_jwt_detection() {
        let builder = TokenBuilder::silent();
        assert!(builder.is_jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
    }
}

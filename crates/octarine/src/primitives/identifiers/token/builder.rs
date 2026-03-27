//! Token identifier builder
//!
//! Unified builder API for token identifier operations.

use crate::primitives::Problem;

use super::{conversion, detection, redaction, sanitization, validation};

// Re-export types for convenience
pub use detection::{ApiKeyProvider, JwtAlgorithm};

/// Builder for token identifier operations
///
/// Provides a unified interface for detection, validation, and sanitization
/// of authentication and authorization tokens.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokenIdentifierBuilder;

impl TokenIdentifierBuilder {
    /// Create a new token identifier builder
    pub fn new() -> Self {
        Self
    }

    // ============================================================================
    // Detection Methods
    // ============================================================================

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

    /// Check if value is a GitLab token
    pub fn is_gitlab_token(&self, value: &str) -> bool {
        detection::is_gitlab_token(value)
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

    // ============================================================================
    // Validation Methods
    //
    // Naming convention:
    // - `is_*` returns `bool` (detection layer only)
    // - `validate_*` returns `Result<T, E>` (validation with error details)
    // ============================================================================

    /// Validate JWT token format (returns Result)
    pub fn validate_jwt(&self, token: &str) -> Result<(), Problem> {
        validation::validate_jwt(token)
    }

    /// Validate JWT algorithm security (returns Result with algorithm)
    pub fn validate_jwt_algorithm(
        &self,
        token: &str,
        allow_hmac: bool,
    ) -> Result<detection::JwtAlgorithm, Problem> {
        validation::validate_jwt_algorithm(token, allow_hmac)
    }

    /// Detect JWT algorithm from token
    pub fn detect_jwt_algorithm(&self, token: &str) -> Result<detection::JwtAlgorithm, Problem> {
        detection::detect_jwt_algorithm(token)
    }

    /// Validate API key format (returns Result with provider)
    pub fn validate_api_key(
        &self,
        key: &str,
        min: usize,
        max: usize,
    ) -> Result<detection::ApiKeyProvider, Problem> {
        validation::validate_api_key(key, min, max)
    }

    /// Validate session ID format (returns Result)
    pub fn validate_session_id(
        &self,
        session_id: &str,
        min: usize,
        max: usize,
    ) -> Result<(), Problem> {
        validation::validate_session_id(session_id, min, max)
    }

    // ============================================================================
    // Conversion Methods
    // ============================================================================

    /// Extract metadata from JWT header (safe - header is publicly visible)
    ///
    /// Returns algorithm, token type, and header keys.
    /// Does NOT access payload (which may contain PII).
    pub fn extract_jwt_metadata(&self, token: &str) -> Result<conversion::JwtMetadata, Problem> {
        conversion::extract_jwt_metadata(token)
    }

    /// Parse JWT header and return raw JSON
    ///
    /// Useful for examining non-standard header fields.
    pub fn parse_jwt_header(&self, token: &str) -> Result<serde_json::Value, Problem> {
        conversion::parse_jwt_header(token)
    }

    /// Extract algorithm string from JWT header
    pub fn extract_jwt_algorithm_string(&self, token: &str) -> Result<String, Problem> {
        conversion::extract_jwt_algorithm(token)
    }

    /// Extract token type from JWT header (usually "JWT")
    pub fn extract_jwt_type(&self, token: &str) -> Result<Option<String>, Problem> {
        conversion::extract_jwt_type(token)
    }

    // ============================================================================
    // Sanitization Methods
    // ============================================================================

    // =========================================================================
    // JWT Redaction
    // =========================================================================

    /// Redact JWT token (show algorithm by default)
    ///
    /// Example: "eyJhbGc..." → "<JWT-RS256>"
    pub fn redact_jwt(&self, token: &str) -> String {
        sanitization::redact_jwt(token, redaction::JwtRedactionStrategy::ShowAlgorithm)
    }

    /// Redact JWT token with custom strategy
    pub fn redact_jwt_with_strategy(
        &self,
        token: &str,
        strategy: redaction::JwtRedactionStrategy,
    ) -> String {
        sanitization::redact_jwt(token, strategy)
    }

    /// Mask JWT token (convenience wrapper)
    ///
    /// Shows algorithm only: "<JWT-RS256>"
    pub fn mask_jwt(&self, token: &str) -> String {
        sanitization::mask_jwt(token)
    }

    /// Redact JWTs in text (complete redaction by default)
    pub fn redact_jwts_in_text<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
        sanitization::redact_jwts_in_text(text, redaction::TextRedactionPolicy::Complete)
    }

    /// Redact JWTs in text with custom policy
    pub fn redact_jwts_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: redaction::TextRedactionPolicy,
    ) -> std::borrow::Cow<'a, str> {
        sanitization::redact_jwts_in_text(text, policy)
    }

    // =========================================================================
    // API Key Redaction
    // =========================================================================

    /// Redact API key (show prefix by default)
    ///
    /// Example: "sk_live_abc123..." → "sk_live_****"
    pub fn redact_api_key(&self, key: &str) -> String {
        sanitization::redact_api_key(key, redaction::ApiKeyRedactionStrategy::ShowPrefix)
    }

    /// Redact API key with custom strategy
    pub fn redact_api_key_with_strategy(
        &self,
        key: &str,
        strategy: redaction::ApiKeyRedactionStrategy,
    ) -> String {
        sanitization::redact_api_key(key, strategy)
    }

    /// Mask API key (convenience wrapper)
    ///
    /// Shows prefix only: "sk_live_****"
    pub fn mask_api_key(&self, key: &str) -> String {
        sanitization::mask_api_key(key)
    }

    /// Redact API keys in text (complete redaction by default)
    pub fn redact_api_keys_in_text<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
        sanitization::redact_api_keys_in_text(text, redaction::TextRedactionPolicy::Complete)
    }

    /// Redact API keys in text with custom policy
    pub fn redact_api_keys_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: redaction::TextRedactionPolicy,
    ) -> std::borrow::Cow<'a, str> {
        sanitization::redact_api_keys_in_text(text, policy)
    }

    // =========================================================================
    // Session ID Redaction
    // =========================================================================

    /// Redact session ID (show prefix by default)
    ///
    /// Example: "sess_abc123..." → "sess_****"
    pub fn redact_session_id(&self, session_id: &str) -> String {
        sanitization::redact_session_id(
            session_id,
            redaction::SessionIdRedactionStrategy::ShowPrefix,
        )
    }

    /// Redact session ID with custom strategy
    pub fn redact_session_id_with_strategy(
        &self,
        session_id: &str,
        strategy: redaction::SessionIdRedactionStrategy,
    ) -> String {
        sanitization::redact_session_id(session_id, strategy)
    }

    /// Mask session ID (convenience wrapper)
    ///
    /// Shows prefix only: "sess_****"
    pub fn mask_session_id(&self, session_id: &str) -> String {
        sanitization::mask_session_id(session_id)
    }

    /// Redact session IDs in text (complete redaction by default)
    pub fn redact_session_ids_in_text<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
        sanitization::redact_session_ids_in_text(text, redaction::TextRedactionPolicy::Complete)
    }

    /// Redact session IDs in text with custom policy
    pub fn redact_session_ids_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: redaction::TextRedactionPolicy,
    ) -> std::borrow::Cow<'a, str> {
        sanitization::redact_session_ids_in_text(text, policy)
    }

    // =========================================================================
    // SSH Key Redaction
    // =========================================================================

    /// Redact SSH key (show type by default)
    ///
    /// Example: "ssh-rsa AAAAB3..." → "<SSH-RSA>"
    pub fn redact_ssh_key(&self, key: &str) -> String {
        sanitization::redact_ssh_key(key, redaction::SshKeyRedactionStrategy::ShowType)
    }

    /// Redact SSH key with custom strategy
    pub fn redact_ssh_key_with_strategy(
        &self,
        key: &str,
        strategy: redaction::SshKeyRedactionStrategy,
    ) -> String {
        sanitization::redact_ssh_key(key, strategy)
    }

    /// Mask SSH key (convenience wrapper)
    ///
    /// Shows key type only: "<SSH-RSA>"
    pub fn mask_ssh_key(&self, key: &str) -> String {
        sanitization::mask_ssh_key(key)
    }

    /// Redact SSH keys in text (complete redaction by default)
    pub fn redact_ssh_keys_in_text<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
        sanitization::redact_ssh_keys_in_text(text, redaction::TextRedactionPolicy::Complete)
    }

    /// Redact SSH keys in text with custom policy
    pub fn redact_ssh_keys_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: redaction::TextRedactionPolicy,
    ) -> std::borrow::Cow<'a, str> {
        sanitization::redact_ssh_keys_in_text(text, policy)
    }

    // =========================================================================
    // SSH Fingerprint Redaction
    // =========================================================================

    /// Redact SSH fingerprint (show type by default)
    ///
    /// Example: "SHA256:abc..." → "<SSH-FP-SHA256>"
    pub fn redact_ssh_fingerprint(&self, fingerprint: &str) -> String {
        sanitization::redact_ssh_fingerprint(
            fingerprint,
            redaction::SshFingerprintRedactionStrategy::ShowType,
        )
    }

    /// Redact SSH fingerprint with custom strategy
    pub fn redact_ssh_fingerprint_with_strategy(
        &self,
        fingerprint: &str,
        strategy: redaction::SshFingerprintRedactionStrategy,
    ) -> String {
        sanitization::redact_ssh_fingerprint(fingerprint, strategy)
    }

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
    // Provider-Specific Masking (Square, Shopify, PayPal)
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

    // =========================================================================
    // Comprehensive Text Redaction
    // =========================================================================

    /// Redact all token types in text using default Complete policy
    ///
    /// Scans for and redacts: JWTs, API keys, session IDs, SSH keys
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use crate::primitives::identifiers::token::TokenIdentifierBuilder;
    ///
    /// let builder = TokenIdentifierBuilder::new();
    /// let result = builder.redact_all_in_text("Key: sk_live_1234567890");
    /// assert!(result.contains("<API_KEY>"));
    /// ```
    #[must_use]
    pub fn redact_all_in_text(&self, text: &str) -> String {
        sanitization::redact_all_tokens_in_text(text, redaction::TextRedactionPolicy::Complete)
    }

    /// Redact all token types in text with explicit policy
    ///
    /// # Arguments
    ///
    /// * `text` - The text to scan for token identifiers
    /// * `policy` - The redaction policy to apply
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use crate::primitives::identifiers::token::{TokenIdentifierBuilder, TextRedactionPolicy};
    ///
    /// let builder = TokenIdentifierBuilder::new();
    ///
    /// // Partial - shows prefix
    /// let result = builder.redact_all_in_text_with_policy(
    ///     "Key: sk_live_1234567890",
    ///     TextRedactionPolicy::Partial
    /// );
    /// assert!(result.contains("sk_live_****"));
    /// ```
    #[must_use]
    pub fn redact_all_in_text_with_policy(
        &self,
        text: &str,
        policy: redaction::TextRedactionPolicy,
    ) -> String {
        sanitization::redact_all_tokens_in_text(text, policy)
    }

    // =========================================================================
    // Test Data Detection Methods
    // =========================================================================

    /// Check if JWT is a known test/development token
    ///
    /// Detects jwt.io example tokens, "none" algorithm, and test signatures.
    #[must_use]
    pub fn is_test_jwt(&self, jwt: &str) -> bool {
        detection::is_test_jwt(jwt)
    }

    /// Check if API key is a known test/development key
    ///
    /// Detects test environment keys, example keys, and keys with test keywords.
    #[must_use]
    pub fn is_test_api_key(&self, key: &str) -> bool {
        detection::is_test_api_key(key)
    }

    /// Check if session ID is a known test/development ID
    ///
    /// Detects session IDs with test prefixes, keywords, or sequential patterns.
    #[must_use]
    pub fn is_test_session_id(&self, session_id: &str) -> bool {
        detection::is_test_session_id(session_id)
    }

    /// Check if SSH key or fingerprint is a known test/example
    ///
    /// Detects keys with test/example comments and known example fingerprints.
    #[must_use]
    pub fn is_test_ssh_key(&self, ssh_key: &str) -> bool {
        detection::is_test_ssh_key(ssh_key)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = TokenIdentifierBuilder::new();
        // Use a real JWT token (from jwt.io)
        assert!(builder.is_jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
    }

    #[test]
    fn test_builder_api_key_detection() {
        let builder = TokenIdentifierBuilder::new();
        assert!(builder.is_api_key(&format!("sk_live_{}", "EXAMPLE000000000KEY01abcdef")));
        assert!(builder.is_stripe_key(&format!("sk_live_{}", "EXAMPLE000000000KEY01abcdef")));
    }

    #[test]
    fn test_builder_masking() {
        let builder = TokenIdentifierBuilder::new();
        let masked = builder.mask_api_key(&format!("sk_live_{}", "EXAMPLE000000000KEY01abcdef"));
        assert_eq!(masked, "sk_live_EXAM***");
    }
}

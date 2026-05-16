//! API key redaction methods for `TokenIdentifierBuilder`

use crate::primitives::identifiers::token::{redaction, sanitization};

use super::TokenIdentifierBuilder;

impl TokenIdentifierBuilder {
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
}

//! API key redaction — single key and in-text redaction.

use super::*;

impl TokenBuilder {
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
}

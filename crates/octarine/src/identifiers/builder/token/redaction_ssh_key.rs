//! SSH key redaction — single key and in-text redaction.

use super::*;

impl TokenBuilder {
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
}

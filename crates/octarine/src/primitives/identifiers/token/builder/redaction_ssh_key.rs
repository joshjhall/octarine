//! SSH key redaction methods for `TokenIdentifierBuilder`

use crate::primitives::identifiers::token::{redaction, sanitization};

use super::TokenIdentifierBuilder;

impl TokenIdentifierBuilder {
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
}

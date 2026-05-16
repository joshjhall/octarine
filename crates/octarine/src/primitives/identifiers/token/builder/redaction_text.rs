//! Comprehensive text-redaction methods for `TokenIdentifierBuilder`
//!
//! Scans text for all supported token types (JWTs, API keys, session IDs,
//! SSH keys) and redacts them in a single pass.

use crate::primitives::identifiers::token::{redaction, sanitization};

use super::TokenIdentifierBuilder;

impl TokenIdentifierBuilder {
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
}

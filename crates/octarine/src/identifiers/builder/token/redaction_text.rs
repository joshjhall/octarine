//! Comprehensive text redaction — multi-token sweep across an input string.

use super::*;

impl TokenBuilder {
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
}

//! Session ID redaction — single ID and in-text redaction.

use super::*;

impl TokenBuilder {
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
}

//! Session ID redaction methods for `TokenIdentifierBuilder`

use crate::primitives::identifiers::token::{redaction, sanitization};

use super::TokenIdentifierBuilder;

impl TokenIdentifierBuilder {
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
}

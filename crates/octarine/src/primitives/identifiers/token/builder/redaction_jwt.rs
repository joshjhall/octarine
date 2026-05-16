//! JWT redaction methods for `TokenIdentifierBuilder`

use crate::primitives::identifiers::token::{redaction, sanitization};

use super::TokenIdentifierBuilder;

impl TokenIdentifierBuilder {
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
}

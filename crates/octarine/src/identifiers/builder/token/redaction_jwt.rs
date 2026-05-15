//! JWT redaction — single token and in-text redaction.

use super::*;

impl TokenBuilder {
    /// Redact JWT token (show algorithm by default)
    #[must_use]
    pub fn redact_jwt(&self, token: &str) -> String {
        self.inner.redact_jwt(token)
    }

    /// Redact JWT token with custom strategy
    #[must_use]
    pub fn redact_jwt_with_strategy(&self, token: &str, strategy: JwtRedactionStrategy) -> String {
        self.inner.redact_jwt_with_strategy(token, strategy)
    }

    /// Mask JWT token (convenience wrapper)
    #[must_use]
    pub fn mask_jwt(&self, token: &str) -> String {
        self.inner.mask_jwt(token)
    }

    /// Redact JWTs in text
    #[must_use]
    pub fn redact_jwts_in_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.inner.redact_jwts_in_text(text)
    }

    /// Redact JWTs in text with custom policy
    #[must_use]
    pub fn redact_jwts_in_text_with_policy<'a>(
        &self,
        text: &'a str,
        policy: TokenTextPolicy,
    ) -> Cow<'a, str> {
        self.inner.redact_jwts_in_text_with_policy(text, policy)
    }
}

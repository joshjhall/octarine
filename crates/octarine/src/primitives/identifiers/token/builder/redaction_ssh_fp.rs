//! SSH fingerprint redaction methods for `TokenIdentifierBuilder`

use crate::primitives::identifiers::token::{redaction, sanitization};

use super::TokenIdentifierBuilder;

impl TokenIdentifierBuilder {
    /// Redact SSH fingerprint (show type by default)
    ///
    /// Example: "SHA256:abc..." → "<SSH-FP-SHA256>"
    pub fn redact_ssh_fingerprint(&self, fingerprint: &str) -> String {
        sanitization::redact_ssh_fingerprint(
            fingerprint,
            redaction::SshFingerprintRedactionStrategy::ShowType,
        )
    }

    /// Redact SSH fingerprint with custom strategy
    pub fn redact_ssh_fingerprint_with_strategy(
        &self,
        fingerprint: &str,
        strategy: redaction::SshFingerprintRedactionStrategy,
    ) -> String {
        sanitization::redact_ssh_fingerprint(fingerprint, strategy)
    }
}

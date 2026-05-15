//! SSH fingerprint redaction.

use super::*;

impl TokenBuilder {
    /// Redact SSH fingerprint (show type by default)
    #[must_use]
    pub fn redact_ssh_fingerprint(&self, fingerprint: &str) -> String {
        self.inner.redact_ssh_fingerprint(fingerprint)
    }

    /// Redact SSH fingerprint with custom strategy
    #[must_use]
    pub fn redact_ssh_fingerprint_with_strategy(
        &self,
        fingerprint: &str,
        strategy: SshFingerprintRedactionStrategy,
    ) -> String {
        self.inner
            .redact_ssh_fingerprint_with_strategy(fingerprint, strategy)
    }
}

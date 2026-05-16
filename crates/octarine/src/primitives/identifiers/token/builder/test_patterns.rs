//! Test-data detection methods for `TokenIdentifierBuilder`
//!
//! `is_test_*` predicates that identify known development/test/example tokens
//! (jwt.io examples, "none" algorithm JWTs, sequential session IDs, etc.) so
//! they can be filtered out of audit alerts.

use crate::primitives::identifiers::token::detection;

use super::TokenIdentifierBuilder;

impl TokenIdentifierBuilder {
    /// Check if JWT is a known test/development token
    ///
    /// Detects jwt.io example tokens, "none" algorithm, and test signatures.
    #[must_use]
    pub fn is_test_jwt(&self, jwt: &str) -> bool {
        detection::is_test_jwt(jwt)
    }

    /// Check if API key is a known test/development key
    ///
    /// Detects test environment keys, example keys, and keys with test keywords.
    #[must_use]
    pub fn is_test_api_key(&self, key: &str) -> bool {
        detection::is_test_api_key(key)
    }

    /// Check if session ID is a known test/development ID
    ///
    /// Detects session IDs with test prefixes, keywords, or sequential patterns.
    #[must_use]
    pub fn is_test_session_id(&self, session_id: &str) -> bool {
        detection::is_test_session_id(session_id)
    }

    /// Check if SSH key or fingerprint is a known test/example
    ///
    /// Detects keys with test/example comments and known example fingerprints.
    #[must_use]
    pub fn is_test_ssh_key(&self, ssh_key: &str) -> bool {
        detection::is_test_ssh_key(ssh_key)
    }
}

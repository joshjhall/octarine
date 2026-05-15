//! Test data detection — predicates that identify known test/example
//! token patterns so they can be excluded from production sensitivity
//! rules.

use super::*;

impl TokenBuilder {
    /// Check if JWT is a known test/development token
    #[must_use]
    pub fn is_test_jwt(&self, jwt: &str) -> bool {
        self.inner.is_test_jwt(jwt)
    }

    /// Check if API key is a known test/development key
    #[must_use]
    pub fn is_test_api_key(&self, key: &str) -> bool {
        self.inner.is_test_api_key(key)
    }

    /// Check if session ID is a known test/development ID
    #[must_use]
    pub fn is_test_session_id(&self, session_id: &str) -> bool {
        self.inner.is_test_session_id(session_id)
    }

    /// Check if SSH key or fingerprint is a known test/example
    #[must_use]
    pub fn is_test_ssh_key(&self, ssh_key: &str) -> bool {
        self.inner.is_test_ssh_key(ssh_key)
    }
}

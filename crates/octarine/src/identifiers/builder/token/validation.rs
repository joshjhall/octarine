//! Validation methods — `validate_*` returning `Result<T, Problem>`.
//!
//! Naming convention:
//! - `is_*` returns `bool` (detection layer only)
//! - `validate_*` returns `Result<T, E>` (validation with error details)

use super::*;

impl TokenBuilder {
    /// Validate JWT token format (returns Result)
    pub fn validate_jwt(&self, token: &str) -> Result<(), Problem> {
        self.inner.validate_jwt(token)
    }

    /// Validate JWT algorithm security (returns Result with algorithm)
    pub fn validate_jwt_algorithm(
        &self,
        token: &str,
        allow_hmac: bool,
    ) -> Result<JwtAlgorithm, Problem> {
        self.inner.validate_jwt_algorithm(token, allow_hmac)
    }

    /// Detect JWT algorithm from token
    pub fn detect_jwt_algorithm(&self, token: &str) -> Result<JwtAlgorithm, Problem> {
        self.inner.detect_jwt_algorithm(token)
    }

    /// Validate API key format (returns Result with provider)
    pub fn validate_api_key(
        &self,
        key: &str,
        min: usize,
        max: usize,
    ) -> Result<ApiKeyProvider, Problem> {
        self.inner.validate_api_key(key, min, max)
    }

    /// Validate session ID format (returns Result)
    pub fn validate_session_id(
        &self,
        session_id: &str,
        min: usize,
        max: usize,
    ) -> Result<(), Problem> {
        self.inner.validate_session_id(session_id, min, max)
    }
}

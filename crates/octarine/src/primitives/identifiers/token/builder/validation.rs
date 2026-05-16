//! Validation methods for `TokenIdentifierBuilder`
//!
//! `validate_*` methods that return `Result<T, Problem>` with detailed error
//! information. Calls into `token::validation` and `token::detection`.

use crate::primitives::Problem;
use crate::primitives::identifiers::token::{detection, validation};

use super::TokenIdentifierBuilder;

impl TokenIdentifierBuilder {
    /// Validate JWT token format (returns Result)
    pub fn validate_jwt(&self, token: &str) -> Result<(), Problem> {
        validation::validate_jwt(token)
    }

    /// Validate JWT algorithm security (returns Result with algorithm)
    pub fn validate_jwt_algorithm(
        &self,
        token: &str,
        allow_hmac: bool,
    ) -> Result<detection::JwtAlgorithm, Problem> {
        validation::validate_jwt_algorithm(token, allow_hmac)
    }

    /// Detect JWT algorithm from token
    pub fn detect_jwt_algorithm(&self, token: &str) -> Result<detection::JwtAlgorithm, Problem> {
        detection::detect_jwt_algorithm(token)
    }

    /// Validate API key format (returns Result with provider)
    pub fn validate_api_key(
        &self,
        key: &str,
        min: usize,
        max: usize,
    ) -> Result<detection::ApiKeyProvider, Problem> {
        validation::validate_api_key(key, min, max)
    }

    /// Validate session ID format (returns Result)
    pub fn validate_session_id(
        &self,
        session_id: &str,
        min: usize,
        max: usize,
    ) -> Result<(), Problem> {
        validation::validate_session_id(session_id, min, max)
    }
}

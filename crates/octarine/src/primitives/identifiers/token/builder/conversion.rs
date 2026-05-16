//! Conversion methods for `TokenIdentifierBuilder`
//!
//! Methods that extract structured information from tokens (JWT header
//! parsing, metadata extraction). Calls into `token::conversion`.

use crate::primitives::Problem;
use crate::primitives::identifiers::token::conversion;

use super::TokenIdentifierBuilder;

impl TokenIdentifierBuilder {
    /// Extract metadata from JWT header (safe - header is publicly visible)
    ///
    /// Returns algorithm, token type, and header keys.
    /// Does NOT access payload (which may contain PII).
    pub fn extract_jwt_metadata(&self, token: &str) -> Result<conversion::JwtMetadata, Problem> {
        conversion::extract_jwt_metadata(token)
    }

    /// Parse JWT header and return raw JSON
    ///
    /// Useful for examining non-standard header fields.
    pub fn parse_jwt_header(&self, token: &str) -> Result<serde_json::Value, Problem> {
        conversion::parse_jwt_header(token)
    }

    /// Extract algorithm string from JWT header
    pub fn extract_jwt_algorithm_string(&self, token: &str) -> Result<String, Problem> {
        conversion::extract_jwt_algorithm(token)
    }

    /// Extract token type from JWT header (usually "JWT")
    pub fn extract_jwt_type(&self, token: &str) -> Result<Option<String>, Problem> {
        conversion::extract_jwt_type(token)
    }
}

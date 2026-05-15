//! Conversion methods — JWT header extraction and parsing.

use super::*;

impl TokenBuilder {
    /// Extract metadata from JWT header
    pub fn extract_jwt_metadata(&self, token: &str) -> Result<JwtMetadata, Problem> {
        self.inner.extract_jwt_metadata(token)
    }

    /// Parse JWT header and return raw JSON
    pub fn parse_jwt_header(&self, token: &str) -> Result<serde_json::Value, Problem> {
        self.inner.parse_jwt_header(token)
    }

    /// Extract algorithm string from JWT header
    pub fn extract_jwt_algorithm_string(&self, token: &str) -> Result<String, Problem> {
        self.inner.extract_jwt_algorithm_string(token)
    }

    /// Extract token type from JWT header
    pub fn extract_jwt_type(&self, token: &str) -> Result<Option<String>, Problem> {
        self.inner.extract_jwt_type(token)
    }
}

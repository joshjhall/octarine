//! Data platform API key detection (Databricks).

use super::super::super::super::common::patterns;
use super::MAX_IDENTIFIER_LENGTH;

/// Check if value is a Databricks access token
///
/// Databricks tokens start with "dapi" followed by 32 hex characters,
/// with an optional "-N" suffix
#[must_use]
pub fn is_databricks_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_DATABRICKS.is_match(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_databricks_token() {
        // Valid Databricks token (dapi + 32 hex)
        assert!(is_databricks_token(&format!("dapi{}", "a".repeat(32))));
        // Valid with suffix
        assert!(is_databricks_token(&format!("dapi{}-2", "a".repeat(32))));
        // Invalid: wrong prefix
        assert!(!is_databricks_token(&format!("dapx{}", "a".repeat(32))));
        // Invalid: too short
        assert!(!is_databricks_token("dapi1234"));
    }
}

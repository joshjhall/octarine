//! Secrets manager API key detection (1Password tokens and vault refs, HashiCorp Vault).

use super::super::super::super::common::patterns;
use super::MAX_IDENTIFIER_LENGTH;

/// Check if value is a 1Password Service Account Token
///
/// 1Password service account tokens start with "ops_" followed by base64-like characters
#[must_use]
pub fn is_onepassword_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_1PASSWORD.is_match(trimmed)
}

/// Check if value is a 1Password Vault Reference
///
/// 1Password vault references have format: op://vault/item/field or op://vault/item
#[must_use]
pub fn is_onepassword_vault_ref(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::ONEPASSWORD_VAULT_REF.is_match(trimmed)
}

/// Check if value is a HashiCorp Vault token
///
/// Matches modern tokens (hvs.), batch tokens (b.), and legacy service tokens (s.)
#[must_use]
pub fn is_vault_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_VAULT.is_match(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_onepassword_token() {
        // Valid 1Password service account tokens
        assert!(is_onepassword_token(
            "ops_eyJzaWduSW5BZGRyZXNzIjoiaHR0cHM6Ly9teS4xcGFzc3dvcmQuY29tIiwidXNlckF1dGgiOiJ5"
        ));
        assert!(!is_onepassword_token("ops_short")); // Too short
        assert!(!is_onepassword_token("opsshort")); // Missing underscore
        assert!(!is_onepassword_token("regular_token")); // Wrong prefix
    }

    #[test]
    fn test_is_onepassword_vault_ref() {
        // Valid vault references
        assert!(is_onepassword_vault_ref("op://vault/item/field"));
        assert!(is_onepassword_vault_ref("op://my-vault/my-item"));
        assert!(is_onepassword_vault_ref(
            "op://Production/Database/password"
        ));
        assert!(!is_onepassword_vault_ref("op://vault")); // Missing item
        assert!(!is_onepassword_vault_ref("https://example.com")); // Wrong protocol
    }

    #[test]
    fn test_is_vault_token() {
        // Valid modern token (hvs. + 24+ chars)
        assert!(is_vault_token(&format!("hvs.{}", "A".repeat(24))));
        // Valid wrapped token
        assert!(is_vault_token(&format!("hvs.CAESI{}", "B".repeat(30))));
        // Valid batch token (b. + 24+ chars)
        assert!(is_vault_token(&format!("b.{}", "A".repeat(24))));
        // Valid legacy service token (s. + exactly 24 chars)
        assert!(is_vault_token(&format!("s.{}", "A".repeat(24))));
        // Invalid: s. with wrong length (23 chars)
        assert!(!is_vault_token(&format!("s.{}", "A".repeat(23))));
        // Invalid: wrong prefix
        assert!(!is_vault_token(&format!("x.{}", "A".repeat(24))));
        // Invalid: too short hvs.
        assert!(!is_vault_token("hvs.short"));
    }
}

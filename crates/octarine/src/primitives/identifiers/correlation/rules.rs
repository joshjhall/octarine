//! Credential pair recognition rules.
//!
//! Maps combinations of `IdentifierType` values to known `CredentialPairType`
//! variants. Given two `IdentifierMatch` values, determines if they form a
//! recognized credential pair (e.g., AWS access key + secret key).
//!
//! Rules are order-independent: `(A, B)` and `(B, A)` both match.

use super::super::types::{IdentifierMatch, IdentifierType};
use super::types::CredentialPairType;

/// Check if two identifier matches form a known credential pair.
///
/// Returns the pair type if recognized, `None` otherwise.
/// Order-independent: `(A, B)` and `(B, A)` both match.
#[must_use]
pub(crate) fn is_credential_pair(
    primary: &IdentifierMatch,
    secondary: &IdentifierMatch,
) -> Option<CredentialPairType> {
    // Try (primary, secondary) then (secondary, primary)
    classify_ordered_pair(primary, secondary).or_else(|| classify_ordered_pair(secondary, primary))
}

/// Try to classify a pair in a specific order.
///
/// Each rule checks the first argument as the "expected primary" and the
/// second as the "expected secondary". The caller tries both orderings.
fn classify_ordered_pair(
    first: &IdentifierMatch,
    second: &IdentifierMatch,
) -> Option<CredentialPairType> {
    match (&first.identifier_type, &second.identifier_type) {
        // AWS: AwsAccessKey + ApiKey (40-char base64-ish secret)
        (IdentifierType::AwsAccessKey, IdentifierType::ApiKey)
            if is_aws_secret_pattern(&second.matched_text) =>
        {
            Some(CredentialPairType::AwsKeyPair)
        }

        // Twilio: ApiKey (AC... SID) + ApiKey (32 hex auth token)
        // Must check before generic KeyPair since both are ApiKey
        (IdentifierType::ApiKey, IdentifierType::ApiKey)
            if is_twilio_sid(&first.matched_text) && is_hex_string(&second.matched_text, 32) =>
        {
            Some(CredentialPairType::TwilioPair)
        }

        // Token pair: Jwt/ApiKey with access/refresh context
        (IdentifierType::Jwt, IdentifierType::Jwt) => Some(CredentialPairType::TokenPair),
        (IdentifierType::Jwt, IdentifierType::ApiKey)
        | (IdentifierType::ApiKey, IdentifierType::Jwt) => Some(CredentialPairType::TokenPair),

        // KeyPair: ApiKey + ApiKey where one is public and other is private/secret
        (IdentifierType::ApiKey, IdentifierType::ApiKey) => {
            classify_api_key_pair(&first.matched_text, &second.matched_text)
        }

        // OAuth: URL/Domain with OAuth context + ApiKey/Password
        (
            IdentifierType::Url | IdentifierType::Domain,
            IdentifierType::ApiKey | IdentifierType::Password,
        ) if is_oauth_context(&first.matched_text) => Some(CredentialPairType::OAuthClientPair),

        // Username/Password: Username or Email + Password
        (IdentifierType::Username | IdentifierType::Email, IdentifierType::Password) => {
            Some(CredentialPairType::UsernamePasswordPair)
        }

        // Azure: UUID (client_id) + ApiKey/Password (client_secret)
        (IdentifierType::Uuid, IdentifierType::ApiKey | IdentifierType::Password) => {
            Some(CredentialPairType::AzureServicePrincipal)
        }

        _ => None,
    }
}

// =============================================================================
// Text Pattern Helpers
// =============================================================================

/// Check if text matches the AWS secret key pattern: 40 characters of base64-like chars.
fn is_aws_secret_pattern(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.len() == 40
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

/// Check if text looks like a Twilio Account SID: starts with "AC" and is 34 characters.
fn is_twilio_sid(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.len() == 34
        && trimmed.starts_with("AC")
        && trimmed.bytes().skip(2).all(|b| b.is_ascii_hexdigit())
}

/// Check if text is a hex string of exactly the given length.
fn is_hex_string(text: &str, expected_len: usize) -> bool {
    let trimmed = text.trim();
    trimmed.len() == expected_len && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Check if URL/domain text has OAuth-related context.
fn is_oauth_context(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("oauth")
        || lower.contains("client")
        || lower.contains("authorize")
        || lower.contains("token")
        || lower.contains("auth0")
        || lower.contains("okta")
}

/// Classify two ApiKey matches as either a KeyPair or None.
///
/// Checks for public/private key patterns (e.g., "pk_live_" / "sk_live_")
/// or explicit public/private/secret markers in the text.
fn classify_api_key_pair(text_a: &str, text_b: &str) -> Option<CredentialPairType> {
    let a_lower = text_a.to_lowercase();
    let b_lower = text_b.to_lowercase();

    let a_is_public = is_public_key_marker(&a_lower);
    let b_is_public = is_public_key_marker(&b_lower);
    let a_is_private = is_private_key_marker(&a_lower);
    let b_is_private = is_private_key_marker(&b_lower);

    // One public + one private = KeyPair
    if (a_is_public && b_is_private) || (a_is_private && b_is_public) {
        return Some(CredentialPairType::KeyPair);
    }

    None
}

/// Check if text contains markers suggesting a public key.
fn is_public_key_marker(lower_text: &str) -> bool {
    lower_text.starts_with("pk_") || lower_text.starts_with("pub_") || lower_text.contains("public")
}

/// Check if text contains markers suggesting a private/secret key.
fn is_private_key_marker(lower_text: &str) -> bool {
    lower_text.starts_with("sk_")
        || lower_text.starts_with("sec_")
        || lower_text.contains("private")
        || lower_text.contains("secret")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]

    use super::*;
    use crate::primitives::identifiers::types::DetectionConfidence;

    fn make_match(text: &str, id_type: IdentifierType) -> IdentifierMatch {
        IdentifierMatch::new(
            0,
            text.len(),
            text.to_string(),
            id_type,
            DetectionConfidence::Medium,
        )
    }

    // === AWS Key Pair ===

    #[test]
    fn test_aws_key_pair() {
        let access = make_match("AKIAIOSFODNN7EXAMPLE", IdentifierType::AwsAccessKey);
        let secret = make_match(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            IdentifierType::ApiKey,
        );
        let result = is_credential_pair(&access, &secret);
        assert_eq!(result, Some(CredentialPairType::AwsKeyPair));
    }

    #[test]
    fn test_aws_key_pair_reversed() {
        let access = make_match("AKIAIOSFODNN7EXAMPLE", IdentifierType::AwsAccessKey);
        let secret = make_match(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            IdentifierType::ApiKey,
        );
        let result = is_credential_pair(&secret, &access);
        assert_eq!(result, Some(CredentialPairType::AwsKeyPair));
    }

    #[test]
    fn test_aws_key_pair_wrong_secret_length() {
        let access = make_match("AKIAIOSFODNN7EXAMPLE", IdentifierType::AwsAccessKey);
        let not_secret = make_match("short", IdentifierType::ApiKey);
        assert_eq!(is_credential_pair(&access, &not_secret), None);
    }

    // === OAuth Client Pair ===

    #[test]
    fn test_oauth_client_pair() {
        let url = make_match("https://oauth.example.com/authorize", IdentifierType::Url);
        let secret = make_match("abc123secret", IdentifierType::ApiKey);
        let result = is_credential_pair(&url, &secret);
        assert_eq!(result, Some(CredentialPairType::OAuthClientPair));
    }

    #[test]
    fn test_oauth_client_pair_domain() {
        let domain = make_match("client.auth0.com", IdentifierType::Domain);
        let password = make_match("supersecret", IdentifierType::Password);
        let result = is_credential_pair(&domain, &password);
        assert_eq!(result, Some(CredentialPairType::OAuthClientPair));
    }

    #[test]
    fn test_oauth_client_pair_reversed() {
        let url = make_match("https://oauth.example.com/token", IdentifierType::Url);
        let secret = make_match("client_secret_value", IdentifierType::ApiKey);
        let result = is_credential_pair(&secret, &url);
        assert_eq!(result, Some(CredentialPairType::OAuthClientPair));
    }

    #[test]
    fn test_url_without_oauth_context() {
        let url = make_match("https://example.com/api/data", IdentifierType::Url);
        let key = make_match("some_api_key_value", IdentifierType::ApiKey);
        assert_eq!(is_credential_pair(&url, &key), None);
    }

    // === Username/Password Pair ===

    #[test]
    fn test_username_password_pair() {
        let user = make_match("admin", IdentifierType::Username);
        let pass = make_match("P@ssw0rd!", IdentifierType::Password);
        let result = is_credential_pair(&user, &pass);
        assert_eq!(result, Some(CredentialPairType::UsernamePasswordPair));
    }

    #[test]
    fn test_email_password_pair() {
        let email = make_match("user@example.com", IdentifierType::Email);
        let pass = make_match("hunter2", IdentifierType::Password);
        let result = is_credential_pair(&email, &pass);
        assert_eq!(result, Some(CredentialPairType::UsernamePasswordPair));
    }

    #[test]
    fn test_username_password_reversed() {
        let user = make_match("admin", IdentifierType::Username);
        let pass = make_match("P@ssw0rd!", IdentifierType::Password);
        let result = is_credential_pair(&pass, &user);
        assert_eq!(result, Some(CredentialPairType::UsernamePasswordPair));
    }

    // === Token Pair ===

    #[test]
    fn test_jwt_jwt_token_pair() {
        let access = make_match(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc",
            IdentifierType::Jwt,
        );
        let refresh = make_match(
            "eyJhbGciOiJIUzI1NiJ9.eyJ0eXAiOiJyZWZyZXNoIn0.xyz",
            IdentifierType::Jwt,
        );
        let result = is_credential_pair(&access, &refresh);
        assert_eq!(result, Some(CredentialPairType::TokenPair));
    }

    #[test]
    fn test_jwt_apikey_token_pair() {
        let jwt = make_match("eyJhbGciOiJIUzI1NiJ9.payload.sig", IdentifierType::Jwt);
        let key = make_match("refresh_token_abc123", IdentifierType::ApiKey);
        let result = is_credential_pair(&jwt, &key);
        assert_eq!(result, Some(CredentialPairType::TokenPair));
    }

    // === KeyPair ===

    #[test]
    fn test_key_pair_stripe_style() {
        let public = make_match("pk_live_abc123", IdentifierType::ApiKey);
        let secret = make_match("sk_live_xyz789", IdentifierType::ApiKey);
        let result = is_credential_pair(&public, &secret);
        assert_eq!(result, Some(CredentialPairType::KeyPair));
    }

    #[test]
    fn test_key_pair_public_private_text() {
        let public = make_match("public_key_abc123def456", IdentifierType::ApiKey);
        let private = make_match("private_key_xyz789ghi012", IdentifierType::ApiKey);
        let result = is_credential_pair(&public, &private);
        assert_eq!(result, Some(CredentialPairType::KeyPair));
    }

    #[test]
    fn test_key_pair_reversed() {
        let public = make_match("pk_live_abc123", IdentifierType::ApiKey);
        let secret = make_match("sk_live_xyz789", IdentifierType::ApiKey);
        let result = is_credential_pair(&secret, &public);
        assert_eq!(result, Some(CredentialPairType::KeyPair));
    }

    #[test]
    fn test_two_generic_api_keys_not_a_pair() {
        let key1 = make_match("random_key_abc123", IdentifierType::ApiKey);
        let key2 = make_match("another_key_xyz789", IdentifierType::ApiKey);
        assert_eq!(is_credential_pair(&key1, &key2), None);
    }

    // === Twilio Pair ===

    #[test]
    fn test_twilio_pair() {
        let sid = make_match("AC00000000000000000000000000000000", IdentifierType::ApiKey);
        let token = make_match("1234567890abcdef1234567890abcdef", IdentifierType::ApiKey);
        let result = is_credential_pair(&sid, &token);
        assert_eq!(result, Some(CredentialPairType::TwilioPair));
    }

    #[test]
    fn test_twilio_pair_reversed() {
        let sid = make_match("AC00000000000000000000000000000000", IdentifierType::ApiKey);
        let token = make_match("1234567890abcdef1234567890abcdef", IdentifierType::ApiKey);
        let result = is_credential_pair(&token, &sid);
        assert_eq!(result, Some(CredentialPairType::TwilioPair));
    }

    // === Azure Service Principal ===

    #[test]
    fn test_azure_service_principal() {
        let client_id = make_match("550e8400-e29b-41d4-a716-446655440000", IdentifierType::Uuid);
        let secret = make_match("azure_secret_value_123", IdentifierType::ApiKey);
        let result = is_credential_pair(&client_id, &secret);
        assert_eq!(result, Some(CredentialPairType::AzureServicePrincipal));
    }

    #[test]
    fn test_azure_service_principal_with_password() {
        let client_id = make_match("550e8400-e29b-41d4-a716-446655440000", IdentifierType::Uuid);
        let secret = make_match("myAzureSecret123!", IdentifierType::Password);
        let result = is_credential_pair(&client_id, &secret);
        assert_eq!(result, Some(CredentialPairType::AzureServicePrincipal));
    }

    #[test]
    fn test_azure_reversed() {
        let client_id = make_match("550e8400-e29b-41d4-a716-446655440000", IdentifierType::Uuid);
        let secret = make_match("azure_secret_value_123", IdentifierType::ApiKey);
        let result = is_credential_pair(&secret, &client_id);
        assert_eq!(result, Some(CredentialPairType::AzureServicePrincipal));
    }

    // === Negative / Edge Cases ===

    #[test]
    fn test_unrelated_types_return_none() {
        let ip = make_match("192.168.1.1", IdentifierType::IpAddress);
        let phone = make_match("+15551234567", IdentifierType::PhoneNumber);
        assert_eq!(is_credential_pair(&ip, &phone), None);
    }

    #[test]
    fn test_same_non_apikey_type_returns_none() {
        let email1 = make_match("a@example.com", IdentifierType::Email);
        let email2 = make_match("b@example.com", IdentifierType::Email);
        assert_eq!(is_credential_pair(&email1, &email2), None);
    }

    #[test]
    fn test_specificity_twilio_over_keypair() {
        // Twilio SID + 32 hex should match TwilioPair, not KeyPair
        let sid = make_match("AC00000000000000000000000000000000", IdentifierType::ApiKey);
        let token = make_match("1234567890abcdef1234567890abcdef", IdentifierType::ApiKey);
        let result = is_credential_pair(&sid, &token);
        assert_eq!(result, Some(CredentialPairType::TwilioPair));
    }
}

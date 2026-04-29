//! AWS API key detection (access key, secret key, session token).

use super::super::super::super::common::patterns;
use super::MAX_IDENTIFIER_LENGTH;

/// Check if value is an AWS Access Key ID
///
/// AWS Access Key IDs start with "AKIA" (long-term) or "ASIA" (temporary STS)
/// followed by 16 alphanumeric characters
#[must_use]
pub fn is_aws_access_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_AWS_ACCESS.is_match(trimmed)
}

/// Check if value is an AWS Secret Access Key
///
/// AWS Secret Access Keys are 40 base64 characters
#[must_use]
pub fn is_aws_secret_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_AWS_SECRET.is_match(trimmed)
}

/// Check if value is an AWS Session Token
///
/// AWS session tokens are long Base64 strings (100+ characters) that accompany
/// temporary STS credentials (ASIA prefix access keys)
#[must_use]
pub fn is_aws_session_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_AWS_SESSION.is_match(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_aws_access_key() {
        // Long-term AKIA keys (constructed to avoid secret scanner false positives)
        let akia1 = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let akia2 = format!("AKIA{}", "I44QH8DHBEXAMPLE");
        assert!(is_aws_access_key(&akia1));
        assert!(is_aws_access_key(&akia2));
        // Temporary STS ASIA keys
        let asia1 = format!("ASIA{}", "IOSFODNN7EXAMPLE");
        let asia2 = format!("ASIA{}", "I44QH8DHBEXAMPLE");
        assert!(is_aws_access_key(&asia1));
        assert!(is_aws_access_key(&asia2));
        // Negative cases
        assert!(!is_aws_access_key("AKIA123")); // Too short
        assert!(!is_aws_access_key("ASIA123")); // Too short
        assert!(!is_aws_access_key("BKIAIOSFODNN7EXAMPLE")); // Wrong prefix
    }

    #[test]
    fn test_is_aws_secret_key() {
        assert!(is_aws_secret_key(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ));
        assert!(!is_aws_secret_key("short"));
    }

    #[test]
    fn test_is_aws_session_token() {
        // Valid session token (100+ Base64 characters)
        let token = "FwoGZXIvYXdzEBYaDHVlTGhjaHJNTkxqayLIATCCAQIwggECMIIBAjCCAQIwggECMIIBAjCCAQIwggECabcdef";
        // Pad to 100+ chars
        let long_token = format!("{}{}", token, "A".repeat(20));
        assert!(is_aws_session_token(&long_token));
        // Too short
        assert!(!is_aws_session_token("FwoGZXIvYXdzEBYaDHVl"));
    }
}

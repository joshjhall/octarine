//! Google Cloud Platform API key detection (GCP, OAuth, service accounts, Firebase FCM).

use super::super::super::super::common::patterns;
use super::MAX_IDENTIFIER_LENGTH;

/// Check if value is a Google Cloud Platform API key
///
/// GCP API keys start with "AIza" followed by 35 alphanumeric characters
#[must_use]
pub fn is_gcp_api_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_GCP.is_match(trimmed)
}

/// Check if text contains a GCP service account JSON marker
///
/// Detects `"type": "service_account"` in service account key JSON files.
#[must_use]
pub fn is_gcp_service_account(text: &str) -> bool {
    if text.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::GCP_SERVICE_ACCOUNT_TYPE.is_match(text)
}

/// Check if text contains a GCP service account email
///
/// Matches `*@*.iam.gserviceaccount.com` patterns.
#[must_use]
pub fn is_gcp_service_account_email(text: &str) -> bool {
    if text.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::GCP_SERVICE_ACCOUNT_EMAIL.is_match(text)
}

/// Check if value is a GCP OAuth2 client secret
///
/// GCP OAuth client secrets start with "GOCSPX-" followed by 28 characters.
#[must_use]
pub fn is_gcp_oauth_client_secret(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::GCP_OAUTH_CLIENT_SECRET.is_match(trimmed)
}

/// Check if value is a Firebase Cloud Messaging server key
///
/// FCM server keys start with "AAAA" followed by 140+ characters.
#[must_use]
pub fn is_firebase_fcm_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::FIREBASE_FCM_SERVER_KEY.is_match(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_gcp_api_key() {
        assert!(is_gcp_api_key("AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"));
        assert!(!is_gcp_api_key("AIza123")); // Too short
        assert!(!is_gcp_api_key("BIzaSyDaGmWKa4JsXZ")); // Wrong prefix
    }

    #[test]
    fn test_is_gcp_service_account() {
        assert!(is_gcp_service_account(
            r#"{"type": "service_account", "project_id": "my-project"}"#
        ));
        assert!(is_gcp_service_account(r#""type" : "service_account""#));
        assert!(!is_gcp_service_account(r#"{"type": "authorized_user"}"#));
        assert!(!is_gcp_service_account("random text"));
    }

    #[test]
    fn test_is_gcp_service_account_email() {
        assert!(is_gcp_service_account_email(
            "my-svc@my-project.iam.gserviceaccount.com"
        ));
        assert!(is_gcp_service_account_email(
            "test-123@example-proj.iam.gserviceaccount.com"
        ));
        assert!(!is_gcp_service_account_email("user@gmail.com"));
        assert!(!is_gcp_service_account_email("user@gserviceaccount.com")); // missing .iam.
    }

    #[test]
    fn test_is_gcp_oauth_client_secret() {
        // GOCSPX- + 28 chars = 35 total
        assert!(is_gcp_oauth_client_secret(
            "GOCSPX-abcdefghijklmnopqrstuvwx1234"
        ));
        assert!(!is_gcp_oauth_client_secret("GOCSPX-short")); // Too short
        assert!(!is_gcp_oauth_client_secret("NOT-GOCSPX-abcdefghijklmnop")); // Wrong prefix
    }

    #[test]
    fn test_is_firebase_fcm_key() {
        // 144+ chars (AAAA + 140)
        let key = format!("AAAA{}", "a".repeat(140));
        assert!(is_firebase_fcm_key(&key));
        assert!(!is_firebase_fcm_key("AAAA_too_short")); // Too short
        assert!(!is_firebase_fcm_key(&format!("BBBB{}", "a".repeat(140)))); // Wrong prefix
    }
}

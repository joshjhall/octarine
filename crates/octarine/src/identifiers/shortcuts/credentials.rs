//! Connection-string credential shortcuts.
//!
//! Convenience functions over [`CredentialsBuilder`](super::super::CredentialsBuilder)
//! for detecting and redacting embedded credentials in database/service URLs.

use super::super::CredentialsBuilder;
use super::super::types::CredentialMatch;

/// Check if value contains a connection string with embedded credentials
#[must_use]
pub fn is_connection_string_with_credentials(value: &str) -> bool {
    CredentialsBuilder::new().is_connection_string_with_credentials(value)
}

/// Check if value is a database connection string (URL-based)
#[must_use]
pub fn is_database_connection_string(value: &str) -> bool {
    CredentialsBuilder::new().is_database_connection_string(value)
}

/// Find all connection strings with credentials in text
#[must_use]
pub fn find_connection_strings(text: &str) -> Vec<CredentialMatch> {
    CredentialsBuilder::new().find_connection_strings_in_text(text)
}

/// Redact credentials in a connection string while preserving host/database
#[must_use]
pub fn redact_connection_string(value: &str) -> String {
    CredentialsBuilder::new().redact_connection_string(value)
}

/// Redact all connection strings in text
#[must_use]
pub fn redact_connection_strings(text: &str) -> String {
    CredentialsBuilder::new()
        .redact_connection_strings_in_text(text)
        .to_string()
}

/// Check if text contains framework-style credentials (Django, Rails YAML, .env, Docker Compose)
#[must_use]
pub fn is_framework_credential(text: &str) -> bool {
    CredentialsBuilder::new().is_framework_credential_present(text)
}

/// Find all framework-style credential matches in text
#[must_use]
pub fn find_framework_credentials(text: &str) -> Vec<CredentialMatch> {
    CredentialsBuilder::new().find_framework_credentials_in_text(text)
}

/// Redact the value of a framework credential while preserving the key
#[must_use]
pub fn redact_framework_credential(value: &str) -> String {
    CredentialsBuilder::new().redact_framework_credential(value)
}

/// Redact all framework-style credentials in text
#[must_use]
pub fn redact_framework_credentials(text: &str) -> String {
    CredentialsBuilder::new()
        .redact_framework_credentials_in_text(text)
        .to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_connection_string_with_credentials_shortcut() {
        assert!(is_connection_string_with_credentials("postgres://u:p@h/db"));
        assert!(!is_connection_string_with_credentials("hello world"));
    }

    #[test]
    fn test_is_framework_credential_shortcut() {
        assert!(is_framework_credential("DB_PASSWORD=secret"));
        assert!(is_framework_credential("'PASSWORD': 'sv'"));
        assert!(!is_framework_credential("APP_HOST=localhost"));
    }

    #[test]
    fn test_find_framework_credentials_shortcut() {
        let matches = find_framework_credentials("DB_PASSWORD=secret");
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("one match");
        assert_eq!(first.value, "secret");
    }

    #[test]
    fn test_redact_framework_credential_shortcut() {
        assert_eq!(
            redact_framework_credential("DB_PASSWORD=secret"),
            "DB_PASSWORD=****"
        );
    }

    #[test]
    fn test_redact_framework_credentials_shortcut() {
        let text = "DB_PASSWORD=secret\nAPP_HOST=localhost";
        let result = redact_framework_credentials(text);
        assert!(result.contains("DB_PASSWORD=****"));
        assert!(result.contains("APP_HOST=localhost"));
    }
}

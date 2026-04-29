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

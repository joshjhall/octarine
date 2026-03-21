//! Token and secret redaction functions
//!
//! Redacts JWTs, session tokens, SSH keys, API keys, and other secrets.

use super::super::config::RedactionProfile;
use crate::primitives::identifiers::{NetworkIdentifierBuilder, TokenIdentifierBuilder};

/// Redact API keys based on profile
pub(super) fn redact_api_keys(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            // Use the network builder's API key redaction which properly replaces entire keys
            let builder = NetworkIdentifierBuilder::new();
            builder.redact_api_keys_in_text(text).into_owned()
        }
        RedactionProfile::Development => {
            // In dev mode, show prefix for debugging
            if text.contains("sk_") || text.contains("pk_") {
                text.replace("sk_", "sk_[REDACTED]_")
                    .replace("pk_", "pk_[REDACTED]_")
            } else {
                text.to_string()
            }
        }
        RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact JWTs based on profile
pub(super) fn redact_jwts(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = TokenIdentifierBuilder::new();
            builder.redact_jwts_in_text(text).into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact session tokens based on profile
pub(super) fn redact_session_tokens(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = TokenIdentifierBuilder::new();
            builder.redact_session_ids_in_text(text).into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact SSH keys based on profile
pub(super) fn redact_ssh_keys(text: &str, profile: RedactionProfile) -> String {
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            let builder = TokenIdentifierBuilder::new();
            builder.redact_ssh_keys_in_text(text).into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

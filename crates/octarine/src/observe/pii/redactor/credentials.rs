//! Credential redaction functions (NIST Factor 1: Something You Know)
//!
//! Redacts passwords, PINs, security answers, and passphrases.

use super::super::config::RedactionProfile;
use crate::primitives::identifiers::{
    CredentialIdentifierBuilder, CredentialTextPolicy, NetworkIdentifierBuilder,
};

/// Redact passwords based on profile using primitives
pub(super) fn redact_passwords(text: &str, profile: RedactionProfile) -> String {
    let builder = CredentialIdentifierBuilder::new();
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => builder
            .redact_passwords_in_text_with_policy(text, CredentialTextPolicy::Complete)
            .into_owned(),
        RedactionProfile::Development => {
            // In development, still redact but allow anonymous placeholder
            builder
                .redact_passwords_in_text_with_policy(text, CredentialTextPolicy::Anonymous)
                .into_owned()
        }
        RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact PINs based on profile using primitives
pub(super) fn redact_pins(text: &str, profile: RedactionProfile) -> String {
    let builder = CredentialIdentifierBuilder::new();
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => builder
            .redact_pins_in_text_with_policy(text, CredentialTextPolicy::Complete)
            .into_owned(),
        RedactionProfile::Development => builder
            .redact_pins_in_text_with_policy(text, CredentialTextPolicy::Partial)
            .into_owned(),
        RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact security answers based on profile using primitives
pub(super) fn redact_security_answers(text: &str, profile: RedactionProfile) -> String {
    let builder = CredentialIdentifierBuilder::new();
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            // Security answers need context-based detection and redaction
            // Use find + manual redaction since there's no redact_security_answers_in_text
            let matches = builder.detect_security_answers(text);
            if matches.is_empty() {
                return text.to_string();
            }
            let mut result = text.to_string();
            for m in matches.iter().rev() {
                result.replace_range(m.start..m.end, "[SECURITY_ANSWER]");
            }
            result
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact passphrases based on profile using primitives
pub(super) fn redact_passphrases(text: &str, profile: RedactionProfile) -> String {
    let builder = CredentialIdentifierBuilder::new();
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            // Passphrases need context-based detection and redaction
            let matches = builder.detect_passphrases(text);
            if matches.is_empty() {
                return text.to_string();
            }
            let mut result = text.to_string();
            for m in matches.iter().rev() {
                result.replace_range(m.start..m.end, "[PASSPHRASE]");
            }
            result
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

/// Redact IP addresses based on profile using primitives
pub(super) fn redact_ip_addresses(text: &str, profile: RedactionProfile) -> String {
    let builder = NetworkIdentifierBuilder::new();
    match profile {
        RedactionProfile::ProductionStrict | RedactionProfile::ProductionLenient => {
            // Use primitives builder for IP redaction
            builder.redact_ips_in_text(text).into_owned()
        }
        RedactionProfile::Development | RedactionProfile::Testing => text.to_string(),
    }
}

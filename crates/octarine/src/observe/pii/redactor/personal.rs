//! Personal information redaction functions
//!
//! Redacts emails and phone numbers.

use super::super::config::RedactionProfile;
use crate::primitives::identifiers::PersonalIdentifierBuilder;

/// Redact emails based on profile using primitives
pub(super) fn redact_emails(text: &str, profile: RedactionProfile) -> String {
    let strategy = profile.email_strategy();
    let builder = PersonalIdentifierBuilder::new();
    builder.redact_emails_in_text_with_strategy(text, strategy)
}

/// Redact phone numbers based on profile using primitives
pub(super) fn redact_phones(text: &str, profile: RedactionProfile) -> String {
    let strategy = profile.phone_strategy();
    let builder = PersonalIdentifierBuilder::new();
    builder.redact_phones_in_text_with_strategy(text, strategy)
}

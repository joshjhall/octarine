//! Bulk redaction shortcuts (PII, credentials, all).
//!
//! Comprehensive multi-domain redaction helpers that compose all builders.

use crate::primitives::identifiers::{
    CredentialTextPolicy, GovernmentTextPolicy, PersonalTextPolicy,
};

use super::super::IdentifierBuilder;
use super::super::types::{FinancialTextPolicy, LocationTextPolicy};

/// Redact all PII in text
///
/// This is a comprehensive redaction that handles emails, phones, SSNs,
/// credit cards, and other common PII types.
#[must_use]
pub fn redact_pii(text: &str) -> String {
    let builder = IdentifierBuilder::new();
    let mut result = text.to_string();

    // Redact personal identifiers
    result = builder
        .personal()
        .redact_all_in_text_with_policy(&result, PersonalTextPolicy::Complete);

    // Redact government identifiers
    result = builder
        .government()
        .redact_all_in_text_with_policy(&result, GovernmentTextPolicy::Complete);

    // Redact financial identifiers
    result = builder
        .financial()
        .redact_all_in_text_with_policy(&result, FinancialTextPolicy::Complete);

    result
}

/// Redact all credentials in text
///
/// Handles passwords, tokens, etc.
#[must_use]
pub fn redact_credentials(text: &str) -> String {
    let builder = IdentifierBuilder::new();
    let mut result = text.to_string();

    result = builder
        .credentials()
        .redact_credentials_in_text_with_policy(&result, CredentialTextPolicy::Complete)
        .to_string();
    result = builder.token().redact_all_in_text(&result);

    result
}

/// Redact everything (PII, credentials, network identifiers)
///
/// Most comprehensive redaction - use when maximum privacy is needed.
#[must_use]
pub fn redact_all(text: &str) -> String {
    let builder = IdentifierBuilder::new();
    let mut result = text.to_string();

    // Redact all domains
    result = builder
        .personal()
        .redact_all_in_text_with_policy(&result, PersonalTextPolicy::Complete);
    result = builder
        .government()
        .redact_all_in_text_with_policy(&result, GovernmentTextPolicy::Complete);
    result = builder
        .financial()
        .redact_all_in_text_with_policy(&result, FinancialTextPolicy::Complete);
    result = builder
        .credentials()
        .redact_credentials_in_text_with_policy(&result, CredentialTextPolicy::Complete)
        .to_string();
    result = builder.token().redact_all_in_text(&result);
    result = builder.medical().redact_all_in_text(&result);
    result = builder.biometric().redact_all_in_text(&result);
    result = builder
        .organizational()
        .redact_all_in_text(&result)
        .to_string();
    result = builder
        .location()
        .redact_all_in_text_with_strategy(&result, LocationTextPolicy::Complete);

    result
}

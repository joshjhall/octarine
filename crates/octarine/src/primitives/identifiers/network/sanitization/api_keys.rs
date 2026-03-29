//! API key redaction functions
//!
//! Redaction for various cloud provider API keys, tokens, and JWTs.

use super::super::detection;
use super::super::redaction::{ApiKeyRedactionStrategy, TextRedactionPolicy};
use crate::primitives::data::tokens::RedactionTokenCore;
use std::borrow::Cow;

// ============================================================================
// Individual Redaction
// ============================================================================

/// Redact a single API key with explicit strategy
///
/// Uses detection to verify input is a valid API key before redacting.
///
/// # Arguments
/// * `key` - The API key to redact
/// * `strategy` - How to redact the API key
#[must_use]
pub fn redact_api_key_with_strategy(key: &str, strategy: ApiKeyRedactionStrategy) -> String {
    if matches!(strategy, ApiKeyRedactionStrategy::Skip) {
        return key.to_string();
    }

    let is_valid = detection::is_api_key(key);

    match strategy {
        ApiKeyRedactionStrategy::Skip => key.to_string(),
        ApiKeyRedactionStrategy::ShowPrefix => {
            // Show prefix (e.g., sk_live_, pk_test_)
            // Try to show prefix even for invalid keys if they have the structure
            if let Some(underscore_pos) = key.rfind('_') {
                if underscore_pos < key.len() {
                    format!("{}****", &key[..=underscore_pos])
                } else {
                    RedactionTokenCore::ApiKey.into()
                }
            } else {
                RedactionTokenCore::ApiKey.into()
            }
        }
        ApiKeyRedactionStrategy::Mask => {
            // Existing mask behavior: show first 12 chars
            if key.len() >= 12 {
                format!("{}***", &key[..12])
            } else {
                RedactionTokenCore::ApiKey.into()
            }
        }
        ApiKeyRedactionStrategy::Token => RedactionTokenCore::ApiKey.into(),
        ApiKeyRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        ApiKeyRedactionStrategy::Asterisks => {
            // For invalid input, use simpler handling
            if !is_valid {
                RedactionTokenCore::ApiKey.into()
            } else {
                "*".repeat(key.len())
            }
        }
        ApiKeyRedactionStrategy::Hashes => {
            // For invalid input, use simpler handling
            if !is_valid {
                RedactionTokenCore::ApiKey.into()
            } else {
                "#".repeat(key.len())
            }
        }
    }
}

// ============================================================================
// Text Redaction
// ============================================================================

/// Redact all API keys in text
///
/// Uses detection layer for ReDoS protection and accurate matching.
///
/// # Arguments
/// * `text` - The text to scan and redact
/// * `policy` - Redaction policy to apply
#[must_use]
pub fn redact_api_keys_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_api_key_strategy();
    if matches!(strategy, ApiKeyRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let matches = detection::find_api_keys_in_text(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();
    for m in matches.iter().rev() {
        let redacted = redact_api_key_with_strategy(&m.matched_text, strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_redact_api_key_with_strategy_token() {
        assert_eq!(
            redact_api_key_with_strategy(
                "sk_live_1234567890abcdef",
                ApiKeyRedactionStrategy::Token
            ),
            "[API_KEY]"
        );
    }

    #[test]
    fn test_redact_api_key_with_strategy_show_prefix() {
        assert_eq!(
            redact_api_key_with_strategy("sk_live_1234567890", ApiKeyRedactionStrategy::ShowPrefix),
            "sk_live_****"
        );
    }

    #[test]
    fn test_redact_api_key_with_strategy_mask() {
        assert_eq!(
            redact_api_key_with_strategy(
                &format!("sk_live_{}", "EXAMPLE000000000000KEY01abcd"),
                ApiKeyRedactionStrategy::Mask
            ),
            "sk_live_EXAM***"
        );
        assert_eq!(
            redact_api_key_with_strategy("short", ApiKeyRedactionStrategy::Mask),
            "[API_KEY]"
        );
    }

    #[test]
    fn test_redact_api_keys_in_text() {
        let text = &format!("Key: sk_live_{}", "EXAMPLE000000000000KEY01abcd");
        let result = redact_api_keys_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[API_KEY]"));
        assert!(!result.contains("sk_live"));
    }
}

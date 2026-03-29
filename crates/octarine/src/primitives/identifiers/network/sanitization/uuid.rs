//! UUID redaction functions
//!
//! Redaction for Universally Unique Identifiers.

use super::super::detection;
use super::super::redaction::{TextRedactionPolicy, UuidRedactionStrategy};
use crate::primitives::data::tokens::RedactionTokenCore;
use std::borrow::Cow;

// ============================================================================
// Individual Redaction
// ============================================================================

/// Redact a single UUID with explicit strategy
///
/// Uses detection to verify input is a valid UUID before redacting.
/// Invalid input is treated as potential PII and redacted to token.
///
/// # Arguments
/// * `uuid` - The UUID to redact
/// * `strategy` - How to redact the UUID
///
/// # Examples
/// ```ignore
/// use octarine::primitives::identifiers::network::{redact_uuid_with_strategy, UuidRedactionStrategy};
///
/// let uuid = "550e8400-e29b-41d4-a716-446655440000";
/// assert_eq!(redact_uuid_with_strategy(uuid, UuidRedactionStrategy::Token), "[UUID]");
/// assert_eq!(redact_uuid_with_strategy(uuid, UuidRedactionStrategy::ShowPrefix), "550e8400-****");
/// ```
#[must_use]
pub fn redact_uuid_with_strategy(uuid: &str, strategy: UuidRedactionStrategy) -> String {
    if matches!(strategy, UuidRedactionStrategy::Skip) {
        return uuid.to_string();
    }

    // For invalid input, still redact but use simplified strategy
    if !detection::is_uuid(uuid) {
        return match strategy {
            UuidRedactionStrategy::Skip => uuid.to_string(),
            UuidRedactionStrategy::ShowVersion
            | UuidRedactionStrategy::ShowPrefix
            | UuidRedactionStrategy::Mask
            | UuidRedactionStrategy::Token => RedactionTokenCore::Uuid.into(),
            UuidRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
            UuidRedactionStrategy::Asterisks => "*".repeat(uuid.len()),
            UuidRedactionStrategy::Hashes => "#".repeat(uuid.len()),
        };
    }

    match strategy {
        UuidRedactionStrategy::Skip => uuid.to_string(),
        UuidRedactionStrategy::ShowVersion => {
            // Detect version from UUID
            if detection::is_uuid_v4(uuid) {
                "[UUID-v4]".to_string()
            } else if detection::is_uuid_v5(uuid) {
                "[UUID-v5]".to_string()
            } else {
                RedactionTokenCore::Uuid.into()
            }
        }
        UuidRedactionStrategy::ShowPrefix => {
            // Show first 8 characters (first segment)
            if uuid.len() >= 8 {
                format!("{}-****", &uuid[..8])
            } else {
                RedactionTokenCore::Uuid.into()
            }
        }
        UuidRedactionStrategy::Mask => {
            // Existing mask behavior: 550e8400-****-****-****-************
            if uuid.len() == 36 && uuid.chars().filter(|&c| c == '-').count() == 4 {
                format!("{}****-****-****-************", &uuid[..8])
            } else {
                RedactionTokenCore::Uuid.into()
            }
        }
        UuidRedactionStrategy::Token => RedactionTokenCore::Uuid.into(),
        UuidRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        UuidRedactionStrategy::Asterisks => "*".repeat(uuid.len()),
        UuidRedactionStrategy::Hashes => "#".repeat(uuid.len()),
    }
}

// ============================================================================
// Text Redaction
// ============================================================================

/// Redact all UUIDs in text
///
/// Uses detection layer for ReDoS protection and accurate matching.
///
/// # Arguments
/// * `text` - The text to scan and redact
/// * `policy` - Redaction policy to apply
#[must_use]
pub fn redact_uuids_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_uuid_strategy();
    if matches!(strategy, UuidRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let matches = detection::find_uuids_in_text(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();
    // Process matches in reverse order to maintain string positions
    for m in matches.iter().rev() {
        let redacted = redact_uuid_with_strategy(&m.matched_text, strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_redact_uuid_with_strategy_token() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            redact_uuid_with_strategy(uuid, UuidRedactionStrategy::Token),
            "[UUID]"
        );
    }

    #[test]
    fn test_redact_uuid_with_strategy_show_prefix() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            redact_uuid_with_strategy(uuid, UuidRedactionStrategy::ShowPrefix),
            "550e8400-****"
        );
    }

    #[test]
    fn test_redact_uuid_with_strategy_mask() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let result = redact_uuid_with_strategy(uuid, UuidRedactionStrategy::Mask);
        assert!(result.starts_with("550e8400"));
        assert!(result.contains("****"));
    }

    #[test]
    fn test_redact_uuid_with_strategy_invalid() {
        let invalid = "not-a-uuid";
        assert_eq!(
            redact_uuid_with_strategy(invalid, UuidRedactionStrategy::Token),
            "[UUID]"
        );
        assert_eq!(
            redact_uuid_with_strategy(invalid, UuidRedactionStrategy::Anonymous),
            "[REDACTED]"
        );
    }

    #[test]
    fn test_redact_uuids_in_text() {
        let text = "ID: 550e8400-e29b-41d4-a716-446655440000";
        let result = redact_uuids_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[UUID]"));
        assert!(!result.contains("550e8400"));
    }

    #[test]
    fn test_cow_optimization() {
        // Clean text should return borrowed
        let text = "Clean text";
        let result = redact_uuids_in_text(text, TextRedactionPolicy::Complete);
        assert!(matches!(result, Cow::Borrowed(_)));

        // Dirty text should return owned
        let text = "UUID: 550e8400-e29b-41d4-a716-446655440000";
        let result = redact_uuids_in_text(text, TextRedactionPolicy::Complete);
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn test_policy_none() {
        let text = "UUID: 550e8400-e29b-41d4-a716-446655440000";
        let result = redact_uuids_in_text(text, TextRedactionPolicy::Skip);
        assert_eq!(result, text);
    }

    #[test]
    fn test_policy_partial() {
        let text = "UUID: 550e8400-e29b-41d4-a716-446655440000";
        let result = redact_uuids_in_text(text, TextRedactionPolicy::Partial);
        assert!(result.contains("550e8400-****"));
    }

    #[test]
    fn test_policy_complete() {
        let text = "UUID: 550e8400-e29b-41d4-a716-446655440000";
        let result = redact_uuids_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[UUID]"));
    }

    #[test]
    fn test_policy_anonymous() {
        let text = "UUID: 550e8400-e29b-41d4-a716-446655440000";
        let result = redact_uuids_in_text(text, TextRedactionPolicy::Anonymous);
        assert!(result.contains("[REDACTED]"));
    }
}

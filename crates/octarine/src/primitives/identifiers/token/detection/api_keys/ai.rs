//! AI / LLM API key detection (OpenAI).

use super::super::super::super::common::patterns;
use super::MAX_IDENTIFIER_LENGTH;

/// Check if value is an OpenAI API key
///
/// OpenAI keys come in three formats:
/// - Legacy: `sk-[20 alnum]T3BlbkFJ[20 alnum]`
/// - Project: `sk-proj-[80+ alnum/underscore/dash]`
/// - Organization: `org-[24 alnum]`
#[must_use]
pub fn is_openai_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_OPENAI_LEGACY.is_match(trimmed)
        || patterns::network::API_KEY_OPENAI_PROJECT.is_match(trimmed)
        || patterns::network::API_KEY_OPENAI_ORG.is_match(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_openai_key() {
        // Legacy format: sk-[20 alnum]T3BlbkFJ[20 alnum]
        assert!(is_openai_key(&format!(
            "sk-{}T3BlbkFJ{}",
            "A".repeat(20),
            "B".repeat(20)
        )));

        // Project format: sk-proj-[80+ chars]
        assert!(is_openai_key(&format!("sk-proj-{}", "AbCd1234".repeat(10))));

        // Organization format: org-[24 alnum]
        assert!(is_openai_key(&format!("org-{}", "a".repeat(24))));

        // Invalid: sk-proj- too short
        assert!(!is_openai_key("sk-proj-short"));

        // Invalid: org- wrong length
        assert!(!is_openai_key("org-short"));

        // Invalid: wrong prefix entirely
        assert!(!is_openai_key("not-an-openai-key"));
    }
}

//! URL redaction functions
//!
//! Redaction for web URLs with various protocol schemes.

use super::super::detection;
use super::super::redaction::{TextRedactionPolicy, UrlRedactionStrategy};
use crate::primitives::data::tokens::RedactionTokenCore;
use std::borrow::Cow;

// ============================================================================
// Individual Redaction
// ============================================================================

/// Redact a single URL with explicit strategy
///
/// Uses detection to verify input is a valid URL before redacting.
///
/// # Arguments
/// * `url` - The URL to redact
/// * `strategy` - How to redact the URL
#[must_use]
pub fn redact_url_with_strategy(url: &str, strategy: UrlRedactionStrategy) -> String {
    if matches!(strategy, UrlRedactionStrategy::Skip) {
        return url.to_string();
    }

    // For invalid input, still redact but use simplified strategy
    if !detection::is_url(url) {
        return match strategy {
            UrlRedactionStrategy::Skip => url.to_string(),
            UrlRedactionStrategy::ShowDomain
            | UrlRedactionStrategy::ShowScheme
            | UrlRedactionStrategy::Mask
            | UrlRedactionStrategy::Token => RedactionTokenCore::Url.into(),
            UrlRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
            UrlRedactionStrategy::Asterisks => "*".repeat(url.len()),
            UrlRedactionStrategy::Hashes => "#".repeat(url.len()),
        };
    }

    match strategy {
        UrlRedactionStrategy::Skip => url.to_string(),
        UrlRedactionStrategy::ShowDomain | UrlRedactionStrategy::Mask => {
            // Show protocol and domain, hide path/query
            if let Some(protocol_end) = url.find("://") {
                let separator_end = protocol_end.saturating_add(3);
                if separator_end > url.len() {
                    return RedactionTokenCore::Url.into();
                }

                let protocol = &url[..separator_end];
                let remainder = &url[separator_end..];

                // Find first slash after protocol
                if let Some(path_start) = remainder.find('/') {
                    let domain = &remainder[..path_start];
                    format!("{}{}***", protocol, domain)
                } else {
                    url.to_string() // No path, just protocol://domain
                }
            } else {
                RedactionTokenCore::Url.into()
            }
        }
        UrlRedactionStrategy::ShowScheme => {
            // Show only the scheme (https, http, etc.)
            if let Some(protocol_end) = url.find("://") {
                format!("{}://***", &url[..protocol_end])
            } else {
                RedactionTokenCore::Url.into()
            }
        }
        UrlRedactionStrategy::Token => RedactionTokenCore::Url.into(),
        UrlRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        UrlRedactionStrategy::Asterisks => "*".repeat(url.len()),
        UrlRedactionStrategy::Hashes => "#".repeat(url.len()),
    }
}

// ============================================================================
// Text Redaction
// ============================================================================

/// Redact all URLs in text
///
/// Uses detection layer for ReDoS protection and accurate matching.
///
/// # Arguments
/// * `text` - The text to scan and redact
/// * `policy` - Redaction policy to apply
#[must_use]
pub fn redact_urls_in_text(text: &str, policy: TextRedactionPolicy) -> Cow<'_, str> {
    let strategy = policy.to_url_strategy();
    if matches!(strategy, UrlRedactionStrategy::Skip) {
        return Cow::Borrowed(text);
    }

    let matches = detection::find_urls_in_text(text);
    if matches.is_empty() {
        return Cow::Borrowed(text);
    }

    let mut result = text.to_string();
    for m in matches.iter().rev() {
        let redacted = redact_url_with_strategy(&m.matched_text, strategy);
        result.replace_range(m.start..m.end, &redacted);
    }

    Cow::Owned(result)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_redact_url_with_strategy_token() {
        assert_eq!(
            redact_url_with_strategy("https://example.com/path", UrlRedactionStrategy::Token),
            "[URL]"
        );
    }

    #[test]
    fn test_redact_url_with_strategy_show_domain() {
        assert_eq!(
            redact_url_with_strategy(
                "https://example.com/path?key=value",
                UrlRedactionStrategy::ShowDomain
            ),
            "https://example.com***"
        );
    }

    #[test]
    fn test_redact_url_with_strategy_show_scheme() {
        assert_eq!(
            redact_url_with_strategy("https://example.com/path", UrlRedactionStrategy::ShowScheme),
            "https://***"
        );
    }

    #[test]
    fn test_redact_url_with_strategy_mask() {
        assert_eq!(
            redact_url_with_strategy(
                "https://example.com/path?key=value",
                UrlRedactionStrategy::Mask
            ),
            "https://example.com***"
        );
        assert_eq!(
            redact_url_with_strategy("https://example.com", UrlRedactionStrategy::Mask),
            "https://example.com"
        );
        assert_eq!(
            redact_url_with_strategy(
                "wss://socket.example.com/stream",
                UrlRedactionStrategy::Mask
            ),
            "wss://socket.example.com***"
        );
        assert_eq!(
            redact_url_with_strategy("ws://localhost:8080", UrlRedactionStrategy::Mask),
            "ws://localhost:8080"
        );
    }

    #[test]
    fn test_redact_urls_in_text() {
        let text = "Visit https://example.com/path";
        let result = redact_urls_in_text(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[URL]"));
        assert!(!result.contains("example.com"));
    }
}

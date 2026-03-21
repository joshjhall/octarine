//! Session ID detection
//!
//! Heuristic-based detection functions for session identifiers.

use std::collections::HashSet;

// ============================================================================
// Public API
// ============================================================================

/// Check if a string looks like a session ID (high entropy heuristic)
///
/// Session IDs are typically:
/// - 20+ characters long
/// - Mix of letters and numbers
/// - High entropy (not repetitive)
///
/// This is a heuristic check and may have false positives/negatives.
#[must_use]
pub fn is_likely_session_id(value: &str) -> bool {
    let trimmed = value.trim();

    // Must be at least 20 characters
    if trimmed.len() < 20 {
        return false;
    }

    // Must have both letters and numbers
    let has_letters = trimmed.chars().any(|c| c.is_alphabetic());
    let has_numbers = trimmed.chars().any(|c| c.is_numeric());

    if !has_letters || !has_numbers {
        return false;
    }

    // Check for low entropy (repetitive patterns)
    let unique_chars: HashSet<char> = trimmed.chars().collect();
    let entropy_ratio = unique_chars.len() as f32 / trimmed.len() as f32;

    // At least 50% unique characters
    entropy_ratio > 0.5
}

/// Check if session ID is a known test/development ID
///
/// Detects:
/// - Session IDs with test prefixes (test-, demo-, sample-)
/// - Sequential or repeating patterns
/// - Common test session IDs
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::detection::is_test_session_id;
///
/// assert!(is_test_session_id("test-session-123456"));
/// assert!(is_test_session_id("sess_test_abc123def456"));
/// assert!(!is_test_session_id("sess_real_abc123def456xyz"));
/// ```
#[must_use]
pub fn is_test_session_id(session_id: &str) -> bool {
    let trimmed = session_id.trim();
    let lower = trimmed.to_lowercase();

    // Test prefixes
    let test_prefixes = [
        "test-", "test_", "demo-", "demo_", "sample-", "sample_", "fake-", "fake_", "mock-",
        "mock_",
    ];
    for prefix in &test_prefixes {
        if lower.starts_with(prefix) {
            return true;
        }
    }

    // Contains test keywords
    let test_keywords = [
        "_test", "-test", "_demo", "-demo", "_mock", "-mock", "_fake", "-fake",
    ];
    for keyword in &test_keywords {
        if lower.contains(keyword) {
            return true;
        }
    }

    // Sequential patterns
    if lower.contains("123456")
        || lower.contains("abcdef")
        || lower.contains("000000")
        || lower.contains("111111")
    {
        return true;
    }

    // All same character
    if trimmed.len() >= 20 {
        let first_char = trimmed.chars().next().unwrap_or('x');
        if trimmed.chars().all(|c| c == first_char) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_likely_session_id() {
        // Valid high-entropy session IDs
        assert!(is_likely_session_id("Ab3De8Gh2Jk5Mn9Pq4Rs7Tv0Wx3Yz6"));
        assert!(is_likely_session_id("s1e2s3s4i5o6n7i8d9a0b1c2d3e4f5"));

        // Too short
        assert!(!is_likely_session_id("short123"));
        assert!(!is_likely_session_id("12345678901234567"));

        // Low entropy (repetitive)
        assert!(!is_likely_session_id("aaaaaaaaaaaaaaaaaaaaaa"));
        assert!(!is_likely_session_id("11111111111111111111111"));
        assert!(!is_likely_session_id("abcabcabcabcabcabcabcabc"));

        // Only letters or only numbers
        assert!(!is_likely_session_id("abcdefghijklmnopqrstuvwxyz"));
        assert!(!is_likely_session_id("123456789012345678901234"));
    }

    #[test]
    fn test_is_test_session_id_prefixes() {
        // Test prefixes
        assert!(is_test_session_id("test-session-abc123"));
        assert!(is_test_session_id("test_session_abc123"));
        assert!(is_test_session_id("demo-session-xyz789"));
        assert!(is_test_session_id("sample_sess_12345"));
        assert!(is_test_session_id("mock-session-abcdef"));
    }

    #[test]
    fn test_is_test_session_id_keywords() {
        // Contains test keywords
        assert!(is_test_session_id("session_test_abc123"));
        assert!(is_test_session_id("abc-demo-xyz123456"));
        assert!(is_test_session_id("real_fake_session_id"));
    }

    #[test]
    fn test_is_test_session_id_patterns() {
        // Sequential patterns
        assert!(is_test_session_id("sess_1234567890abc"));
        assert!(is_test_session_id("session_abcdefghij"));
        assert!(is_test_session_id("id_0000001111112222"));
    }

    #[test]
    fn test_is_test_session_id_production() {
        // Production session IDs should not be test
        assert!(!is_test_session_id("sess_7f8k2n9p3q5r6s1t"));
        assert!(!is_test_session_id("session_a7b8c9d0e1f2"));
    }
}

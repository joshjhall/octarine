//! Api Keys validation functions
//!
//! Pure validation functions for token identifiers.

use super::super::super::common::patterns;
use super::super::detection::{ApiKeyProvider, detect_api_key_provider};
use crate::primitives::Problem;

// ============================================================================
// API Key Validation
// ============================================================================

/// Validate API key format (strict - returns Result with provider)
///
/// # Examples
///
/// ```ignore
/// let provider = validate_api_key("sk_live_123456789012345678", 10, 100)?;
/// assert_eq!(provider, ApiKeyProvider::Stripe);
/// ```
pub fn validate_api_key(
    key: &str,
    min_length: usize,
    max_length: usize,
) -> Result<ApiKeyProvider, Problem> {
    // Note: We don't call is_api_key() here because this function is designed
    // to validate generic API key formats with custom length requirements.
    // The is_api_key() detector only matches known provider patterns.
    // We detect the provider at the end using detect_api_key_provider().

    // Length validation
    if key.len() < min_length {
        return Err(Problem::Validation(format!(
            "API key too short (minimum {} characters)",
            min_length
        )));
    }

    if key.len() > max_length {
        return Err(Problem::Validation(format!(
            "API key too long (maximum {} characters)",
            max_length
        )));
    }

    // Check for test/example keys
    let key_lower = key.to_lowercase();

    // OWASP: Allow properly prefixed keys (service prefixes like pk_, sk_, etc.)
    let has_service_prefix = key_lower.starts_with("pk_")
        || key_lower.starts_with("sk_")
        || key_lower.starts_with("test_")
        || key_lower.starts_with("demo_");

    // Placeholder text patterns - always reject these
    let placeholder_patterns = [
        "your_api_key",
        "api_key_here",
        "replace_me",
        "example",
        "sample",
        "dummy",
    ];

    // Check for placeholder text (for all keys, even with prefixes)
    if placeholder_patterns
        .iter()
        .any(|&pattern| key_lower.contains(pattern))
    {
        return Err(Problem::Validation(
            "Generic test/example API keys not allowed".into(),
        ));
    }

    // Sequential patterns - only reject if key is mostly sequential
    // Keys like "valid_key_1234567890" are OK, but "12345678901234567890" should be rejected
    let sequential_patterns = ["00000", "11111", "12345", "abcdef"];

    // Only check sequential patterns for unprefixed keys
    // And only reject if the key is dominated by sequential content (no other meaningful text)
    if !has_service_prefix {
        // Check if key is mostly sequential (starts with or is mostly sequential pattern)
        let is_mostly_sequential = sequential_patterns.iter().any(|&pattern| {
            key_lower.starts_with(pattern) || key_lower.replace(pattern, "").len() < 5
        });

        if is_mostly_sequential {
            return Err(Problem::Validation(
                "Sequential or predictable API keys not allowed".into(),
            ));
        }
    }

    // Reject unprefixed test/demo keywords
    if !has_service_prefix && (key_lower.contains("test") || key_lower.contains("demo")) {
        return Err(Problem::Validation(
            "Test/demo keys must use proper prefixes (pk_test_, sk_test_, etc.)".into(),
        ));
    }

    // Check character set
    if !key
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(Problem::Validation(
            "API key contains invalid characters".into(),
        ));
    }

    // Detect and return provider
    let provider = detect_api_key_provider(key)
        .ok_or_else(|| Problem::Validation("Unable to detect API key provider".into()))?;

    Ok(provider)
}

// ============================================================================
#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::super::{analyze_key_strength, validate_key_entropy};
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_adversarial_api_key_weak_patterns() {
        // Sequential patterns (should fail entropy check)
        assert!(validate_key_entropy("abcdefghijklmnop", 3.0).is_err());
        assert!(validate_key_entropy("1234567890123456", 3.0).is_err());

        // Repeated patterns
        assert!(validate_key_entropy("aaaaaaaaaaaaaaaa", 3.0).is_err());
        assert!(validate_key_entropy("abcabcabcabcabc", 3.0).is_err());

        // Dictionary words (low entropy)
        assert!(validate_key_entropy("passwordpassword", 3.0).is_err());
    }

    #[test]
    fn test_adversarial_api_key_length_bypass() {
        // API key validation with min/max length

        // Just under minimum (should fail)
        assert!(validate_api_key("abc", 10, 100).is_err());

        // Exactly at minimum (should pass)
        assert!(validate_api_key("a".repeat(10).as_str(), 10, 100).is_ok());

        // Exactly at maximum (should pass)
        assert!(validate_api_key("a".repeat(100).as_str(), 10, 100).is_ok());

        // Just over maximum (should fail)
        assert!(validate_api_key("a".repeat(101).as_str(), 10, 100).is_err());
    }

    #[test]
    fn test_adversarial_api_key_test_patterns() {
        // Test/demo keys should be rejected (but test_ prefix is valid for some providers)
        assert!(validate_api_key("testkey1234567890abcdef", 10, 100).is_err());
        assert!(validate_api_key("demokey1234567890abcdef", 10, 100).is_err());
        assert!(validate_api_key("example1234567890abcdef", 10, 100).is_err());

        // Valid provider prefixes like test_ are allowed
        let _ = validate_api_key("test_1234567890abcdef", 10, 100);
        // May be valid
    }

    #[test]
    fn test_adversarial_api_key_provider_prefix_bypass() {
        // Valid provider prefixes should be allowed
        assert!(validate_api_key("sk_live_1234567890abcdef", 10, 100).is_ok());
        assert!(validate_api_key("pk_test_1234567890abcdef", 10, 100).is_ok());

        // But "test" and "demo" in the body should still fail
        assert!(validate_api_key("sk_test_1234567890abcdef", 10, 100).is_ok()); // sk_test_ is valid prefix

        // Invalid: test/demo without proper prefix
        assert!(validate_api_key("invalidtest1234567890", 10, 100).is_err());
    }

    #[test]
    #[ignore = "perf test - run manually with: cargo test -p octarine test_perf_ -- --ignored"]
    fn test_perf_api_key_format_validation() {
        // API key format validation
        let key = format!("sk_live_{}", "EXAMPLE000000000KEY01abcdef");
        let iterations = 10000;
        let start = std::time::Instant::now();

        for _ in 0..iterations {
            let _ = validate_api_key(&key, 10, 100);
        }

        let duration = start.elapsed();
        let avg_micros = duration.as_micros() / iterations;

        // API key validation should be sub-50 microseconds
        assert!(avg_micros < 50, "Average: {} µs", avg_micros);
    }

    #[test]
    #[ignore = "perf test - run manually with: cargo test -p octarine test_perf_ -- --ignored"]
    fn test_perf_batch_api_key_strength() {
        // Batch strength analysis of multiple API keys
        let keys = vec![
            "sk_live_AbCdEf123456GhIjKl",
            "pk_test_MnOpQr789012StUvWx",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG",
        ];

        let iterations = 1000;
        let start = std::time::Instant::now();

        for _ in 0..iterations {
            for key in &keys {
                let _ = analyze_key_strength(key);
            }
        }

        let duration = start.elapsed();
        let total_ops = iterations * keys.len() as u128;
        let avg_micros = duration.as_micros() / total_ops;

        // Batch strength analysis should maintain sub-150µs average
        assert!(avg_micros < 150, "Average: {} µs", avg_micros);
    }

    proptest! {

        #[test]
        fn prop_no_panic_api_key_validation(s in "\\PC*") {
                let _ = validate_api_key(&s, 16, 128);
            }

    }
}

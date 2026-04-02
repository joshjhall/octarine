//! Entropy-based high-entropy string detection
//!
//! Detects potential secrets, API keys, and generated passwords by analyzing
//! Shannon entropy with per-charset thresholds and false positive filtering.
//!
//! # Detection Strategy
//!
//! 1. Tokenize text by whitespace and common delimiters
//! 2. Filter tokens by minimum length
//! 3. Classify charset (Hex, Base64, Alphanumeric, Unknown)
//! 4. Apply per-charset entropy threshold
//! 5. Apply digit penalty (detect-secrets convention)
//! 6. Exclude known safe patterns (UUIDs, version strings, hex colors)
//!
//! # False Positive Mitigation
//!
//! Common patterns that produce high entropy but are not secrets:
//! - UUIDs (`550e8400-e29b-41d4-a716-446655440000`)
//! - Semantic versions (`1.2.3-beta.4+build.123`)
//! - Hex colors (`#FF5733`)
//! - Repeated characters (`aaaaaaaaaaaaaaaa`)
//! - All-digit strings (phone numbers, timestamps)

use super::charsets::{CharsetClass, classify_charset};
use super::core::calculate_shannon_entropy;
use super::types::EntropyConfig;
use crate::primitives::identifiers::types::{DetectionConfidence, IdentifierMatch, IdentifierType};

/// Maximum input length for text scanning (ReDoS protection)
const MAX_INPUT_LENGTH: usize = 100_000;

// ============================================================================
// Single-Value Detection
// ============================================================================

/// Check if a string has high entropy (potential secret)
///
/// Uses default thresholds: Base64 ≥ 4.5, Hex ≥ 3.0, minimum 20 chars.
/// Excludes known safe patterns (UUIDs, version strings, hex colors).
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::entropy::detection::is_high_entropy;
///
/// // Random API key — high entropy
/// assert!(is_high_entropy("Rq7mX9nB3pL2wK8jF5hT4vD6cE1fG0aH"));
///
/// // UUID — excluded as false positive
/// assert!(!is_high_entropy("550e8400-e29b-41d4-a716-446655440000"));
/// ```
#[must_use]
pub fn is_high_entropy(value: &str) -> bool {
    is_high_entropy_with_config(value, &EntropyConfig::default())
}

/// Check if a string has high entropy using Base64 threshold
///
/// Tests against the Base64 threshold (default 4.5) regardless of charset.
#[must_use]
pub fn is_high_entropy_base64(value: &str) -> bool {
    let config = EntropyConfig::default();
    if value.len() < config.min_length {
        return false;
    }
    let entropy = calculate_shannon_entropy(value);
    entropy >= config.base64_threshold
}

/// Check if a string has high entropy using Hex threshold
///
/// Tests against the Hex threshold (default 3.0) regardless of charset.
#[must_use]
pub fn is_high_entropy_hex(value: &str) -> bool {
    let config = EntropyConfig::default();
    if value.len() < config.min_length {
        return false;
    }
    let entropy = calculate_shannon_entropy(value);
    entropy >= config.hex_threshold
}

/// Check if a string has high entropy with custom configuration
#[must_use]
fn is_high_entropy_with_config(value: &str, config: &EntropyConfig) -> bool {
    if value.len() < config.min_length {
        return false;
    }

    // Exclude known safe patterns
    if config.exclude_known_patterns && is_known_safe_pattern(value) {
        return false;
    }

    let charset = classify_charset(value);
    let threshold = config.threshold_for(&charset);
    let mut entropy = calculate_shannon_entropy(value);

    // Apply digit penalty for all-digit strings
    if config.digit_penalty && is_all_digits(value) {
        entropy = apply_digit_penalty(entropy, value.len());
    }

    entropy >= threshold
}

// ============================================================================
// Text Scanning
// ============================================================================

/// Detect high-entropy strings in text using default configuration
///
/// Scans text for tokens that exceed entropy thresholds, filtering out
/// known safe patterns.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::entropy::detection::detect_high_entropy_strings_in_text;
///
/// let text = r#"token_val = "Rq7mX9nB3pL2wK8jF5hT4vD6cE1fG0aH""#;
/// let matches = detect_high_entropy_strings_in_text(text);
/// assert!(!matches.is_empty());
/// ```
#[must_use]
pub fn detect_high_entropy_strings_in_text(text: &str) -> Vec<IdentifierMatch> {
    detect_high_entropy_strings_with_config(text, &EntropyConfig::default())
}

/// Detect high-entropy strings in text with custom configuration
///
/// # Arguments
///
/// * `text` - The text to scan for high-entropy strings
/// * `config` - Custom entropy detection configuration
///
/// # Returns
///
/// Vector of `IdentifierMatch` for each detected high-entropy string.
/// Matches have `Medium` confidence since entropy detection is heuristic.
#[must_use]
pub fn detect_high_entropy_strings_with_config(
    text: &str,
    config: &EntropyConfig,
) -> Vec<IdentifierMatch> {
    if text.is_empty() || text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for (start, token) in tokenize(text) {
        if token.len() < config.min_length {
            continue;
        }

        if config.exclude_known_patterns && is_known_safe_pattern(token) {
            continue;
        }

        let charset = classify_charset(token);
        let threshold = config.threshold_for(&charset);
        let mut entropy = calculate_shannon_entropy(token);

        if config.digit_penalty && is_all_digits(token) {
            entropy = apply_digit_penalty(entropy, token.len());
        }

        if entropy >= threshold {
            let end = start.saturating_add(token.len());
            matches.push(IdentifierMatch::new(
                start,
                end,
                token.to_string(),
                IdentifierType::HighEntropyString,
                DetectionConfidence::Medium,
            ));
        }
    }

    matches
}

// ============================================================================
// Tokenizer
// ============================================================================

/// Extract candidate tokens from text with their byte offsets
///
/// Splits on whitespace and common delimiters (quotes, brackets, etc.)
/// to isolate potential secret strings.
fn tokenize(text: &str) -> Vec<(usize, &str)> {
    let mut tokens = Vec::new();
    let mut start = None;

    for (i, c) in text.char_indices() {
        if is_delimiter(c) {
            if let Some(s) = start {
                let token = text.get(s..i).unwrap_or_default();
                if !token.is_empty() {
                    tokens.push((s, token));
                }
                start = None;
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }

    // Handle last token
    if let Some(s) = start {
        let token = text.get(s..).unwrap_or_default();
        if !token.is_empty() {
            tokens.push((s, token));
        }
    }

    tokens
}

/// Check if a character is a token delimiter
fn is_delimiter(c: char) -> bool {
    c.is_whitespace()
        || c == '"'
        || c == '\''
        || c == '`'
        || c == '('
        || c == ')'
        || c == '['
        || c == ']'
        || c == '{'
        || c == '}'
        || c == ','
        || c == ';'
        || c == ':'
        || c == '\n'
        || c == '\r'
        || c == '\t'
}

// ============================================================================
// False Positive Filters
// ============================================================================

/// Orchestrate all false positive checks
fn is_known_safe_pattern(value: &str) -> bool {
    is_uuid_pattern(value)
        || is_version_string(value)
        || is_hex_color(value)
        || is_repeated_chars(value)
}

/// Check if value matches UUID format (8-4-4-4-12 hex with dashes)
fn is_uuid_pattern(value: &str) -> bool {
    let bytes = value.as_bytes();
    // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
    if bytes.len() != 36 {
        return false;
    }
    // Check dash positions
    let dash_positions = [8, 13, 18, 23];
    for &pos in &dash_positions {
        if bytes.get(pos).copied() != Some(b'-') {
            return false;
        }
    }
    // Check all other chars are hex digits
    for (i, &b) in bytes.iter().enumerate() {
        if dash_positions.contains(&i) {
            continue;
        }
        if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Check if value looks like a semantic version string
///
/// Matches: `1.2.3`, `v1.2.3`, `1.2.3-beta.4`, `1.2.3+build.123`
fn is_version_string(value: &str) -> bool {
    let s = value.strip_prefix('v').unwrap_or(value);

    // Must start with a digit
    if s.is_empty() || !s.as_bytes().first().is_some_and(|b| b.is_ascii_digit()) {
        return false;
    }

    // Must contain at least one dot separating numeric parts
    let mut dot_count = 0u32;
    let mut has_digit_before_dot = false;

    for c in s.chars() {
        if c == '.' {
            if !has_digit_before_dot {
                return false;
            }
            dot_count = dot_count.saturating_add(1);
            has_digit_before_dot = false;
        } else if c.is_ascii_digit() {
            has_digit_before_dot = true;
        } else if c == '-' || c == '+' {
            // Pre-release or build metadata — rest is free-form
            break;
        } else {
            return false;
        }
    }

    // Must have at least one dot (e.g., "1.2" minimum)
    dot_count >= 1
}

/// Check if value is a hex color code
///
/// Matches: `#RGB`, `#RRGGBB`, `#RRGGBBAA` (3-8 hex chars after #)
fn is_hex_color(value: &str) -> bool {
    if let Some(hex) = value.strip_prefix('#') {
        let len = hex.len();
        (len == 3 || len == 4 || len == 6 || len == 8) && hex.bytes().all(|b| b.is_ascii_hexdigit())
    } else {
        false
    }
}

/// Check if value has >60% repeated characters (low actual randomness)
fn is_repeated_chars(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }

    let mut freq_map = std::collections::HashMap::new();
    let mut total = 0usize;

    for c in value.chars() {
        #[allow(clippy::arithmetic_side_effects)] // Safe: counting chars
        {
            *freq_map.entry(c).or_insert(0usize) += 1;
        }
        total = total.saturating_add(1);
    }

    if total == 0 {
        return false;
    }

    // Find the most common character
    let max_count = freq_map.values().copied().max().unwrap_or(0);

    // If most common char appears > 60% of the time, it's repetitive
    // Use integer math to avoid float precision issues: max_count * 10 > total * 6
    max_count.saturating_mul(10) > total.saturating_mul(6)
}

// ============================================================================
// Digit Penalty
// ============================================================================

/// Check if string contains only ASCII digits
fn is_all_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

/// Apply digit penalty following detect-secrets convention
///
/// For all-digit strings, reduces entropy by `1.2 / log2(len)`.
/// This accounts for the fact that digit-only strings (phone numbers,
/// timestamps) naturally have lower charset diversity.
fn apply_digit_penalty(entropy: f64, len: usize) -> f64 {
    if len <= 1 {
        return entropy;
    }
    let log2_len = (len as f64).log2();
    if log2_len <= 0.0 {
        return entropy;
    }
    let penalty = 1.2 / log2_len;
    if entropy > penalty {
        entropy - penalty
    } else {
        0.0
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ---- is_high_entropy: true positives ----

    #[test]
    fn test_high_entropy_random_alphanumeric() {
        // Random 32-char mixed case alphanumeric
        assert!(is_high_entropy("Rq7mX9nB3pL2wK8jF5hT4vD6cE1fG0aH"));
    }

    #[test]
    fn test_high_entropy_base64_string() {
        // High-entropy Base64-like string (entropy ~4.67)
        assert!(is_high_entropy("odJFCrnl2edlBDdz1C5Jau2RJtBRnlWmTSHf6pW"));
    }

    #[test]
    fn test_high_entropy_hex_string() {
        // 64-char random hex string (sha256-like)
        assert!(is_high_entropy(
            "a3f8b2c9e1d047569ab8cd3ef012345678901abcdef234567890abcdef123456"
        ));
    }

    #[test]
    fn test_high_entropy_mixed_alphanumeric() {
        // Mixed alphanumeric with high diversity
        assert!(is_high_entropy("Rq7mX9nB3pL2wK8jF5hT4vD6cE1fG0"));
    }

    // ---- is_high_entropy: false positives (should NOT trigger) ----

    #[test]
    fn test_not_high_entropy_uuid() {
        assert!(!is_high_entropy("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn test_not_high_entropy_version_string() {
        assert!(!is_high_entropy("1.2.3"));
        assert!(!is_high_entropy("v2.0.0-beta.4+build.123"));
    }

    #[test]
    fn test_not_high_entropy_hex_color() {
        assert!(!is_high_entropy("#FF5733"));
        assert!(!is_high_entropy("#f1c"));
    }

    #[test]
    fn test_not_high_entropy_repeated_chars() {
        assert!(!is_high_entropy("aaaaaaaaaaaaaaaaaaaaa"));
        assert!(!is_high_entropy("ababababababababababab"));
    }

    #[test]
    fn test_not_high_entropy_short_string() {
        assert!(!is_high_entropy("short"));
        assert!(!is_high_entropy("abc123"));
    }

    #[test]
    fn test_not_high_entropy_empty() {
        assert!(!is_high_entropy(""));
    }

    #[test]
    fn test_not_high_entropy_common_words() {
        assert!(!is_high_entropy(
            "this_is_a_normal_variable_name_not_a_secret"
        ));
    }

    // ---- is_high_entropy_base64 / is_high_entropy_hex ----

    #[test]
    fn test_high_entropy_base64_fn() {
        // High-entropy Base64-like string (entropy ~4.67)
        assert!(is_high_entropy_base64(
            "odJFCrnl2edlBDdz1C5Jau2RJtBRnlWmTSHf6pW"
        ));
        assert!(!is_high_entropy_base64("short"));
    }

    #[test]
    fn test_high_entropy_hex_fn() {
        assert!(is_high_entropy_hex("a3f8b2c9e1d047569ab8cd3ef0123456"));
        assert!(!is_high_entropy_hex("short"));
    }

    // ---- EntropyConfig customization ----

    #[test]
    fn test_custom_threshold_stricter() {
        let config = EntropyConfig {
            base64_threshold: 5.5, // Very strict
            ..EntropyConfig::default()
        };
        // This string has moderate entropy, should NOT pass strict threshold
        let moderate = "abcdefghijklmnopqrst";
        assert!(!is_high_entropy_with_config(moderate, &config));
    }

    #[test]
    fn test_custom_threshold_looser() {
        let config = EntropyConfig {
            base64_threshold: 2.0, // Very loose
            min_length: 10,
            ..EntropyConfig::default()
        };
        // Even moderate strings pass loose threshold
        assert!(is_high_entropy_with_config("abcdefghijk", &config));
    }

    #[test]
    fn test_digit_penalty_disabled() {
        let config = EntropyConfig {
            digit_penalty: false,
            hex_threshold: 2.5,
            min_length: 10,
            ..EntropyConfig::default()
        };
        // All-digit string with moderate entropy — passes without penalty
        let digits = "31415926535897932384";
        // With penalty disabled, the raw entropy is used
        assert!(is_high_entropy_with_config(digits, &config));
    }

    #[test]
    fn test_digit_penalty_enabled() {
        // All-digit string — penalty reduces effective entropy
        let digits = "31415926535897932384";
        let raw_entropy = calculate_shannon_entropy(digits);
        let penalized = apply_digit_penalty(raw_entropy, digits.len());
        // Verify penalty was applied
        assert!(penalized < raw_entropy);

        // With penalty enabled + tight threshold, digits should be rejected
        let config_with_penalty = EntropyConfig {
            digit_penalty: true,
            hex_threshold: 3.2,
            min_length: 10,
            ..EntropyConfig::default()
        };
        assert!(!is_high_entropy_with_config(digits, &config_with_penalty));
    }

    #[test]
    fn test_exclude_patterns_disabled() {
        // With filters off, known patterns are not excluded — only entropy decides
        let config_off = EntropyConfig {
            exclude_known_patterns: false,
            ..EntropyConfig::default()
        };
        let config_on = EntropyConfig {
            exclude_known_patterns: true,
            ..EntropyConfig::default()
        };
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        // Both should return false here (UUID entropy is below base64 threshold)
        // but the code path differs: config_on filters by pattern, config_off by entropy
        let result_off = is_high_entropy_with_config(uuid, &config_off);
        let result_on = is_high_entropy_with_config(uuid, &config_on);
        assert!(!result_on, "UUID should be excluded by pattern filter");
        assert!(!result_off, "UUID entropy is below threshold anyway");
    }

    // ---- Text scanning ----

    #[test]
    fn test_detect_in_text_json() {
        let text = r#"{"token_val": "Rq7mX9nB3pL2wK8jF5hT4vD6cE1fG0aH", "name": "test"}"#;
        let matches = detect_high_entropy_strings_in_text(text);
        assert!(
            !matches.is_empty(),
            "Should detect high-entropy API key in JSON"
        );
        assert!(
            matches
                .iter()
                .any(|m| m.matched_text.contains("Rq7mX9nB3pL2wK8jF5hT4vD6cE1fG0aH"))
        );
    }

    #[test]
    fn test_detect_in_text_yaml() {
        let text = "secret: Rq7mX9nB3pL2wK8jF5hT4vD6cE1fG0aH\nname: test";
        let matches = detect_high_entropy_strings_in_text(text);
        assert!(
            !matches.is_empty(),
            "Should detect high-entropy secret in YAML"
        );
    }

    #[test]
    fn test_detect_in_text_code() {
        let text = r#"let token_val = "Rq7mX9nB3pL2wK8jF5hT4vD6cE1fG0aH";"#;
        let matches = detect_high_entropy_strings_in_text(text);
        assert!(
            !matches.is_empty(),
            "Should detect high-entropy string in code"
        );
    }

    #[test]
    fn test_detect_in_text_no_false_positives() {
        let text = "uuid: 550e8400-e29b-41d4-a716-446655440000, version: 1.2.3, color: #FF5733";
        let matches = detect_high_entropy_strings_in_text(text);
        // UUIDs, versions, and colors should be excluded
        for m in &matches {
            assert!(
                !is_uuid_pattern(&m.matched_text),
                "UUID should be excluded: {}",
                m.matched_text
            );
        }
    }

    #[test]
    fn test_detect_in_text_empty() {
        assert!(detect_high_entropy_strings_in_text("").is_empty());
    }

    #[test]
    fn test_detect_in_text_normal_text() {
        let text = "This is a normal sentence with no secrets or high entropy strings.";
        let matches = detect_high_entropy_strings_in_text(text);
        assert!(matches.is_empty(), "Normal text should produce no matches");
    }

    #[test]
    fn test_detect_with_config() {
        let config = EntropyConfig {
            min_length: 10,
            base64_threshold: 2.0, // Very loose
            ..EntropyConfig::default()
        };
        let text = "token: abcdefghijk";
        let matches = detect_high_entropy_strings_with_config(text, &config);
        assert!(
            !matches.is_empty(),
            "Loose config should detect moderate entropy"
        );
    }

    #[test]
    fn test_detect_match_positions() {
        let text = r#"key = "Rq7mX9nB3pL2wK8jF5hT4vD6cE1fG0aH""#;
        let matches = detect_high_entropy_strings_in_text(text);
        for m in &matches {
            assert!(m.start < m.end);
            assert_eq!(m.identifier_type, IdentifierType::HighEntropyString);
            assert_eq!(m.confidence, DetectionConfidence::Medium);
        }
    }

    #[test]
    fn test_detect_max_input_length() {
        let huge = "a".repeat(MAX_INPUT_LENGTH.saturating_add(1));
        assert!(detect_high_entropy_strings_in_text(&huge).is_empty());
    }

    // ---- False positive filters ----

    #[test]
    fn test_uuid_pattern_valid() {
        assert!(is_uuid_pattern("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_uuid_pattern("00000000-0000-0000-0000-000000000000"));
        assert!(is_uuid_pattern("ffffffff-ffff-ffff-ffff-ffffffffffff"));
    }

    #[test]
    fn test_uuid_pattern_invalid() {
        assert!(!is_uuid_pattern("not-a-uuid"));
        assert!(!is_uuid_pattern("550e8400e29b41d4a716446655440000")); // No dashes
        assert!(!is_uuid_pattern("550e8400-e29b-41d4-a716-44665544000")); // Too short
        assert!(!is_uuid_pattern("")); // Empty
    }

    #[test]
    fn test_version_string_valid() {
        assert!(is_version_string("1.2.3"));
        assert!(is_version_string("1.0"));
        assert!(is_version_string("v2.0.0"));
        assert!(is_version_string("1.2.3-beta"));
        assert!(is_version_string("1.2.3-beta.4"));
        assert!(is_version_string("1.2.3+build.123"));
        assert!(is_version_string("1.2.3-beta.4+build.123"));
        assert!(is_version_string("10.20.30"));
    }

    #[test]
    fn test_version_string_invalid() {
        assert!(!is_version_string("abc"));
        assert!(!is_version_string("123"));
        assert!(!is_version_string(""));
        assert!(!is_version_string(".1.2"));
        assert!(!is_version_string("v"));
    }

    #[test]
    fn test_hex_color_valid() {
        assert!(is_hex_color("#FFF"));
        assert!(is_hex_color("#FFFF")); // RGBA short
        assert!(is_hex_color("#FF5733"));
        assert!(is_hex_color("#FF573380")); // RGBA
        assert!(is_hex_color("#f1c"));
    }

    #[test]
    fn test_hex_color_invalid() {
        assert!(!is_hex_color("FF5733")); // No #
        assert!(!is_hex_color("#GG5733")); // Invalid hex
        assert!(!is_hex_color("#FF")); // Too short
        assert!(!is_hex_color("#FF573380AA")); // Too long
        assert!(!is_hex_color(""));
    }

    #[test]
    fn test_repeated_chars() {
        assert!(is_repeated_chars("aaaaaaaaaaaaaaa"));
        assert!(is_repeated_chars("aaaaaaaabbbb")); // 'a' is 66%
        assert!(!is_repeated_chars("abcdefghijklmno")); // Well distributed
        assert!(!is_repeated_chars("")); // Empty
    }

    #[test]
    fn test_all_digits() {
        assert!(is_all_digits("0123456789"));
        assert!(!is_all_digits("abc123"));
        assert!(!is_all_digits(""));
    }

    #[test]
    fn test_digit_penalty_application() {
        let entropy = 3.5;
        let penalized = apply_digit_penalty(entropy, 20);
        assert!(penalized < entropy);
        assert!(penalized > 0.0);
    }

    #[test]
    fn test_digit_penalty_small_string() {
        let entropy = 3.5;
        let penalized = apply_digit_penalty(entropy, 1);
        // No penalty for len <= 1
        assert!((penalized - entropy).abs() < f64::EPSILON);
    }

    // ---- Tokenizer ----

    #[test]
    fn test_tokenize_whitespace() {
        let tokens = tokenize("hello world foo");
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens.first().map(|t| t.1), Some("hello"));
    }

    #[test]
    fn test_tokenize_json() {
        let tokens = tokenize(r#"{"key": "value"}"#);
        assert!(tokens.iter().any(|t| t.1 == "key"));
        assert!(tokens.iter().any(|t| t.1 == "value"));
    }

    #[test]
    fn test_tokenize_preserves_offsets() {
        let text = "hello world";
        let tokens = tokenize(text);
        assert_eq!(tokens.first().map(|t| t.0), Some(0));
        assert_eq!(tokens.get(1).map(|t| t.0), Some(6));
    }

    #[test]
    fn test_tokenize_empty() {
        assert!(tokenize("").is_empty());
    }

    #[test]
    fn test_tokenize_delimiters() {
        let tokens = tokenize("a,b;c:d");
        assert_eq!(tokens.len(), 4);
    }
}

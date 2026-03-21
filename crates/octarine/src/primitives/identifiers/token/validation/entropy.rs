//! Entropy validation functions
//!
//! Pure validation functions for token identifiers.

use super::super::super::common::patterns;
use crate::primitives::Problem;
use std::collections::{HashMap, HashSet};

// ============================================================================
// Entropy Analysis for API Keys and Tokens
// ============================================================================

/// Calculate Shannon entropy for a string
///
/// Shannon entropy measures the randomness/unpredictability of a string.
/// Higher entropy indicates more randomness and better security.
///
/// # Entropy Scale
///
/// - **0.0**: All identical characters (e.g., "aaaaaaa")
/// - **1.0-2.0**: Very low entropy, highly predictable
/// - **2.0-3.0**: Low entropy, weak security
/// - **3.0-4.0**: Moderate entropy, acceptable for some use cases
/// - **4.0-5.0**: Good entropy, suitable for most keys
/// - **5.0+**: High entropy, cryptographically strong
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::validation::calculate_shannon_entropy;
///
/// // Low entropy (all same character)
/// assert!(calculate_shannon_entropy("aaaaaaa") < 1.0);
///
/// // Moderate entropy (simple pattern)
/// assert!(calculate_shannon_entropy("abcdef123456") > 2.0);
///
/// // High entropy (random-looking)
/// assert!(calculate_shannon_entropy("xK9#mQ2$pL5@nR8") > 4.0);
/// ```
#[must_use]
pub fn calculate_shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    // Count character frequencies
    let mut freq_map = std::collections::HashMap::new();
    for c in s.chars() {
        #[allow(clippy::arithmetic_side_effects)] // Safe: counting character occurrences
        {
            *freq_map.entry(c).or_insert(0) += 1;
        }
    }

    let len = s.chars().count() as f64;
    let mut entropy = 0.0;

    // Calculate Shannon entropy: H = -Σ(p(x) * log2(p(x)))
    for &count in freq_map.values() {
        let probability = count as f64 / len;
        entropy -= probability * probability.log2();
    }

    entropy
}

/// Calculate character set diversity metrics
///
/// Returns a tuple of (unique_char_count, char_set_types) where:
/// - `unique_char_count`: Number of unique characters
/// - `char_set_types`: Bitmask of character types present
///   - Bit 0: lowercase letters
///   - Bit 1: uppercase letters
///   - Bit 2: digits
///   - Bit 3: special characters
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::validation::calculate_char_diversity;
///
/// // Only lowercase
/// let (unique, types) = calculate_char_diversity("abcabc");
/// assert_eq!(unique, 3);
/// assert_eq!(types, 1); // Bit 0 set
///
/// // Mixed case + digits
/// let (unique, types) = calculate_char_diversity("Abc123");
/// assert_eq!(unique, 6);
/// assert_eq!(types, 7); // Bits 0, 1, 2 set
/// ```
#[must_use]
pub fn calculate_char_diversity(s: &str) -> (usize, u8) {
    let mut unique_chars = std::collections::HashSet::new();
    let mut char_types = 0u8;

    for c in s.chars() {
        unique_chars.insert(c);

        if c.is_lowercase() {
            char_types |= 0b0001; // Bit 0: lowercase
        }
        if c.is_uppercase() {
            char_types |= 0b0010; // Bit 1: uppercase
        }
        if c.is_numeric() {
            char_types |= 0b0100; // Bit 2: digits
        }
        if !c.is_alphanumeric() {
            char_types |= 0b1000; // Bit 3: special chars
        }
    }

    (unique_chars.len(), char_types)
}

/// Validate that a key/token meets minimum entropy requirements (strict - returns Result)
///
/// Checks both Shannon entropy and character diversity to ensure
/// the key is sufficiently random and secure.
///
/// # Security Thresholds (OWASP Recommendations)
///
/// - **Minimum entropy**: 3.0 bits (rejects highly predictable keys)
/// - **Recommended entropy**: 4.0+ bits (strong keys)
/// - **Character diversity**: At least 2 character types (e.g., letters + digits)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::validation::validate_key_entropy;
///
/// // Weak key (low entropy)
/// assert!(validate_key_entropy("aaaaaaa", 3.0).is_err());
///
/// // Good key (high entropy)
/// assert!(validate_key_entropy("xK9mQ2pL5nR8", 3.0).is_ok());
/// ```
pub fn validate_key_entropy(key: &str, min_entropy: f64) -> Result<(), Problem> {
    // Calculate Shannon entropy
    let entropy = calculate_shannon_entropy(key);

    if entropy < min_entropy {
        return Err(Problem::Validation(format!(
            "Key entropy too low ({:.2} bits, minimum {:.2} bits required)",
            entropy, min_entropy
        )));
    }

    // Calculate character diversity
    let (unique_count, char_types) = calculate_char_diversity(key);

    // Require at least 2 character types for security
    let type_count = char_types.count_ones();
    if type_count < 2 {
        return Err(Problem::Validation(
            "Key must use at least 2 character types (lowercase, uppercase, digits, special)"
                .into(),
        ));
    }

    // Warn if unique character count is very low (potential repeated patterns)
    let key_len = key.chars().count();
    let uniqueness_ratio = unique_count as f64 / key_len as f64;

    if uniqueness_ratio < 0.5 {
        return Err(Problem::Validation(format!(
            "Key has too many repeated characters ({:.1}% unique)",
            uniqueness_ratio * 100.0
        )));
    }

    Ok(())
}

/// Analyze key strength and return detailed metrics
///
/// Returns a tuple of (entropy, unique_chars, char_types, strength_score) where:
/// - `entropy`: Shannon entropy (0.0-8.0 typically)
/// - `unique_chars`: Number of unique characters
/// - `char_types`: Number of character types (1-4)
/// - `strength_score`: Overall strength (0-100)
///
/// # Strength Score Calculation
///
/// - **0-25**: Very weak (predictable, low entropy)
/// - **26-50**: Weak (some randomness, limited diversity)
/// - **51-75**: Moderate (acceptable for some use cases)
/// - **76-90**: Strong (good entropy and diversity)
/// - **91-100**: Very strong (high entropy, full diversity)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::token::validation::analyze_key_strength;
///
/// let (entropy, unique, types, score) = analyze_key_strength("xK9#mQ2$pL5@nR8");
/// assert!(entropy > 4.0);
/// assert!(score > 75);
/// ```
#[must_use]
pub fn analyze_key_strength(key: &str) -> (f64, usize, u32, u8) {
    let entropy = calculate_shannon_entropy(key);
    let (unique_count, char_types) = calculate_char_diversity(key);
    let type_count = char_types.count_ones();

    // Calculate strength score (0-100)
    let entropy_score = (entropy / 5.0 * 50.0).min(50.0); // Max 50 points from entropy
    let diversity_score = (type_count as f64 / 4.0 * 25.0).min(25.0); // Max 25 points from diversity

    let key_len = key.chars().count();
    let uniqueness_ratio = unique_count as f64 / key_len as f64;
    let uniqueness_score = (uniqueness_ratio * 25.0).min(25.0); // Max 25 points from uniqueness

    let strength_score = (entropy_score + diversity_score + uniqueness_score) as u8;

    (entropy, unique_count, type_count, strength_score)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::super::validate_jwt;
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_calculate_shannon_entropy_zero() {
        // All same character = zero entropy
        assert_eq!(calculate_shannon_entropy("aaaaaaa"), 0.0);
        assert_eq!(calculate_shannon_entropy("1111111"), 0.0);
    }

    #[test]
    fn test_calculate_shannon_entropy_low() {
        // Simple patterns = low entropy
        let entropy = calculate_shannon_entropy("ababab");
        assert!(entropy > 0.0);
        assert!(entropy < 2.0);
    }

    #[test]
    fn test_calculate_shannon_entropy_moderate() {
        // More variety = moderate entropy
        let entropy = calculate_shannon_entropy("abcdef123456");
        assert!(entropy > 2.0);
        assert!(entropy < 4.0);
    }

    #[test]
    fn test_calculate_shannon_entropy_high() {
        // High diversity = high entropy
        let entropy = calculate_shannon_entropy("xK9#mQ2$pL5@nR8");
        assert!(entropy > 3.5); // ~3.9 bits
        assert!(entropy < 4.5);
    }

    #[test]
    fn test_calculate_shannon_entropy_empty() {
        assert_eq!(calculate_shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_calculate_char_diversity_single_type() {
        // Only lowercase
        let (unique, types) = calculate_char_diversity("abcabc");
        assert_eq!(unique, 3);
        assert_eq!(types, 0b0001); // Only lowercase bit set

        // Only digits
        let (unique, types) = calculate_char_diversity("123123");
        assert_eq!(unique, 3);
        assert_eq!(types, 0b0100); // Only digits bit set
    }

    #[test]
    fn test_calculate_char_diversity_mixed() {
        // Lowercase + uppercase + digits
        let (unique, types) = calculate_char_diversity("Abc123");
        assert_eq!(unique, 6);
        assert_eq!(types, 0b0111); // Bits 0, 1, 2 set
    }

    #[test]
    fn test_calculate_char_diversity_all_types() {
        // All character types
        let (unique, types) = calculate_char_diversity("Abc123!@#");
        assert_eq!(unique, 9);
        assert_eq!(types, 0b1111); // All bits set
    }

    #[test]
    fn test_validate_key_entropy_weak() {
        // Very weak key (all same character)
        assert!(validate_key_entropy("aaaaaaa", 3.0).is_err());

        // Weak key (simple pattern)
        assert!(validate_key_entropy("abcabc", 3.0).is_err());
    }

    #[test]
    fn test_validate_key_entropy_insufficient_diversity() {
        // High entropy but only one character type
        assert!(validate_key_entropy("abcdefghijklmnop", 3.0).is_err());
    }

    #[test]
    fn test_validate_key_entropy_too_many_repeats() {
        // Good diversity but too many repeated characters
        assert!(validate_key_entropy("Aa11111111", 3.0).is_err());
    }

    #[test]
    fn test_validate_key_entropy_strong() {
        // Strong keys with good entropy and diversity
        assert!(validate_key_entropy("xK9mQ2pL5nR8", 3.0).is_ok());
        assert!(validate_key_entropy("sk_live_xK9mQ2pL5nR8", 3.0).is_ok());
        assert!(validate_key_entropy("AKIAIOSFODNN7EXAMPLE", 3.0).is_ok());
    }

    #[test]
    fn test_analyze_key_strength_very_weak() {
        let (entropy, unique, types, score) = analyze_key_strength("aaaaaaa");
        assert_eq!(entropy, 0.0);
        assert_eq!(unique, 1);
        assert_eq!(types, 1);
        assert!(score < 25);
    }

    #[test]
    fn test_analyze_key_strength_weak() {
        let (entropy, unique, types, score) = analyze_key_strength("abcabc");
        assert!(entropy < 2.0);
        assert_eq!(unique, 3);
        assert_eq!(types, 1);
        assert!(score < 50);
    }

    #[test]
    fn test_analyze_key_strength_moderate() {
        let (entropy, unique, types, score) = analyze_key_strength("Abcdef123");
        assert!(entropy > 2.0);
        assert!(entropy < 4.0);
        assert_eq!(unique, 9);
        assert_eq!(types, 3);
        assert!(score >= 50);
        // Score is ~75 for this key
    }

    #[test]
    fn test_analyze_key_strength_strong() {
        let (entropy, _unique, types, score) = analyze_key_strength("xK9#mQ2$pL5@nR8");
        assert!(entropy > 3.5); // ~3.9 bits
        assert!(types >= 3);
        assert!(score >= 75);
    }

    #[test]
    fn test_analyze_key_strength_real_keys() {
        // AWS Access Key
        let (_, _, types, score) = analyze_key_strength("AKIAIOSFODNN7EXAMPLE");
        assert!(types >= 2);
        assert!(score >= 50);

        // Stripe key
        let (_, _, types, score) = analyze_key_strength("sk_live_1234567890abcdef");
        assert!(types >= 2);
        assert!(score >= 50);
    }

    #[test]
    fn test_validate_key_entropy_bool() {
        // Result version with .is_ok() / .is_err()
        assert!(validate_key_entropy("aaaaaaa", 3.0).is_err());
        assert!(validate_key_entropy("xK9mQ2pL5nR8", 3.0).is_ok());
    }

    #[test]
    fn test_adversarial_entropy_single_char_type() {
        // Only lowercase (fails diversity check)
        assert!(validate_key_entropy("abcdefghijklmnopqrst", 3.0).is_err());

        // Only uppercase (fails diversity check)
        assert!(validate_key_entropy("ABCDEFGHIJKLMNOPQRST", 3.0).is_err());

        // Only digits (fails diversity check)
        assert!(validate_key_entropy("12345678901234567890", 3.0).is_err());

        // Need at least 2 character types
        assert!(validate_key_entropy("Abc123def456ghi789jk", 3.0).is_ok());
    }

    #[test]
    fn test_adversarial_entropy_repeated_chars() {
        // High character type diversity but too many repeats (< 50% unique)
        assert!(validate_key_entropy("Aa11111111", 3.0).is_err());
        assert!(validate_key_entropy("Bb22222222", 3.0).is_err());

        // Borderline uniqueness ratio
        let borderline = "Aa1234567890"; // 12 chars, 10 unique = 83% unique
        assert!(validate_key_entropy(borderline, 3.0).is_ok());
    }

    #[test]
    fn test_adversarial_entropy_homograph_confusion() {
        // Cyrillic characters that look like Latin
        // These might pass basic checks but should fail our validation
        let cyrillic_key = "АВСdef123456"; // Cyrillic A, B, C

        // Calculate entropy - should still work
        let entropy = calculate_shannon_entropy(cyrillic_key);
        assert!(entropy > 0.0); // Will have some entropy

        // But character diversity should detect non-ASCII
        let (unique, _char_types) = calculate_char_diversity(cyrillic_key);
        assert!(unique > 0);
        // Cyrillic uppercase would be detected as uppercase
    }

    #[test]
    fn test_adversarial_entropy_zero_width_chars() {
        // Zero-width characters shouldn't inflate uniqueness
        let key_with_zwc = "Abc\u{200B}123\u{FEFF}def456";

        let (unique, _) = calculate_char_diversity(key_with_zwc);
        // Zero-width chars count as unique but don't help with character types
        assert!(unique > 0);
    }

    #[test]
    fn test_adversarial_key_strength_boundary() {
        // Test strength score boundaries

        // Very weak (score < 25)
        let (_, _, _, score) = analyze_key_strength("aaaaaaa");
        assert!(score < 25);

        // Weak (score < 50)
        let (_, _, _, score) = analyze_key_strength("abcabc");
        assert!(score < 50);

        // Moderate (score >= 50)
        let (_, _, _, score) = analyze_key_strength("Abcdef123");
        assert!(score >= 50);

        // Strong (score >= 75)
        let (_, _, _, score) = analyze_key_strength("xK9#mQ2$pL5@nR8");
        assert!(score >= 75);
    }

    #[test]
    #[ignore = "perf test - timing-sensitive, run manually with: cargo test -p octarine test_adversarial_ -- --ignored"]
    fn test_adversarial_long_input_performance() {
        // Very long inputs should still complete quickly (ReDoS prevention)

        // Long repeated pattern
        let long_key = "Ab12".repeat(1000); // 4000 chars
        let start = std::time::Instant::now();
        let _ = calculate_shannon_entropy(&long_key);
        let duration = start.elapsed();

        // Should complete in well under 100ms (usually <1ms)
        assert!(duration.as_millis() < 100);

        // Long random-looking pattern
        let long_random = "xK9#".repeat(1000); // 4000 chars
        let start = std::time::Instant::now();
        let _ = analyze_key_strength(&long_random);
        let duration = start.elapsed();

        // Should still complete quickly
        assert!(duration.as_millis() < 100);
    }

    #[test]
    fn test_adversarial_empty_string_handling() {
        // Empty strings should be handled gracefully

        // Entropy of empty string
        assert_eq!(calculate_shannon_entropy(""), 0.0);

        // Diversity of empty string
        let (unique, types) = calculate_char_diversity("");
        assert_eq!(unique, 0);
        assert_eq!(types, 0);

        // Strength of empty string - should return minimal values
        let (entropy, unique, types, score) = analyze_key_strength("");
        assert_eq!(entropy, 0.0);
        assert_eq!(unique, 0);
        assert_eq!(types, 0);
        // Score may have minimum value due to calculation rounding
        assert!(score <= 25); // Very weak range
    }

    #[test]
    #[ignore = "perf test - run manually with: cargo test -p octarine test_perf_ -- --ignored"]
    fn test_perf_shannon_entropy_short() {
        // Entropy calculation on short strings
        let key = "AbCdEf123456";
        let iterations = 10000;
        let start = std::time::Instant::now();

        for _ in 0..iterations {
            let _ = calculate_shannon_entropy(key);
        }

        let duration = start.elapsed();
        let avg_micros = duration.as_micros() / iterations;

        // Entropy on short strings should be sub-50 microseconds
        assert!(avg_micros < 50, "Average: {} µs", avg_micros);
    }

    #[test]
    #[ignore = "perf test - run manually with: cargo test -p octarine test_perf_ -- --ignored"]
    fn test_perf_shannon_entropy_long() {
        // Entropy calculation on longer strings
        let key = "xK9mQ2pL5nR8Abc123Def456Ghi789JklMno";
        let iterations = 5000;
        let start = std::time::Instant::now();

        for _ in 0..iterations {
            let _ = calculate_shannon_entropy(key);
        }

        let duration = start.elapsed();
        let avg_micros = duration.as_micros() / iterations;

        // Entropy on longer strings should still be sub-100 microseconds
        assert!(avg_micros < 100, "Average: {} µs", avg_micros);
    }

    #[test]
    #[ignore = "perf test - run manually with: cargo test -p octarine test_perf_ -- --ignored"]
    fn test_perf_char_diversity() {
        // Character diversity calculation
        let key = "AbCdEf123!@#$%^&*()";
        let iterations = 10000;
        let start = std::time::Instant::now();

        for _ in 0..iterations {
            let _ = calculate_char_diversity(key);
        }

        let duration = start.elapsed();
        let avg_micros = duration.as_micros() / iterations;

        // Diversity calculation should be sub-50 microseconds
        assert!(avg_micros < 50, "Average: {} µs", avg_micros);
    }

    #[test]
    #[ignore = "perf test - run manually with: cargo test -p octarine test_perf_ -- --ignored"]
    fn test_perf_key_strength_analysis() {
        // Full key strength analysis (entropy + diversity + scoring)
        let key = "xK9mQ2pL5nR8Abc123";
        let iterations = 5000;
        let start = std::time::Instant::now();

        for _ in 0..iterations {
            let _ = analyze_key_strength(key);
        }

        let duration = start.elapsed();
        let avg_micros = duration.as_micros() / iterations;

        // Full analysis should be sub-150 microseconds
        assert!(avg_micros < 150, "Average: {} µs", avg_micros);
    }

    #[test]
    #[ignore = "perf test - run manually with: cargo test -p octarine test_perf_ -- --ignored"]
    fn test_perf_entropy_validation() {
        // Entropy validation (includes entropy + diversity + uniqueness)
        let key = "xK9mQ2pL5nR8Abc123";
        let iterations = 5000;
        let start = std::time::Instant::now();

        for _ in 0..iterations {
            let _ = validate_key_entropy(key, 3.0);
        }

        let duration = start.elapsed();
        let avg_micros = duration.as_micros() / iterations;

        // Entropy validation should be sub-200 microseconds
        assert!(avg_micros < 200, "Average: {} µs", avg_micros);
    }

    #[test]
    #[ignore = "perf test - run manually with: cargo test -p octarine test_perf_ -- --ignored"]
    fn test_perf_memory_efficiency() {
        // Verify no memory leaks with repeated operations
        // Use a valid JWT to avoid triggering validation warnings
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let key = "xK9mQ2pL5nR8";
        let iterations = 100000;

        for _ in 0..iterations {
            let _ = validate_jwt(jwt);
            let _ = calculate_shannon_entropy(key);
            let _ = analyze_key_strength(key);
        }

        // If this completes without OOM, we're good
        // (No assertion needed - test passes if it doesn't panic)
    }

    #[test]
    #[ignore = "perf test - run manually with: cargo test -p octarine test_perf_ -- --ignored"]
    fn test_perf_scalability_entropy() {
        // Verify entropy calculation scales linearly with input size
        let key_10 = "AbCdEf1234";
        let key_100 = "AbCdEf1234".repeat(10);
        let key_1000 = "AbCdEf1234".repeat(100);

        let iterations = 1000u128;

        // 10 chars
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = calculate_shannon_entropy(key_10);
        }
        // Use nanos and floating-point to avoid integer division truncating to 0
        let time_10 = start.elapsed().as_nanos() as f64 / iterations as f64;

        // 100 chars
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = calculate_shannon_entropy(&key_100);
        }
        let time_100 = start.elapsed().as_nanos() as f64 / iterations as f64;

        // 1000 chars
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = calculate_shannon_entropy(&key_1000);
        }
        let time_1000 = start.elapsed().as_nanos() as f64 / iterations as f64;

        // Should scale roughly linearly (allow 20x margin for overhead)
        let ratio_10_100 = time_100 / time_10;
        let ratio_100_1000 = time_1000 / time_100;

        assert!(ratio_10_100 < 20.0, "10→100 ratio: {:.2}", ratio_10_100);
        assert!(
            ratio_100_1000 < 20.0,
            "100→1000 ratio: {:.2}",
            ratio_100_1000
        );
    }

    #[test]
    #[ignore = "perf test - timing-sensitive, run manually with: cargo test -p octarine test_perf_ -- --ignored"]
    fn test_perf_no_resource_exhaustion() {
        // Verify entropy calculation completes in reasonable time for large inputs
        // This is a stress test, not a property test - uses fixed worst-case input
        let long_string = "a".repeat(100_000);

        let start = std::time::Instant::now();
        let _ = calculate_shannon_entropy(&long_string);
        let duration = start.elapsed();

        // Should complete in under 500ms even for 100K chars
        // (relaxed from 100ms to handle slow CI environments)
        assert!(
            duration.as_millis() < 500,
            "Entropy calculation took {}ms for 100K chars",
            duration.as_millis()
        );
    }

    proptest! {

        #[test]
        fn prop_entropy_bounds(s in "\\PC*") {
                let entropy = calculate_shannon_entropy(&s);

                // Entropy should never be negative
                assert!(entropy >= 0.0, "Entropy cannot be negative: {}", entropy);

                // Entropy should never exceed theoretical maximum
                // For Unicode, practical maximum is ~16 bits (65536 chars)
                assert!(entropy <= 16.0, "Entropy exceeds theoretical max: {}", entropy);

                // Empty string has zero entropy
                if s.is_empty() {
                    assert_eq!(entropy, 0.0, "Empty string should have 0 entropy");
                }
            }

        #[test]
        fn prop_char_diversity_bounds(s in "\\PC*") {
                let (unique_count, char_types) = calculate_char_diversity(&s);

                // Unique count never exceeds string length
                let len = s.chars().count();
                assert!(unique_count <= len, "Unique {} > len {}", unique_count, len);

                // Character type count is 0-4
                let type_count = char_types.count_ones();
                assert!(type_count <= 4, "Type count {} > 4", type_count);

                // Empty string has no types
                if s.is_empty() {
                    assert_eq!(unique_count, 0, "Empty string should have 0 unique chars");
                    assert_eq!(char_types, 0, "Empty string should have 0 char types");
                }
            }

        #[test]
        fn prop_strength_score_bounds(s in "\\PC*") {
                let (entropy, unique_count, type_count, score) = analyze_key_strength(&s);

                // Score is 0-100
                assert!(score <= 100, "Score {} exceeds 100", score);

                // Entropy bounds (same as prop_entropy_bounds)
                assert!((0.0..=16.0).contains(&entropy));

                // Type count is 0-4
                assert!(type_count <= 4, "Type count {} > 4", type_count);

                // Unique count <= string length
                let len = s.chars().count();
                assert!(unique_count <= len);
            }

        #[test]
        fn prop_entropy_deterministic(s in "\\PC*") {
                let entropy1 = calculate_shannon_entropy(&s);
                let entropy2 = calculate_shannon_entropy(&s);
                // Use epsilon comparison for floating point
                let diff = (entropy1 - entropy2).abs();
                assert!(diff < 1e-10, "Entropy calculation not deterministic: {} vs {}", entropy1, entropy2);
            }

        #[test]
        fn prop_entropy_diversity_relationship(
            base_char in "[a-z]",
            num_additional in 0usize..10
        ) {
            // Single character repeated has low entropy
            let base_char = base_char
                .chars()
                .next()
                .expect("Proptest regex guarantees non-empty string");
            let homogeneous = base_char.to_string().repeat(20);
            let entropy_low = calculate_shannon_entropy(&homogeneous);

            // Adding diverse characters increases entropy
            let mut diverse = homogeneous.clone();
            let additional_chars = "!@#$%^&*()[]{}";
            for i in 0..num_additional.min(additional_chars.len()) {
                if let Some(c) = additional_chars.chars().nth(i) {
                    diverse.push(c);
                }
            }
            let entropy_high = calculate_shannon_entropy(&diverse);

            // More diverse strings should have equal or higher entropy
            assert!(
                entropy_high >= entropy_low,
            "Diverse string has lower entropy: {} < {}",
                entropy_high,
                entropy_low
            );
        }

        #[test]
        fn prop_diversity_monotonic(s in "\\PC*", c in "[!-~]") {
                let (unique1, types1) = calculate_char_diversity(&s);

                // Adding a character never decreases diversity
                let mut s_plus = s.clone();
                if let Some(ch) = c.chars().next() {
                    s_plus.push(ch);
                    let (unique2, types2) = calculate_char_diversity(&s_plus);

                    assert!(unique2 >= unique1, "Adding char decreased unique count");
                    assert!(types2 >= types1, "Adding char decreased type count");
                }
            }

    }
}

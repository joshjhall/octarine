//! Core entropy calculation functions
//!
//! Shannon entropy and character diversity metrics used across
//! multiple identifier detection domains.

// ============================================================================
// Entropy Analysis
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
/// use octarine::primitives::identifiers::entropy::calculate_shannon_entropy;
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
/// use octarine::primitives::identifiers::entropy::calculate_char_diversity;
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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_shannon_entropy_empty() {
        assert!((calculate_shannon_entropy("") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_shannon_entropy_single_char() {
        assert!(calculate_shannon_entropy("aaaaaaa") < 0.01);
    }

    #[test]
    fn test_shannon_entropy_mixed() {
        let entropy = calculate_shannon_entropy("abcdef123456");
        assert!(entropy > 2.0);
    }

    #[test]
    fn test_char_diversity_lowercase_only() {
        let (unique, types) = calculate_char_diversity("abcabc");
        assert_eq!(unique, 3);
        assert_eq!(types, 0b0001);
    }

    #[test]
    fn test_char_diversity_mixed() {
        let (unique, types) = calculate_char_diversity("Abc123");
        assert_eq!(unique, 6);
        assert_eq!(types, 0b0111); // lower + upper + digits
    }

    #[test]
    fn test_char_diversity_all_types() {
        let (_, types) = calculate_char_diversity("aA1!");
        assert_eq!(types, 0b1111);
    }
}

//! Configuration types for entropy-based detection
//!
//! Provides configurable thresholds and filter settings for
//! high-entropy string detection.

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for entropy-based secret detection
///
/// Controls thresholds, minimum lengths, and false positive mitigation.
/// Different charsets have different theoretical maximum entropy, so
/// separate thresholds are provided for Base64 and Hex strings.
///
/// # Defaults
///
/// | Field | Default | Rationale |
/// |-------|---------|-----------|
/// | `base64_threshold` | 4.5 | ~75% of max 6.0 bits/char |
/// | `hex_threshold` | 3.0 | ~75% of max 4.0 bits/char |
/// | `min_length` | 20 | Short strings have inflated entropy ratios |
/// | `digit_penalty` | true | Reduces false positives on phone numbers, timestamps |
/// | `exclude_known_patterns` | true | Filters UUIDs, version strings, hex colors |
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::entropy::EntropyConfig;
///
/// // Use defaults
/// let config = EntropyConfig::default();
///
/// // Custom thresholds for stricter detection
/// let strict = EntropyConfig {
///     base64_threshold: 5.0,
///     hex_threshold: 3.5,
///     ..EntropyConfig::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct EntropyConfig {
    /// Minimum Shannon entropy for Base64-charset strings (default: 4.5)
    ///
    /// Base64 has a theoretical max of ~6.0 bits/char. The default 4.5
    /// catches most generated secrets while avoiding common false positives.
    pub base64_threshold: f64,

    /// Minimum Shannon entropy for Hex-charset strings (default: 3.0)
    ///
    /// Hex has a theoretical max of ~4.0 bits/char. The default 3.0
    /// catches most hex-encoded secrets.
    pub hex_threshold: f64,

    /// Minimum string length to consider for entropy analysis (default: 20)
    ///
    /// Strings shorter than this are skipped. Short strings can have
    /// artificially high entropy ratios that produce false positives.
    pub min_length: usize,

    /// Apply digit penalty for all-digit hex strings (default: true)
    ///
    /// When enabled, reduces effective entropy for strings that are entirely
    /// digits (0-9) by `1.2 / log2(len)`. This prevents phone numbers,
    /// timestamps, and numeric sequences from triggering detection.
    /// Follows the detect-secrets convention.
    pub digit_penalty: bool,

    /// Exclude known safe patterns from detection (default: true)
    ///
    /// When enabled, filters out UUIDs, semantic version strings,
    /// hex color codes, and repeated character sequences.
    pub exclude_known_patterns: bool,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            base64_threshold: 4.5,
            hex_threshold: 3.0,
            min_length: 20,
            digit_penalty: true,
            exclude_known_patterns: true,
        }
    }
}

impl EntropyConfig {
    /// Create a new config with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the entropy threshold for a given charset class
    ///
    /// Returns the appropriate threshold based on the charset:
    /// - Hex → `hex_threshold`
    /// - Base64 → `base64_threshold`
    /// - Alphanumeric → `base64_threshold` (similar max entropy)
    /// - Unknown → `base64_threshold` (conservative)
    #[must_use]
    pub fn threshold_for(&self, charset: &super::charsets::CharsetClass) -> f64 {
        match charset {
            super::charsets::CharsetClass::Hex => self.hex_threshold,
            super::charsets::CharsetClass::Base64
            | super::charsets::CharsetClass::Alphanumeric
            | super::charsets::CharsetClass::Unknown => self.base64_threshold,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::primitives::identifiers::entropy::charsets::CharsetClass;

    #[test]
    fn test_default_config() {
        let config = EntropyConfig::default();
        assert!((config.base64_threshold - 4.5).abs() < f64::EPSILON);
        assert!((config.hex_threshold - 3.0).abs() < f64::EPSILON);
        assert_eq!(config.min_length, 20);
        assert!(config.digit_penalty);
        assert!(config.exclude_known_patterns);
    }

    #[test]
    fn test_new_config() {
        let config = EntropyConfig::new();
        assert!((config.base64_threshold - 4.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_threshold_for_hex() {
        let config = EntropyConfig::default();
        assert!((config.threshold_for(&CharsetClass::Hex) - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_threshold_for_base64() {
        let config = EntropyConfig::default();
        assert!((config.threshold_for(&CharsetClass::Base64) - 4.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_threshold_for_alphanumeric() {
        let config = EntropyConfig::default();
        assert!((config.threshold_for(&CharsetClass::Alphanumeric) - 4.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_threshold_for_unknown() {
        let config = EntropyConfig::default();
        assert!((config.threshold_for(&CharsetClass::Unknown) - 4.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_custom_config() {
        let config = EntropyConfig {
            base64_threshold: 5.0,
            hex_threshold: 3.5,
            min_length: 16,
            digit_penalty: false,
            exclude_known_patterns: false,
        };
        assert!((config.base64_threshold - 5.0).abs() < f64::EPSILON);
        assert!((config.hex_threshold - 3.5).abs() < f64::EPSILON);
        assert_eq!(config.min_length, 16);
        assert!(!config.digit_penalty);
        assert!(!config.exclude_known_patterns);
    }
}

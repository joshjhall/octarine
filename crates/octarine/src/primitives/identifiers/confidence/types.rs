//! Configuration types for context-aware confidence scoring
//!
//! Provides configurable parameters for context window analysis
//! and confidence boosting based on surrounding keyword presence.

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for context-aware confidence scoring
///
/// Controls the text window size around identifier matches and the
/// confidence boost applied when contextual keywords are found nearby.
///
/// # Defaults
///
/// | Field | Default | Rationale |
/// |-------|---------|-----------|
/// | `window_size` | 100 | Presidio default; captures nearby labels |
/// | `boost_factor` | 0.35 | Presidio default; meaningful boost without overconfidence |
/// | `max_confidence` | 0.95 | Prevents false certainty even with strong context |
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::confidence::ContextConfig;
///
/// // Use defaults
/// let config = ContextConfig::default();
///
/// // Custom window for dense text
/// let narrow = ContextConfig {
///     window_size: 50,
///     ..ContextConfig::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ContextConfig {
    /// Characters before/after match to search for keywords (default: 100)
    ///
    /// Larger windows catch more context but may introduce noise from
    /// unrelated text. The Presidio default of 100 works well for most
    /// document formats.
    pub window_size: usize,

    /// Confidence boost multiplier when context keywords are found (default: 0.35)
    ///
    /// Applied additively to the base confidence score. A single boost
    /// is applied regardless of how many keywords match (no double-boosting).
    pub boost_factor: f64,

    /// Maximum confidence score after boosting (default: 0.95)
    ///
    /// Caps the result to prevent false certainty. Even with strong
    /// contextual signals, a small uncertainty margin is preserved.
    pub max_confidence: f64,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            window_size: 100,
            boost_factor: 0.35,
            max_confidence: 0.95,
        }
    }
}

impl ContextConfig {
    /// Create a new config with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ContextConfig::default();
        assert_eq!(config.window_size, 100);
        assert!((config.boost_factor - 0.35).abs() < f64::EPSILON);
        assert!((config.max_confidence - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn test_new_config() {
        let config = ContextConfig::new();
        assert_eq!(config.window_size, 100);
        assert!((config.boost_factor - 0.35).abs() < f64::EPSILON);
    }

    #[test]
    fn test_custom_config() {
        let config = ContextConfig {
            window_size: 50,
            boost_factor: 0.5,
            max_confidence: 0.9,
        };
        assert_eq!(config.window_size, 50);
        assert!((config.boost_factor - 0.5).abs() < f64::EPSILON);
        assert!((config.max_confidence - 0.9).abs() < f64::EPSILON);
    }
}

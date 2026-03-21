// Allow dead code - this module provides public API types that may not
// all be consumed yet internally.
#![allow(dead_code)]

//! Public types for text operations
//!
//! These types form the public API for text sanitization configuration.
//! They wrap the internal primitives types for the stable public API.
//!
//! # Why Wrapper Types?
//!
//! Wrapper types are necessary for two reasons:
//! 1. **Visibility bridging**: Primitives are `pub(crate)`, so we can't directly
//!    re-export them as `pub`. Wrapper types provide the public API surface.
//! 2. **API stability**: Wrappers allow the public API to evolve independently
//!    from internal primitives.
//!
//! # Naming Convention
//!
//! Types are namespaced under their submodule:
//! - `octarine::data::text::TextConfig` (public)
//! - `crate::primitives::data::text::TextConfig` (internal)

// ============================================================================
// Text Configuration
// ============================================================================

/// Configuration for text sanitization operations
///
/// Controls how text is sanitized for safe output in logs, JSON, and other contexts.
///
/// # Presets
///
/// - [`TextConfig::default()`] - Standard safety: escape newlines, remove ANSI/control chars
/// - [`TextConfig::strict()`] - Maximum safety: ASCII only, length limited, escape everything
/// - [`TextConfig::relaxed()`] - Readable: allow newlines, keep unicode, replace dangerous chars
/// - [`TextConfig::json_safe()`] - JSON embedding: escape for JSON string syntax
///
/// # Examples
///
/// ```ignore
/// use octarine::data::text::TextConfig;
///
/// // Default configuration
/// let config = TextConfig::default();
///
/// // Strict for high-security environments
/// let config = TextConfig::strict();
///
/// // Builder pattern for customization
/// let config = TextConfig::default()
///     .with_max_length(1000)
///     .with_replacement_char(true);
/// ```
#[derive(Debug, Clone)]
pub struct TextConfig {
    /// Escape newlines as literal `\n` (default: true)
    pub escape_newlines: bool,

    /// Escape carriage returns as literal `\r` (default: true)
    pub escape_carriage_returns: bool,

    /// Escape tabs as literal `\t` (default: false)
    pub escape_tabs: bool,

    /// Remove ANSI escape sequences (default: true)
    pub remove_ansi_escapes: bool,

    /// Remove other control characters (default: true)
    pub remove_control_chars: bool,

    /// Replace control chars with unicode replacement char instead of removing
    pub use_replacement_char: bool,

    /// Maximum output length, 0 = no limit (default: 0)
    pub max_length: usize,

    /// Truncation suffix when max_length exceeded (default: "...")
    pub truncation_suffix: &'static str,

    /// Allow unicode characters (default: true)
    pub allow_unicode: bool,

    /// Escape unicode for ASCII-only output (default: false)
    pub escape_unicode: bool,
}

impl Default for TextConfig {
    fn default() -> Self {
        Self {
            escape_newlines: true,
            escape_carriage_returns: true,
            escape_tabs: false,
            remove_ansi_escapes: true,
            remove_control_chars: true,
            use_replacement_char: false,
            max_length: 0,
            truncation_suffix: "...",
            allow_unicode: true,
            escape_unicode: false,
        }
    }
}

impl TextConfig {
    /// Strict configuration - escape everything, ASCII only, length limited
    ///
    /// Use for high-security environments where all output must be
    /// predictable and safe for any downstream consumer.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            escape_newlines: true,
            escape_carriage_returns: true,
            escape_tabs: true,
            remove_ansi_escapes: true,
            remove_control_chars: true,
            use_replacement_char: false,
            max_length: 10000,
            truncation_suffix: "...[truncated]",
            allow_unicode: false,
            escape_unicode: true,
        }
    }

    /// Relaxed configuration - allow newlines, keep unicode
    ///
    /// Use for development/debugging where readability is more important
    /// than strict safety. Still removes dangerous control characters.
    #[must_use]
    pub fn relaxed() -> Self {
        Self {
            escape_newlines: false,
            escape_carriage_returns: true,
            escape_tabs: false,
            remove_ansi_escapes: true,
            remove_control_chars: true,
            use_replacement_char: true,
            max_length: 0,
            truncation_suffix: "...",
            allow_unicode: true,
            escape_unicode: false,
        }
    }

    /// JSON-safe configuration - escape for JSON string embedding
    ///
    /// Use when log output will be embedded in JSON. Escapes all
    /// characters that would break JSON string syntax.
    #[must_use]
    pub fn json_safe() -> Self {
        Self {
            escape_newlines: true,
            escape_carriage_returns: true,
            escape_tabs: true,
            remove_ansi_escapes: true,
            remove_control_chars: true,
            use_replacement_char: false,
            max_length: 0,
            truncation_suffix: "...",
            allow_unicode: true,
            escape_unicode: false,
        }
    }

    /// Builder method to set max length
    #[must_use]
    pub fn with_max_length(mut self, max_length: usize) -> Self {
        self.max_length = max_length;
        self
    }

    /// Builder method to set truncation suffix
    #[must_use]
    pub fn with_truncation_suffix(mut self, suffix: &'static str) -> Self {
        self.truncation_suffix = suffix;
        self
    }

    /// Builder method to enable replacement char mode
    ///
    /// When enabled, control characters are replaced with the Unicode
    /// replacement character (U+FFFD) instead of being removed.
    #[must_use]
    pub fn with_replacement_char(mut self, enabled: bool) -> Self {
        self.use_replacement_char = enabled;
        self
    }
}

// ============================================================================
// Conversions
// ============================================================================

impl From<TextConfig> for crate::primitives::data::text::TextConfig {
    fn from(config: TextConfig) -> Self {
        Self {
            escape_newlines: config.escape_newlines,
            escape_carriage_returns: config.escape_carriage_returns,
            escape_tabs: config.escape_tabs,
            remove_ansi_escapes: config.remove_ansi_escapes,
            remove_control_chars: config.remove_control_chars,
            use_replacement_char: config.use_replacement_char,
            max_length: config.max_length,
            truncation_suffix: config.truncation_suffix,
            allow_unicode: config.allow_unicode,
            escape_unicode: config.escape_unicode,
        }
    }
}

impl From<&TextConfig> for crate::primitives::data::text::TextConfig {
    fn from(config: &TextConfig) -> Self {
        Self {
            escape_newlines: config.escape_newlines,
            escape_carriage_returns: config.escape_carriage_returns,
            escape_tabs: config.escape_tabs,
            remove_ansi_escapes: config.remove_ansi_escapes,
            remove_control_chars: config.remove_control_chars,
            use_replacement_char: config.use_replacement_char,
            max_length: config.max_length,
            truncation_suffix: config.truncation_suffix,
            allow_unicode: config.allow_unicode,
            escape_unicode: config.escape_unicode,
        }
    }
}

impl From<crate::primitives::data::text::TextConfig> for TextConfig {
    fn from(config: crate::primitives::data::text::TextConfig) -> Self {
        Self {
            escape_newlines: config.escape_newlines,
            escape_carriage_returns: config.escape_carriage_returns,
            escape_tabs: config.escape_tabs,
            remove_ansi_escapes: config.remove_ansi_escapes,
            remove_control_chars: config.remove_control_chars,
            use_replacement_char: config.use_replacement_char,
            max_length: config.max_length,
            truncation_suffix: config.truncation_suffix,
            allow_unicode: config.allow_unicode,
            escape_unicode: config.escape_unicode,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TextConfig::default();
        assert!(config.escape_newlines);
        assert!(config.remove_ansi_escapes);
        assert_eq!(config.max_length, 0);
    }

    #[test]
    fn test_strict_config() {
        let config = TextConfig::strict();
        assert!(config.escape_tabs);
        assert!(!config.allow_unicode);
        assert_eq!(config.max_length, 10000);
    }

    #[test]
    fn test_relaxed_config() {
        let config = TextConfig::relaxed();
        assert!(!config.escape_newlines);
        assert!(config.use_replacement_char);
    }

    #[test]
    fn test_json_safe_config() {
        let config = TextConfig::json_safe();
        assert!(config.escape_tabs);
        assert!(config.allow_unicode);
    }

    #[test]
    fn test_builder_methods() {
        let config = TextConfig::default()
            .with_max_length(500)
            .with_truncation_suffix("[...]")
            .with_replacement_char(true);

        assert_eq!(config.max_length, 500);
        assert_eq!(config.truncation_suffix, "[...]");
        assert!(config.use_replacement_char);
    }

    #[test]
    fn test_conversion_to_primitive() {
        let config = TextConfig::strict();
        let primitive: crate::primitives::data::text::TextConfig = config.into();
        assert!(primitive.escape_tabs);
        assert!(!primitive.allow_unicode);
    }

    #[test]
    fn test_conversion_from_primitive() {
        let primitive = crate::primitives::data::text::TextConfig::strict();
        let config: TextConfig = primitive.into();
        assert!(config.escape_tabs);
        assert!(!config.allow_unicode);
    }
}

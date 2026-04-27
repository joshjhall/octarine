//! Text builder with observe instrumentation
//!
//! Provides a builder pattern for text operations with
//! built-in logging and metrics via the observe module.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.

// Allow dead_code: This is public API that will be used by consumers
#![allow(dead_code)]

use std::borrow::Cow;
use std::time::Instant;

use crate::observe::event;
use crate::observe::metrics::{increment_by, record};
use crate::primitives::data::text::TextBuilder as PrimitiveTextBuilder;
use crate::primitives::data::text::TextConfig as PrimitiveTextConfig;

use super::types::TextConfig;

crate::define_metrics! {
    sanitize_ms => "data.text.sanitize_ms",
    threats_detected => "data.text.threats_detected",
}

// ============================================================================
// TextBuilder
// ============================================================================

/// Fluent builder for text detection and sanitization with observe instrumentation
///
/// This builder wraps `primitives::data::text::TextBuilder` and adds observe
/// instrumentation for compliance-grade audit trails.
///
/// # Example
///
/// ```ignore
/// use octarine::data::TextBuilder;
///
/// // Detection with event emission
/// let builder = TextBuilder::new(user_input);
/// if builder.is_dangerous_control_chars_present() {
///     // Warning event already emitted
///     let safe = builder.sanitize_for_log().finish();
/// }
///
/// // Chain operations
/// let safe = TextBuilder::new(user_input)
///     .strip_ansi()
///     .sanitize_for_log()
///     .truncate(100)
///     .finish();
/// ```
#[derive(Debug, Clone)]
pub struct TextBuilder<'a> {
    /// The underlying primitive builder
    inner: PrimitiveTextBuilder<'a>,
    /// Whether to emit observe events
    emit_events: bool,
}

impl<'a> TextBuilder<'a> {
    // ========================================================================
    // Construction
    // ========================================================================

    /// Create a new text builder with the given input
    #[inline]
    pub fn new(input: &'a str) -> Self {
        Self {
            inner: PrimitiveTextBuilder::new(input),
            emit_events: true,
        }
    }

    /// Create a text builder from an owned String
    #[inline]
    pub fn from_string(input: String) -> TextBuilder<'static> {
        TextBuilder {
            inner: PrimitiveTextBuilder::from_string(input),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for high-frequency internal paths)
    #[must_use]
    pub fn silent(input: &'a str) -> Self {
        Self {
            inner: PrimitiveTextBuilder::new(input),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // Configuration
    // ========================================================================

    /// Use custom configuration
    #[must_use]
    pub fn with_config(mut self, config: TextConfig) -> Self {
        let primitive_config: PrimitiveTextConfig = config.into();
        self.inner = self.inner.with_config(primitive_config);
        self
    }

    /// Use strict configuration (escape everything, ASCII only, length limited)
    #[must_use]
    pub fn with_strict_config(mut self) -> Self {
        self.inner = self.inner.with_strict_config();
        self
    }

    /// Use relaxed configuration (allow newlines, keep unicode)
    #[must_use]
    pub fn with_relaxed_config(mut self) -> Self {
        self.inner = self.inner.with_relaxed_config();
        self
    }

    /// Use JSON-safe configuration (escape for JSON string embedding)
    #[must_use]
    pub fn with_json_config(mut self) -> Self {
        self.inner = self.inner.with_json_config();
        self
    }

    /// Get the current configuration
    ///
    /// Returns a copy of the current configuration as the public type.
    #[inline]
    #[must_use]
    pub fn config(&self) -> TextConfig {
        self.inner.config().clone().into()
    }

    // ========================================================================
    // Detection (is_* -> bool) - with observe events on detection
    // ========================================================================

    /// Check if text contains any control characters (ASCII 0x00-0x1F, 0x7F)
    pub fn is_control_chars_present(&self) -> bool {
        let result = self.inner.is_control_chars_present();
        if self.emit_events && result {
            event::debug("text.control_chars_detected");
        }
        result
    }

    /// Check if text contains dangerous control characters (excludes tab, newline, CR)
    pub fn is_dangerous_control_chars_present(&self) -> bool {
        let result = self.inner.is_dangerous_control_chars_present();
        if self.emit_events && result {
            event::warn("text.dangerous_control_chars_detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if text contains null bytes
    pub fn is_null_bytes_present(&self) -> bool {
        let result = self.inner.is_null_bytes_present();
        if self.emit_events && result {
            event::warn("text.null_bytes_detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if text contains ANSI escape sequences
    pub fn is_ansi_escapes_present(&self) -> bool {
        let result = self.inner.is_ansi_escapes_present();
        if self.emit_events && result {
            event::debug("text.ansi_escapes_detected");
        }
        result
    }

    /// Check if text contains CRLF sequences (newlines or carriage returns)
    #[inline]
    pub fn is_crlf_present(&self) -> bool {
        self.inner.is_crlf_present()
    }

    /// Check if text contains newlines only
    #[inline]
    pub fn is_newlines_present(&self) -> bool {
        self.inner.is_newlines_present()
    }

    /// Check if text contains carriage returns only
    #[inline]
    pub fn is_carriage_returns_present(&self) -> bool {
        self.inner.is_carriage_returns_present()
    }

    /// Check if text contains cursor control sequences
    pub fn is_cursor_controls_present(&self) -> bool {
        let result = self.inner.is_cursor_controls_present();
        if self.emit_events && result {
            event::warn("text.cursor_controls_detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if text contains bell characters
    pub fn is_bell_present(&self) -> bool {
        let result = self.inner.is_bell_present();
        if self.emit_events && result {
            event::debug("text.bell_char_detected");
        }
        result
    }

    /// Check if text contains backspace characters
    pub fn is_backspace_present(&self) -> bool {
        let result = self.inner.is_backspace_present();
        if self.emit_events && result {
            event::debug("text.backspace_detected");
        }
        result
    }

    /// Check if text contains zero-width characters
    pub fn is_zero_width_chars_present(&self) -> bool {
        let result = self.inner.is_zero_width_chars_present();
        if self.emit_events && result {
            event::warn("text.zero_width_chars_detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if text contains bidirectional override characters
    pub fn is_bidi_overrides_present(&self) -> bool {
        let result = self.inner.is_bidi_overrides_present();
        if self.emit_events && result {
            event::warn("text.bidi_overrides_detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if text is safe for log output (no modifications needed)
    #[inline]
    pub fn is_log_safe(&self) -> bool {
        self.inner.is_log_safe()
    }

    // ========================================================================
    // Unicode Detection (is_* -> bool) - with observe events
    // ========================================================================

    /// Check if text contains mixed scripts (potential homograph attack)
    pub fn is_mixed_script_present(&self) -> bool {
        let result = self.inner.is_mixed_script_present();
        if self.emit_events && result {
            event::warn("text.mixed_script_detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if text uses only a single script (safe for identifiers)
    #[inline]
    pub fn is_single_script(&self) -> bool {
        self.inner.is_single_script()
    }

    /// Check if text contains confusable characters
    pub fn is_confusable_chars_present(&self) -> bool {
        let result = self.inner.is_confusable_chars_present();
        if self.emit_events && result {
            event::warn("text.confusable_chars_detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if text contains format control characters
    pub fn is_format_chars_present(&self) -> bool {
        let result = self.inner.is_format_chars_present();
        if self.emit_events && result {
            event::warn("text.format_chars_detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if text contains private use area characters
    pub fn is_private_use_present(&self) -> bool {
        let result = self.inner.is_private_use_present();
        if self.emit_events && result {
            event::warn("text.private_use_chars_detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if text is already in NFC normalized form
    #[inline]
    pub fn is_nfc(&self) -> bool {
        self.inner.is_nfc()
    }

    /// Check if text is already in NFKC normalized form
    #[inline]
    pub fn is_nfkc(&self) -> bool {
        self.inner.is_nfkc()
    }

    /// Check if text is Unicode-secure (no threats detected)
    #[inline]
    pub fn is_unicode_secure(&self) -> bool {
        self.inner.is_unicode_secure()
    }

    /// Check if a string is confusable with this text
    #[inline]
    pub fn is_confusable_with(&self, other: &str) -> bool {
        self.inner.is_confusable_with(other)
    }

    /// Check if text is safe for use as an identifier
    #[inline]
    pub fn is_identifier_safe(&self) -> bool {
        self.inner.is_identifier_safe()
    }

    // ========================================================================
    // Detection (detect_* -> Vec, count_* -> usize)
    // ========================================================================

    /// Detect positions of all control characters
    #[inline]
    pub fn detect_control_char_positions(&self) -> Vec<usize> {
        self.inner.detect_control_char_positions()
    }

    /// Count the number of control characters
    #[inline]
    pub fn count_control_chars(&self) -> usize {
        self.inner.count_control_chars()
    }

    // ========================================================================
    // Transform (chainable, modifies internal text)
    // ========================================================================

    /// Sanitize text for safe log output using current config
    #[must_use]
    pub fn sanitize_for_log(mut self) -> Self {
        let start = Instant::now();
        self.inner = self.inner.sanitize_for_log();
        if self.emit_events {
            record(
                metric_names::sanitize_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        self
    }

    /// Strip ANSI escape sequences
    #[must_use]
    pub fn strip_ansi(mut self) -> Self {
        self.inner = self.inner.strip_ansi();
        self
    }

    /// Strip dangerous control characters (keeps tab, newline, CR)
    #[must_use]
    pub fn strip_control_chars(mut self) -> Self {
        self.inner = self.inner.strip_control_chars();
        self
    }

    /// Escape line breaks as literal \n and \r
    #[must_use]
    pub fn escape_line_breaks(mut self) -> Self {
        self.inner = self.inner.escape_line_breaks();
        self
    }

    /// Truncate text to maximum length with suffix
    #[must_use]
    pub fn truncate(mut self, max_length: usize) -> Self {
        self.inner = self.inner.truncate(max_length);
        self
    }

    /// Truncate text with custom suffix
    #[must_use]
    pub fn truncate_with_suffix(mut self, max_length: usize, suffix: &str) -> Self {
        self.inner = self.inner.truncate_with_suffix(max_length, suffix);
        self
    }

    // ========================================================================
    // Unicode Transform (chainable, modifies internal text)
    // ========================================================================

    /// Normalize text to NFC form (canonical composition)
    #[must_use]
    pub fn normalize_nfc(mut self) -> Self {
        self.inner = self.inner.normalize_nfc();
        self
    }

    /// Normalize text to NFKC form (compatibility composition)
    #[must_use]
    pub fn normalize_nfkc(mut self) -> Self {
        self.inner = self.inner.normalize_nfkc();
        self
    }

    /// Strip format control characters (soft hyphens, joiners, etc.)
    #[must_use]
    pub fn strip_format_chars(mut self) -> Self {
        self.inner = self.inner.strip_format_chars();
        self
    }

    /// Strip zero-width characters
    #[must_use]
    pub fn strip_zero_width(mut self) -> Self {
        self.inner = self.inner.strip_zero_width();
        self
    }

    /// Strip bidirectional override characters
    #[must_use]
    pub fn strip_bidi_overrides(mut self) -> Self {
        self.inner = self.inner.strip_bidi_overrides();
        self
    }

    /// Apply comprehensive unicode sanitization
    ///
    /// Normalizes to NFC, strips format chars, zero-width chars, and bidi overrides.
    #[must_use]
    pub fn sanitize_unicode(mut self) -> Self {
        let start = Instant::now();
        self.inner = self.inner.sanitize_unicode();
        if self.emit_events {
            record(
                metric_names::sanitize_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        self
    }

    // ========================================================================
    // Finish
    // ========================================================================

    /// Get the current text as a reference
    #[inline]
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Finish and return the processed text
    #[inline]
    pub fn finish(self) -> Cow<'a, str> {
        self.inner.finish()
    }

    /// Finish and return as owned String
    #[inline]
    pub fn into_string(self) -> String {
        self.inner.into_string()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::observe::metrics::{flush_for_testing, snapshot};
    use std::sync::Mutex;

    static METRICS_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_detection_with_events() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Events are enabled by default
        let builder = TextBuilder::new("hello\x00world");
        assert!(builder.is_null_bytes_present());
    }

    #[test]
    fn test_detection_silent() {
        // Events disabled
        let builder = TextBuilder::silent("hello\x00world");
        assert!(builder.is_null_bytes_present());
    }

    #[test]
    fn test_sanitize_chain() {
        let result = TextBuilder::silent("input\n\x1B[31mred\x00text")
            .strip_ansi()
            .strip_control_chars()
            .sanitize_for_log()
            .finish();
        assert!(!result.contains('\x1B'));
        assert!(!result.contains('\x00'));
    }

    #[test]
    fn test_from_string() {
        let owned = String::from("owned input\nwith newline");
        let result = TextBuilder::from_string(owned)
            .with_events(false)
            .sanitize_for_log()
            .finish();
        assert_eq!(result, "owned input\\nwith newline");
    }

    #[test]
    fn test_with_strict_config() {
        let result = TextBuilder::silent("Tab\there")
            .with_strict_config()
            .sanitize_for_log()
            .finish();
        assert_eq!(result, "Tab\\there");
    }

    #[test]
    fn test_with_relaxed_config() {
        let result = TextBuilder::silent("line1\nline2")
            .with_relaxed_config()
            .sanitize_for_log()
            .finish();
        assert_eq!(result, "line1\nline2");
    }

    #[test]
    fn test_truncate() {
        let result = TextBuilder::new("Hello, World!").truncate(10).finish();
        assert_eq!(result, "Hello, ...");
    }

    #[test]
    fn test_as_str() {
        let builder = TextBuilder::new("hello");
        assert_eq!(builder.as_str(), "hello");
    }

    #[test]
    fn test_into_string() {
        let result = TextBuilder::silent("hello")
            .sanitize_for_log()
            .into_string();
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_with_events_toggle() {
        let builder = TextBuilder::new("test").with_events(false);
        assert!(!builder.emit_events);
    }

    // ========================================================================
    // Unicode Security Tests
    // ========================================================================

    #[test]
    fn test_mixed_script_detection() {
        // Cyrillic 'а' mixed with Latin
        let builder = TextBuilder::silent("аpple"); // Cyrillic а + Latin pple
        assert!(builder.is_mixed_script_present());

        // Pure ASCII
        let builder = TextBuilder::silent("apple");
        assert!(!builder.is_mixed_script_present());
    }

    #[test]
    fn test_confusable_detection() {
        // Cyrillic 'а' looks like Latin 'a'
        let builder = TextBuilder::new("аpple"); // Cyrillic а
        assert!(builder.is_confusable_with("apple"));
    }

    #[test]
    fn test_normalize_nfc() {
        // é as e + combining acute vs precomposed é
        let decomposed = "caf\u{0065}\u{0301}"; // e + combining acute
        let result = TextBuilder::new(decomposed).normalize_nfc().into_string();
        assert_eq!(result, "café"); // precomposed
    }

    #[test]
    fn test_zero_width_detection() {
        let zwj = "test\u{200D}data"; // Zero-width joiner
        let builder = TextBuilder::silent(zwj);
        assert!(builder.is_zero_width_chars_present());
    }

    #[test]
    fn test_strip_zero_width() {
        let zwj = "test\u{200D}data"; // Zero-width joiner
        let result = TextBuilder::new(zwj).strip_zero_width().into_string();
        assert_eq!(result, "testdata");
    }

    #[test]
    fn test_bidi_override_detection() {
        let bidi = "hello\u{202E}world"; // Right-to-left override
        let builder = TextBuilder::silent(bidi);
        assert!(builder.is_bidi_overrides_present());
    }

    #[test]
    fn test_strip_bidi_overrides() {
        let bidi = "hello\u{202E}world"; // Right-to-left override
        let result = TextBuilder::new(bidi).strip_bidi_overrides().into_string();
        assert_eq!(result, "helloworld");
    }

    #[test]
    fn test_sanitize_unicode_chain() {
        // Combine multiple threats
        let input = "test\u{200D}\u{202E}data"; // ZWJ + RLO
        let result = TextBuilder::silent(input).sanitize_unicode().into_string();
        assert!(!result.contains('\u{200D}'));
        assert!(!result.contains('\u{202E}'));
    }

    #[test]
    fn test_unicode_secure() {
        let safe = TextBuilder::silent("hello world");
        assert!(safe.is_unicode_secure());

        let unsafe_text = TextBuilder::silent("hello\u{202E}world");
        assert!(!unsafe_text.is_unicode_secure());
    }

    #[test]
    fn test_is_identifier_safe() {
        let safe = TextBuilder::silent("valid_identifier");
        assert!(safe.is_identifier_safe());

        // Single script Cyrillic is safe
        let cyrillic = TextBuilder::silent("Москва");
        assert!(cyrillic.is_identifier_safe());

        // Format control characters are not safe for identifiers
        let with_zwj = TextBuilder::silent("test\u{200D}abc"); // Zero-width joiner
        assert!(!with_zwj.is_identifier_safe());
    }

    // ========================================================================
    // Metrics Tests
    // ========================================================================

    #[test]
    fn test_metrics_sanitize_ms_recorded() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        flush_for_testing();
        let before = snapshot()
            .histograms
            .get("data.text.sanitize_ms")
            .map_or(0, |h| h.count);

        let _ = TextBuilder::new("test\x1B[31mred")
            .sanitize_for_log()
            .into_string();
        flush_for_testing();

        let after = snapshot()
            .histograms
            .get("data.text.sanitize_ms")
            .map_or(0, |h| h.count);
        assert!(
            after > before,
            "sanitize_ms histogram should record at least one sample"
        );
    }

    #[test]
    fn test_metrics_threats_detected_counter() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        flush_for_testing();
        let before = snapshot()
            .counters
            .get("data.text.threats_detected")
            .map_or(0, |c| c.value);

        let builder = TextBuilder::new("hello\x00world");
        assert!(builder.is_null_bytes_present());
        flush_for_testing();

        let after = snapshot()
            .counters
            .get("data.text.threats_detected")
            .map_or(0, |c| c.value);
        assert!(
            after > before,
            "threats_detected counter should increment on null-byte detection"
        );
    }

    #[test]
    fn test_silent_mode_emits_no_metrics() {
        // Structural test: `silent()` returns a builder with emit_events=false,
        // and every metric call site in this module is gated by `if self.emit_events`.
        // A behavioral delta-assertion would race with concurrent tests across the
        // workspace that hit these same global metric names.
        let builder = TextBuilder::silent("hello\x00world");
        assert!(!builder.emit_events);

        // Sanity: invoking through the silent builder still works functionally.
        assert!(builder.is_null_bytes_present());
        let _ = TextBuilder::silent("test\x1B[31mred")
            .sanitize_for_log()
            .into_string();
    }
}

//! Entropy identifier builder with observability
//!
//! Wraps `primitives::identifiers::entropy` free functions with observe
//! instrumentation for compliance-grade audit trails.

use std::time::Instant;

use crate::observe;
use crate::observe::metrics::{MetricName, increment_by, record};
use crate::primitives::identifiers::entropy;

use super::super::types::IdentifierMatch;

#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn detect_ms() -> MetricName {
        MetricName::new("data.identifiers.entropy.detect_ms").expect("valid metric name")
    }

    pub fn detected() -> MetricName {
        MetricName::new("data.identifiers.entropy.detected").expect("valid metric name")
    }
}

/// Entropy identifier builder with observability
///
/// Detects high-entropy strings (potential secrets, API keys, generated passwords)
/// with optional observe instrumentation.
///
/// # Example
///
/// ```ignore
/// use octarine::identifiers::EntropyBuilder;
///
/// let builder = EntropyBuilder::new();
///
/// // Single value check
/// if builder.is_high_entropy("aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0z") {
///     println!("Potential secret detected");
/// }
///
/// // Scan text for high-entropy strings
/// let matches = builder.detect_in_text("token aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0z");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct EntropyBuilder {
    /// Whether to emit observe events
    emit_events: bool,
}

impl EntropyBuilder {
    /// Create a new EntropyBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self { emit_events: true }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self { emit_events: false }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // =========================================================================
    // Detection Methods
    // =========================================================================

    /// Check if a value is a high-entropy string (potential secret)
    #[must_use]
    pub fn is_high_entropy(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = entropy::is_high_entropy(value);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if result {
                increment_by(metric_names::detected(), 1);
                observe::warn(
                    "high_entropy_string_detected",
                    "High-entropy string detected — potential secret or API key",
                );
            }
        }

        result
    }

    /// Detect high-entropy strings in text
    ///
    /// Scans text for tokens that exceed entropy thresholds, returning matches
    /// with position information.
    #[must_use]
    pub fn detect_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = entropy::detect_high_entropy_strings_in_text(text);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
                observe::warn(
                    "high_entropy_string_detected",
                    format!("Detected {} high-entropy string(s) in text", matches.len()),
                );
            }
        }

        matches
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_new_creates_with_events() {
        let builder = EntropyBuilder::new();
        assert!(builder.emit_events);
    }

    #[test]
    fn test_silent_creates_without_events() {
        let builder = EntropyBuilder::silent();
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_with_events_toggle() {
        let builder = EntropyBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_is_high_entropy_detects_secret() {
        let builder = EntropyBuilder::new();
        // A realistic high-entropy string (base64-like API key)
        assert!(builder.is_high_entropy("aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0z"));
    }

    #[test]
    fn test_is_high_entropy_rejects_normal_text() {
        let builder = EntropyBuilder::new();
        assert!(!builder.is_high_entropy("hello"));
        assert!(!builder.is_high_entropy("normal text here"));
    }

    #[test]
    fn test_detect_in_text_finds_secrets() {
        let builder = EntropyBuilder::new();
        let text = "config aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0z value";
        let matches = builder.detect_in_text(text);
        // Should find at least the high-entropy token
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_detect_in_text_empty_for_normal_text() {
        let builder = EntropyBuilder::new();
        let matches = builder.detect_in_text("just some normal everyday text");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_silent_mode_still_detects() {
        let builder = EntropyBuilder::silent();
        // Silent mode suppresses events but detection still works
        let text = "found aB3dE6gH9jK2mN5pQ8rS1tU4vW7xY0z here";
        let matches = builder.detect_in_text(text);
        assert!(!matches.is_empty());
    }
}

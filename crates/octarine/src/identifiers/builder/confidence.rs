//! Confidence scoring builder with observability
//!
//! Wraps `primitives::identifiers::confidence::ConfidenceBuilder` with observe
//! instrumentation for compliance-grade audit trails.

use std::time::Instant;

use crate::observe;
use crate::observe::metrics::{MetricName, increment_by, record};
use crate::primitives::identifiers::IdentifierType;
use crate::primitives::identifiers::confidence::ConfidenceBuilder as PrimitiveConfidenceBuilder;

#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn analyze_ms() -> MetricName {
        MetricName::new("data.identifiers.confidence.analyze_ms").expect("valid metric name")
    }

    pub fn boosted() -> MetricName {
        MetricName::new("data.identifiers.confidence.boosted").expect("valid metric name")
    }
}

/// Confidence scoring builder with observability
///
/// Wraps the primitive `ConfidenceBuilder` to provide context-aware confidence
/// scoring with optional observe instrumentation (metrics and events).
///
/// # Example
///
/// ```ignore
/// use octarine::identifiers::ConfidenceBuilder;
/// use octarine::primitives::identifiers::IdentifierType;
///
/// let builder = ConfidenceBuilder::new();
/// let score = builder.analyze("SSN: 123-45-6789", 5, 16, &IdentifierType::Ssn);
/// assert!(score > 0.5); // Boosted by "SSN" context keyword
/// ```
#[derive(Debug, Clone)]
pub struct ConfidenceBuilder {
    inner: PrimitiveConfidenceBuilder,
    emit_events: bool,
}

impl Default for ConfidenceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfidenceBuilder {
    /// Create a new ConfidenceBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PrimitiveConfidenceBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: PrimitiveConfidenceBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // =========================================================================
    // Configuration Methods (fluent API, delegated to primitive)
    // =========================================================================

    /// Set the context window size in characters (default: 100)
    #[must_use]
    pub fn with_window_size(mut self, size: usize) -> Self {
        self.inner = self.inner.with_window_size(size);
        self
    }

    /// Set the confidence boost factor (default: 0.35)
    #[must_use]
    pub fn with_boost_factor(mut self, factor: f64) -> Self {
        self.inner = self.inner.with_boost_factor(factor);
        self
    }

    /// Set the maximum confidence score (default: 0.95)
    #[must_use]
    pub fn with_max_confidence(mut self, max: f64) -> Self {
        self.inner = self.inner.with_max_confidence(max);
        self
    }

    // =========================================================================
    // Analysis Methods
    // =========================================================================

    /// Analyze context around a match and return a confidence score
    ///
    /// Checks for contextual keywords near the match position and boosts
    /// the confidence score accordingly. Emits timing metrics and a counter
    /// when confidence is boosted above the base score.
    #[must_use]
    pub fn analyze(
        &self,
        text: &str,
        match_start: usize,
        match_end: usize,
        entity_type: &IdentifierType,
    ) -> f64 {
        let start = Instant::now();
        let score = self
            .inner
            .analyze(text, match_start, match_end, entity_type);

        if self.emit_events {
            record(
                metric_names::analyze_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            // Base confidence is 0.5 — anything above means context boosted it
            if score > 0.5 {
                increment_by(metric_names::boosted(), 1);
                observe::debug(
                    "confidence_boosted",
                    format!("Context boost: {entity_type:?} confidence {score:.2} (base 0.50)"),
                );
            }
        }

        score
    }

    /// Check whether context keywords are present near the match
    #[must_use]
    pub fn is_context_present(
        &self,
        text: &str,
        match_start: usize,
        match_end: usize,
        entity_type: &IdentifierType,
    ) -> bool {
        self.inner
            .is_context_present(text, match_start, match_end, entity_type)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_new_creates_with_events() {
        let builder = ConfidenceBuilder::new();
        assert!(builder.emit_events);
    }

    #[test]
    fn test_silent_creates_without_events() {
        let builder = ConfidenceBuilder::silent();
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_with_events_toggle() {
        let builder = ConfidenceBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_analyze_boosts_with_context() {
        let builder = ConfidenceBuilder::new();
        let text = "SSN: 123-45-6789";
        let score = builder.analyze(text, 5, 16, &IdentifierType::Ssn);
        assert!(score > 0.5, "Expected boosted score, got {score}");
    }

    #[test]
    fn test_analyze_base_without_context() {
        let builder = ConfidenceBuilder::new();
        let text = "code: 123-45-6789";
        let score = builder.analyze(text, 6, 17, &IdentifierType::Ssn);
        assert!(
            (score - 0.5).abs() < f64::EPSILON,
            "Expected base confidence, got {score}"
        );
    }

    #[test]
    fn test_is_context_present_with_keyword() {
        let builder = ConfidenceBuilder::new();
        let text = "social security number: 123-45-6789";
        assert!(builder.is_context_present(text, 24, 35, &IdentifierType::Ssn));
    }

    #[test]
    fn test_is_context_present_without_keyword() {
        let builder = ConfidenceBuilder::new();
        let text = "the number is 123-45-6789";
        assert!(!builder.is_context_present(text, 14, 25, &IdentifierType::Ssn));
    }

    #[test]
    fn test_silent_mode_still_analyzes() {
        let builder = ConfidenceBuilder::silent();
        let text = "SSN: 123-45-6789";
        let score = builder.analyze(text, 5, 16, &IdentifierType::Ssn);
        assert!(score > 0.5, "Silent mode should still score, got {score}");
    }

    #[test]
    fn test_fluent_config() {
        let builder = ConfidenceBuilder::new()
            .with_window_size(50)
            .with_boost_factor(0.25)
            .with_max_confidence(0.8);
        let text = "SSN: 123-45-6789";
        let score = builder.analyze(text, 5, 16, &IdentifierType::Ssn);
        let expected = 0.5 + 0.25;
        assert!(
            (score - expected).abs() < f64::EPSILON,
            "Expected {expected}, got {score}"
        );
    }
}

//! Credential pair correlation builder with observability (Layer 3).
//!
//! Wraps `primitives::identifiers::correlation::CorrelationBuilder` with observe
//! instrumentation for compliance-grade audit trails.

use std::time::Instant;

use crate::observe;
use crate::observe::metrics::{MetricName, increment_by, record};
use crate::primitives::identifiers::correlation::builder::CorrelationBuilder as PrimitiveCorrelationBuilder;

use super::super::types::{
    CorrelationConfig, CorrelationMatch, CredentialPairType, IdentifierMatch,
};

// Pre-validated metric names
#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn detect_ms() -> MetricName {
        MetricName::new("data.identifiers.correlation.detect_ms").expect("valid metric name")
    }

    pub fn pairs_detected() -> MetricName {
        MetricName::new("data.identifiers.correlation.pairs_detected").expect("valid metric name")
    }
}

/// Credential pair correlation builder with observability.
///
/// Detects pairs of related credentials (e.g., AWS access key + secret key)
/// that appear near each other in text, with full audit trail via observe.
///
/// # Example
///
/// ```ignore
/// use octarine::identifiers::CorrelationBuilder;
///
/// let builder = CorrelationBuilder::new();
/// let pairs = builder.detect_pairs("AWS_ACCESS_KEY=AKIA... SECRET=...");
///
/// // Silent mode (no observe events)
/// let silent = CorrelationBuilder::silent();
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct CorrelationBuilder {
    inner: PrimitiveCorrelationBuilder,
    emit_events: bool,
}

impl CorrelationBuilder {
    /// Create a new CorrelationBuilder with observe events enabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PrimitiveCorrelationBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use or batch processing).
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: PrimitiveCorrelationBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events.
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // Detection Methods
    // ========================================================================

    /// Detect credential pairs in text using default configuration.
    ///
    /// Scans for all identifier types, finds proximate pairs within the
    /// default window (5 lines / 500 chars), and classifies known pairs.
    #[must_use]
    pub fn detect_pairs(&self, text: &str) -> Vec<CorrelationMatch> {
        let start = Instant::now();
        let prim_results = self.inner.detect_pairs(text);
        let count = prim_results.len();

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if count > 0 {
                increment_by(metric_names::pairs_detected(), count as u64);
                observe::warn(
                    "credential_pairs_detected",
                    format!("Detected {count} credential pair(s) in text"),
                );
            }
        }

        prim_results
    }

    /// Detect credential pairs in text with custom configuration.
    #[must_use]
    pub fn detect_pairs_with_config(
        &self,
        text: &str,
        config: CorrelationConfig,
    ) -> Vec<CorrelationMatch> {
        let start = Instant::now();
        let prim_results = self.inner.detect_pairs_with_config(text, &config);
        let count = prim_results.len();

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if count > 0 {
                increment_by(metric_names::pairs_detected(), count as u64);
                observe::warn(
                    "credential_pairs_detected",
                    format!("Detected {count} credential pair(s) in text"),
                );
            }
        }

        prim_results
    }

    /// Check if two identifier matches form a known credential pair.
    ///
    /// Order-independent: `(A, B)` and `(B, A)` both match.
    #[must_use]
    pub fn is_credential_pair(
        &self,
        primary: &IdentifierMatch,
        secondary: &IdentifierMatch,
    ) -> Option<CredentialPairType> {
        self.inner.is_credential_pair(primary, secondary)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]

    use super::*;
    use crate::identifiers::types::{DetectionConfidence, IdentifierType};

    #[test]
    fn test_builder_creation() {
        let builder = CorrelationBuilder::new();
        assert!(builder.emit_events);
    }

    #[test]
    fn test_silent_builder() {
        let builder = CorrelationBuilder::silent();
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = CorrelationBuilder::new().with_events(false);
        assert!(!builder.emit_events);

        let builder = CorrelationBuilder::silent().with_events(true);
        assert!(builder.emit_events);
    }

    #[test]
    fn test_detect_pairs_empty() {
        let builder = CorrelationBuilder::silent();
        assert!(builder.detect_pairs("").is_empty());
    }

    #[test]
    fn test_detect_pairs_with_config_empty() {
        let builder = CorrelationBuilder::silent();
        let config = CorrelationConfig::default();
        assert!(builder.detect_pairs_with_config("", config).is_empty());
    }

    #[test]
    fn test_is_credential_pair_delegates() {
        let builder = CorrelationBuilder::silent();
        let a = IdentifierMatch {
            start: 0,
            end: 5,
            matched_text: "admin".to_string(),
            identifier_type: IdentifierType::Username,
            confidence: DetectionConfidence::Medium,
        };
        let b = IdentifierMatch {
            start: 10,
            end: 20,
            matched_text: "secret123!".to_string(),
            identifier_type: IdentifierType::Password,
            confidence: DetectionConfidence::High,
        };
        assert_eq!(
            builder.is_credential_pair(&a, &b),
            Some(CredentialPairType::UsernamePasswordPair)
        );
    }
}

//! Label support for dimensional metrics
//!
//! Labels allow metrics to have multiple dimensions for better
//! aggregation and filtering.

use std::collections::BTreeMap;
use std::fmt;

/// A metric with labels for dimensional data
pub(crate) struct LabeledMetric<'a> {
    name: &'a str,
    labels: BTreeMap<&'a str, &'a str>,
}

impl<'a> LabeledMetric<'a> {
    /// Create a new labeled metric
    pub(crate) fn new(name: &'a str) -> Self {
        Self {
            name,
            labels: BTreeMap::new(),
        }
    }

    /// Add a label to this metric
    pub fn with_label(mut self, key: &'a str, value: &'a str) -> Self {
        self.labels.insert(key, value);
        self
    }

    /// Increment this counter by 1
    pub fn increment(self) {
        let name = self.get_validated_name();
        super::global().counter(&name).increment();
    }

    /// Increment this counter by amount
    pub fn increment_by(self, amount: u64) {
        let name = self.get_validated_name();
        super::global().counter(&name).increment_by(amount);
    }

    /// Set gauge value
    pub fn set(self, value: i64) {
        let name = self.get_validated_name();
        super::global().gauge(&name).set(value);
    }

    /// Record histogram value
    pub fn record(self, value: f64) {
        let name = self.get_validated_name();
        super::global().histogram(&name).record(value);
    }

    /// Get the validated metric name (auto-sanitizes if invalid)
    fn get_validated_name(&self) -> String {
        use crate::observe::event::{error, warn};
        use crate::primitives::identifiers::MetricsBuilder;

        let mb = MetricsBuilder::new();

        // Validate the base name
        let _base_name = match mb.validate_name(self.name) {
            Ok(_) => self.name.to_string(),
            Err(_problem) => {
                // Auto-normalize for usability
                let normalized = mb.normalize_name(self.name);

                // Log as warning event (not an error since we auto-correct)
                warn(format!(
                    "Invalid metric name '{}' auto-corrected to '{}'",
                    self.name, normalized
                ));

                normalized
            }
        };

        // Validate labels and collect issues
        let mut label_issues = Vec::new();

        for (key, value) in &self.labels {
            if let Err(problem) = mb.validate_label_key(key) {
                label_issues.push(format!("Invalid label key '{}': {}", key, problem));
            }
            if let Err(problem) = mb.validate_label_value(value) {
                label_issues.push(format!(
                    "Invalid label value '{}' for key '{}': {}",
                    value, key, problem
                ));
            }
        }

        // Check cardinality
        if let Err(_problem) = mb.validate_label_count(self.labels.len()) {
            // This is more serious - could indicate an attack or bug
            error(format!(
                "Too many labels ({}) for metric '{}' (max: 20)",
                self.labels.len(),
                self.name
            ));
        }

        // Log label issues if any
        if !label_issues.is_empty() {
            warn(format!(
                "Label validation issues for metric '{}': {}",
                self.name,
                label_issues.join("; ")
            ));
        }

        self.to_canonical_name()
    }

    /// Convert to canonical name with labels
    fn to_canonical_name(&self) -> String {
        if self.labels.is_empty() {
            self.name.to_string()
        } else {
            // Use consistent ordering with BTreeMap
            let labels = self
                .labels
                .iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, v))
                .collect::<Vec<_>>()
                .join(",");
            format!("{}{{{}}}", self.name, labels)
        }
    }
}

impl<'a> fmt::Display for LabeledMetric<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_canonical_name())
    }
}

/// Create a metric that can have labels
pub fn metric(name: &str) -> LabeledMetric<'_> {
    LabeledMetric::new(name)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_labeled_metric_canonical_name() {
        let metric = LabeledMetric::new("api.requests");
        assert_eq!(metric.to_canonical_name(), "api.requests");

        let metric = LabeledMetric::new("api.requests")
            .with_label("method", "GET")
            .with_label("status", "200");
        assert_eq!(
            metric.to_canonical_name(),
            "api.requests{method=\"GET\",status=\"200\"}"
        );
    }

    #[test]
    fn test_label_ordering() {
        // Labels should be in consistent order (alphabetical by key)
        let metric1 = LabeledMetric::new("test")
            .with_label("b", "2")
            .with_label("a", "1");

        let metric2 = LabeledMetric::new("test")
            .with_label("a", "1")
            .with_label("b", "2");

        assert_eq!(metric1.to_canonical_name(), metric2.to_canonical_name());
    }
}

//! Built-in observe metrics
//!
//! These metrics track the health and performance of the observe module itself.
//! They are automatically exported via Prometheus/StatsD when configured.

/// Metric names for built-in observe metrics
pub mod names {
    // Event metrics
    /// Total events processed (by event_type)
    pub const EVENTS_TOTAL: &str = "observe.events.total";
    /// Event processing errors
    pub const EVENTS_ERRORS: &str = "observe.events.errors";
    /// Event processing latency (histogram)
    pub const EVENTS_LATENCY: &str = "observe.events.latency";

    // PII metrics
    /// Total PII scans performed
    pub const PII_SCANS_TOTAL: &str = "observe.pii.scans.total";
    /// Total redactions performed (by pii_type)
    pub const PII_REDACTIONS_TOTAL: &str = "observe.pii.redactions.total";
    /// PII scan time (histogram)
    pub const PII_SCAN_TIME: &str = "observe.pii.scan_time";
    /// PII cache hits
    pub const PII_CACHE_HITS: &str = "observe.pii.cache_hits";
    /// PII cache misses
    pub const PII_CACHE_MISSES: &str = "observe.pii.cache_misses";

    // Writer metrics
    /// Events written (by writer)
    pub const WRITER_EVENTS: &str = "observe.writer.events";
    /// Writer errors (by writer)
    pub const WRITER_ERRORS: &str = "observe.writer.errors";
    /// Writer latency (histogram, by writer)
    pub const WRITER_LATENCY: &str = "observe.writer.latency";
    /// Writer queue depth (gauge)
    pub const WRITER_QUEUE_DEPTH: &str = "observe.writer.queue_depth";
    /// Writer overflow drops
    pub const WRITER_OVERFLOW_DROPS: &str = "observe.writer.overflow_drops";

    // Compliance metrics
    /// Compliance violations (by type)
    pub const COMPLIANCE_VIOLATIONS: &str = "observe.compliance.violations";
    /// Compliance alerts (by severity)
    pub const COMPLIANCE_ALERTS: &str = "observe.compliance.alerts";

    // Threshold metrics
    /// Threshold warnings triggered
    pub const THRESHOLD_WARNINGS: &str = "observe.threshold.warnings";
    /// Threshold criticals triggered
    pub const THRESHOLD_CRITICALS: &str = "observe.threshold.criticals";
    /// Threshold recoveries
    pub const THRESHOLD_RECOVERIES: &str = "observe.threshold.recoveries";
}

/// All built-in observe metric names
pub const ALL_METRICS: &[&str] = &[
    names::EVENTS_TOTAL,
    names::EVENTS_ERRORS,
    names::EVENTS_LATENCY,
    names::PII_SCANS_TOTAL,
    names::PII_REDACTIONS_TOTAL,
    names::PII_SCAN_TIME,
    names::PII_CACHE_HITS,
    names::PII_CACHE_MISSES,
    names::WRITER_EVENTS,
    names::WRITER_ERRORS,
    names::WRITER_LATENCY,
    names::WRITER_QUEUE_DEPTH,
    names::WRITER_OVERFLOW_DROPS,
    names::COMPLIANCE_VIOLATIONS,
    names::COMPLIANCE_ALERTS,
    names::THRESHOLD_WARNINGS,
    names::THRESHOLD_CRITICALS,
    names::THRESHOLD_RECOVERIES,
];

/// Category of built-in metrics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricCategory {
    /// Event processing metrics
    Events,
    /// PII detection/redaction metrics
    Pii,
    /// Writer performance metrics
    Writer,
    /// Compliance tracking metrics
    Compliance,
    /// Threshold monitoring metrics
    Threshold,
}

impl MetricCategory {
    /// Get all metrics in this category
    pub fn metrics(&self) -> &'static [&'static str] {
        match self {
            MetricCategory::Events => &[
                names::EVENTS_TOTAL,
                names::EVENTS_ERRORS,
                names::EVENTS_LATENCY,
            ],
            MetricCategory::Pii => &[
                names::PII_SCANS_TOTAL,
                names::PII_REDACTIONS_TOTAL,
                names::PII_SCAN_TIME,
                names::PII_CACHE_HITS,
                names::PII_CACHE_MISSES,
            ],
            MetricCategory::Writer => &[
                names::WRITER_EVENTS,
                names::WRITER_ERRORS,
                names::WRITER_LATENCY,
                names::WRITER_QUEUE_DEPTH,
                names::WRITER_OVERFLOW_DROPS,
            ],
            MetricCategory::Compliance => &[names::COMPLIANCE_VIOLATIONS, names::COMPLIANCE_ALERTS],
            MetricCategory::Threshold => &[
                names::THRESHOLD_WARNINGS,
                names::THRESHOLD_CRITICALS,
                names::THRESHOLD_RECOVERIES,
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_all_metrics_count() {
        assert_eq!(ALL_METRICS.len(), 18);
    }

    #[test]
    fn test_metric_categories() {
        assert_eq!(MetricCategory::Events.metrics().len(), 3);
        assert_eq!(MetricCategory::Pii.metrics().len(), 5);
        assert_eq!(MetricCategory::Writer.metrics().len(), 5);
        assert_eq!(MetricCategory::Compliance.metrics().len(), 2);
        assert_eq!(MetricCategory::Threshold.metrics().len(), 3);
    }

    #[test]
    fn test_metric_naming_convention() {
        for metric in ALL_METRICS {
            assert!(
                metric.starts_with("observe."),
                "Metric {} should start with 'observe.'",
                metric
            );
        }
    }
}

//! Prometheus metrics exporter
//!
//! Generates metrics in Prometheus text exposition format for scraping.

use std::fmt::Write;

use super::DefaultLabels;
use crate::observe::metrics::{CounterSnapshot, GaugeSnapshot, HistogramSnapshot, MetricSnapshot};
use crate::primitives::types::Problem;

/// Result type for Prometheus rendering operations.
pub type Result<T> = std::result::Result<T, Problem>;

/// Configuration for the Prometheus exporter
#[derive(Debug, Clone, Default)]
pub struct PrometheusConfig {
    /// Namespace prefix for all metrics (optional)
    pub namespace: Option<String>,
    /// Subsystem prefix for all metrics (optional)
    pub subsystem: Option<String>,
    /// Include timestamps in output
    pub include_timestamps: bool,
    /// Default labels to add to all metrics
    pub default_labels: DefaultLabels,
}

impl PrometheusConfig {
    /// Create a new PrometheusConfig
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the namespace prefix
    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Set the subsystem prefix
    pub fn subsystem(mut self, subsystem: impl Into<String>) -> Self {
        self.subsystem = Some(subsystem.into());
        self
    }

    /// Enable timestamps in output
    pub fn with_timestamps(mut self) -> Self {
        self.include_timestamps = true;
        self
    }

    /// Set default labels
    pub fn default_labels(mut self, labels: DefaultLabels) -> Self {
        self.default_labels = labels;
        self
    }
}

/// Prometheus metrics exporter
///
/// Generates metrics in Prometheus text exposition format (0.0.4).
///
/// # Example
///
/// ```rust
/// use octarine::observe::metrics::{PrometheusExporter, PrometheusConfig, DefaultLabels};
///
/// let config = PrometheusConfig::new()
///     .namespace("myapp")
///     .default_labels(DefaultLabels::new().environment("prod"));
///
/// let exporter = PrometheusExporter::new(config);
/// match exporter.render() {
///     Ok(output) => println!("{}", output),
///     Err(e) => eprintln!("Failed to render metrics: {}", e),
/// }
/// ```
#[derive(Debug, Clone)]
pub struct PrometheusExporter {
    config: PrometheusConfig,
}

impl PrometheusExporter {
    /// Create a new Prometheus exporter
    pub fn new(config: PrometheusConfig) -> Self {
        Self { config }
    }

    /// Render all metrics to Prometheus text format.
    ///
    /// # Errors
    ///
    /// Returns `Problem::OperationFailed` if writing to the output buffer fails.
    pub fn render(&self) -> Result<String> {
        let snapshot = crate::observe::metrics::snapshot();
        self.render_snapshot(&snapshot)
    }

    /// Render a specific snapshot to Prometheus text format.
    ///
    /// # Errors
    ///
    /// Returns `Problem::OperationFailed` if writing to the output buffer fails.
    pub fn render_snapshot(&self, snapshot: &MetricSnapshot) -> Result<String> {
        let mut output = String::new();

        // Render counters
        for (name, counter) in &snapshot.counters {
            self.render_counter(&mut output, name, counter)?;
        }

        // Render gauges
        for (name, gauge) in &snapshot.gauges {
            self.render_gauge(&mut output, name, gauge)?;
        }

        // Render histograms
        for (name, histogram) in &snapshot.histograms {
            self.render_histogram(&mut output, name, histogram)?;
        }

        Ok(output)
    }

    /// Get the full metric name with namespace/subsystem prefix
    fn full_name(&self, name: &str) -> String {
        // Convert dots to underscores for Prometheus compatibility
        let safe_name = name.replace('.', "_");

        match (&self.config.namespace, &self.config.subsystem) {
            (Some(ns), Some(ss)) => format!("{}_{}_{}", ns, ss, safe_name),
            (Some(ns), None) => format!("{}_{}", ns, safe_name),
            (None, Some(ss)) => format!("{}_{}", ss, safe_name),
            (None, None) => safe_name,
        }
    }

    /// Format labels for a metric line
    fn format_labels(&self, additional: &[(&str, &str)]) -> String {
        let default = self.config.default_labels.format_prometheus();

        if additional.is_empty() && default.is_empty() {
            return String::new();
        }

        let mut parts = Vec::new();

        if !default.is_empty() {
            parts.push(default);
        }

        for (key, value) in additional {
            parts.push(format!("{}=\"{}\"", key, escape_label_value(value)));
        }

        format!("{{{}}}", parts.join(","))
    }

    /// Render a counter metric
    fn render_counter(
        &self,
        output: &mut String,
        name: &str,
        counter: &CounterSnapshot,
    ) -> Result<()> {
        let full_name = self.full_name(name);
        let labels = self.format_labels(&[]);

        // HELP and TYPE metadata
        writeln!(
            output,
            "# HELP {} Total count of {}",
            full_name,
            name.replace('_', " ")
        )
        .map_err(|e| Problem::OperationFailed(format!("metrics render failed: {e}")))?;

        writeln!(output, "# TYPE {} counter", full_name)
            .map_err(|e| Problem::OperationFailed(format!("metrics render failed: {e}")))?;

        // Metric value
        writeln!(output, "{}{} {}", full_name, labels, counter.value)
            .map_err(|e| Problem::OperationFailed(format!("metrics render failed: {e}")))?;

        Ok(())
    }

    /// Render a gauge metric
    fn render_gauge(&self, output: &mut String, name: &str, gauge: &GaugeSnapshot) -> Result<()> {
        let full_name = self.full_name(name);
        let labels = self.format_labels(&[]);

        // HELP and TYPE metadata
        writeln!(
            output,
            "# HELP {} Current value of {}",
            full_name,
            name.replace('_', " ")
        )
        .map_err(|e| Problem::OperationFailed(format!("metrics render failed: {e}")))?;

        writeln!(output, "# TYPE {} gauge", full_name)
            .map_err(|e| Problem::OperationFailed(format!("metrics render failed: {e}")))?;

        // Metric value
        writeln!(output, "{}{} {}", full_name, labels, gauge.value)
            .map_err(|e| Problem::OperationFailed(format!("metrics render failed: {e}")))?;

        Ok(())
    }

    /// Render a histogram metric
    fn render_histogram(
        &self,
        output: &mut String,
        name: &str,
        histogram: &HistogramSnapshot,
    ) -> Result<()> {
        let full_name = self.full_name(name);

        // HELP and TYPE metadata
        writeln!(
            output,
            "# HELP {} Distribution of {}",
            full_name,
            name.replace('_', " ")
        )
        .map_err(|e| Problem::OperationFailed(format!("metrics render failed: {e}")))?;

        writeln!(output, "# TYPE {} histogram", full_name)
            .map_err(|e| Problem::OperationFailed(format!("metrics render failed: {e}")))?;

        // Standard Prometheus histogram buckets
        // We approximate bucket counts from percentiles
        let buckets = self.calculate_buckets(histogram);

        for (le, count) in &buckets {
            let labels = self.format_labels(&[("le", le)]);
            writeln!(output, "{}_bucket{} {}", full_name, labels, count)
                .map_err(|e| Problem::OperationFailed(format!("metrics render failed: {e}")))?;
        }

        // Sum and count
        let labels = self.format_labels(&[]);
        writeln!(output, "{}_sum{} {}", full_name, labels, histogram.sum)
            .map_err(|e| Problem::OperationFailed(format!("metrics render failed: {e}")))?;
        writeln!(output, "{}_count{} {}", full_name, labels, histogram.count)
            .map_err(|e| Problem::OperationFailed(format!("metrics render failed: {e}")))?;

        Ok(())
    }

    /// Calculate bucket counts from histogram snapshot
    ///
    /// Since we store percentiles rather than actual bucket counts,
    /// we approximate based on the percentile values.
    fn calculate_buckets(&self, histogram: &HistogramSnapshot) -> Vec<(String, u64)> {
        // Standard Prometheus bucket boundaries
        let boundaries: &[f64] = &[
            0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
        ];

        let mut buckets = Vec::new();
        let count = histogram.count;

        // Estimate bucket counts based on percentiles
        for &le in boundaries {
            let estimated_count = if le >= histogram.max {
                count
            } else if le >= histogram.p99 {
                (count as f64 * 0.99) as u64
            } else if le >= histogram.p95 {
                (count as f64 * 0.95) as u64
            } else if le >= histogram.p90 {
                (count as f64 * 0.90) as u64
            } else if le >= histogram.p75 {
                (count as f64 * 0.75) as u64
            } else if le >= histogram.p50 {
                (count as f64 * 0.50) as u64
            } else if le >= histogram.min {
                1
            } else {
                0
            };

            buckets.push((format!("{}", le), estimated_count));
        }

        // +Inf bucket always contains all observations
        buckets.push(("+Inf".to_string(), count));

        buckets
    }
}

impl Default for PrometheusExporter {
    fn default() -> Self {
        Self::new(PrometheusConfig::default())
    }
}

/// Escape a label value for Prometheus
fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_prometheus_config_builder() {
        let config = PrometheusConfig::new()
            .namespace("myapp")
            .subsystem("api")
            .with_timestamps();

        assert_eq!(config.namespace, Some("myapp".to_string()));
        assert_eq!(config.subsystem, Some("api".to_string()));
        assert!(config.include_timestamps);
    }

    #[test]
    fn test_full_name() {
        let exporter =
            PrometheusExporter::new(PrometheusConfig::new().namespace("myapp").subsystem("api"));

        assert_eq!(exporter.full_name("requests"), "myapp_api_requests");
        assert_eq!(
            exporter.full_name("response.time"),
            "myapp_api_response_time"
        );
    }

    #[test]
    fn test_full_name_no_prefix() {
        let exporter = PrometheusExporter::default();
        assert_eq!(exporter.full_name("requests"), "requests");
    }

    #[test]
    fn test_format_labels() {
        let exporter = PrometheusExporter::new(
            PrometheusConfig::new().default_labels(DefaultLabels::new().environment("prod")),
        );

        let labels = exporter.format_labels(&[("method", "GET")]);
        assert!(labels.contains("env=\"prod\""));
        assert!(labels.contains("method=\"GET\""));
    }

    #[test]
    fn test_format_labels_empty() {
        let exporter = PrometheusExporter::default();
        let labels = exporter.format_labels(&[]);
        assert_eq!(labels, "");
    }

    #[test]
    fn test_render_counter() {
        let exporter = PrometheusExporter::new(PrometheusConfig::new().namespace("test"));

        let counter = CounterSnapshot {
            name: "requests".to_string(),
            value: 42,
            rate_per_second: 1.5,
            created_at: std::time::Instant::now(),
        };

        let mut output = String::new();
        exporter
            .render_counter(&mut output, "requests", &counter)
            .expect("render should succeed");

        assert!(output.contains("# TYPE test_requests counter"));
        assert!(output.contains("test_requests 42"));
    }

    #[test]
    fn test_render_gauge() {
        let exporter = PrometheusExporter::new(PrometheusConfig::new().namespace("test"));

        let gauge = GaugeSnapshot {
            name: "queue_depth".to_string(),
            value: 100,
            min: 0,
            max: 150,
            last_updated: std::time::Instant::now(),
        };

        let mut output = String::new();
        exporter
            .render_gauge(&mut output, "queue_depth", &gauge)
            .expect("render should succeed");

        assert!(output.contains("# TYPE test_queue_depth gauge"));
        assert!(output.contains("test_queue_depth 100"));
    }

    #[test]
    fn test_render_histogram() {
        let exporter = PrometheusExporter::new(PrometheusConfig::new().namespace("test"));

        let histogram = HistogramSnapshot {
            name: "response_time".to_string(),
            count: 100,
            sum: 25.0,
            mean: 0.25,
            min: 0.01,
            max: 1.5,
            p50: 0.2,
            p75: 0.3,
            p90: 0.5,
            p95: 0.8,
            p99: 1.2,
        };

        let mut output = String::new();
        exporter
            .render_histogram(&mut output, "response_time", &histogram)
            .expect("render should succeed");

        assert!(output.contains("# TYPE test_response_time histogram"));
        assert!(output.contains("test_response_time_bucket{le=\"+Inf\"} 100"));
        assert!(output.contains("test_response_time_sum 25"));
        assert!(output.contains("test_response_time_count 100"));
    }

    #[test]
    fn test_escape_label_value() {
        assert_eq!(escape_label_value("simple"), "simple");
        assert_eq!(escape_label_value("with\"quote"), "with\\\"quote");
        assert_eq!(escape_label_value("with\\slash"), "with\\\\slash");
        assert_eq!(escape_label_value("with\nnewline"), "with\\nnewline");
    }
}

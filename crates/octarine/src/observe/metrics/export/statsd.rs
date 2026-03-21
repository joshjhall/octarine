//! StatsD metrics writer
//!
//! Sends metrics via UDP in DogStatsD-compatible format.

use std::io;
use std::net::UdpSocket;
use std::sync::Arc;

use super::DefaultLabels;
use crate::observe::metrics::MetricSnapshot;

/// Configuration for the StatsD writer
#[derive(Debug, Clone)]
pub struct StatsDConfig {
    /// Host to send metrics to
    pub host: String,
    /// Port to send metrics to
    pub port: u16,
    /// Prefix for all metric names
    pub prefix: Option<String>,
    /// Default labels/tags for all metrics
    pub default_labels: DefaultLabels,
    /// Sample rate for metrics (0.0 to 1.0)
    pub sample_rate: f64,
    /// Maximum packet size (MTU)
    pub max_packet_size: usize,
}

impl Default for StatsDConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8125,
            prefix: None,
            default_labels: DefaultLabels::default(),
            sample_rate: 1.0,
            max_packet_size: 1432, // Safe for most networks
        }
    }
}

impl StatsDConfig {
    /// Create a new StatsDConfig
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            ..Default::default()
        }
    }

    /// Set the metric prefix
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Set default labels
    pub fn default_labels(mut self, labels: DefaultLabels) -> Self {
        self.default_labels = labels;
        self
    }

    /// Set the sample rate
    pub fn sample_rate(mut self, rate: f64) -> Self {
        self.sample_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Set max packet size
    pub fn max_packet_size(mut self, size: usize) -> Self {
        self.max_packet_size = size;
        self
    }
}

/// StatsD metrics writer
///
/// Sends metrics via UDP in DogStatsD-compatible format.
///
/// # Example
///
/// ```rust,no_run
/// use octarine::observe::metrics::{StatsDWriter, StatsDConfig, DefaultLabels};
///
/// let config = StatsDConfig::new("localhost", 8125)
///     .prefix("myapp")
///     .default_labels(DefaultLabels::new().environment("prod"));
///
/// let writer = StatsDWriter::new(config);
/// writer.counter("api.requests", 1, &[("method", "GET")]);
/// writer.gauge("queue.depth", 42, &[]);
/// writer.timing("response.time", 150, &[]);
/// ```
pub struct StatsDWriter {
    config: StatsDConfig,
    socket: Arc<Option<UdpSocket>>,
}

impl StatsDWriter {
    /// Create a new StatsD writer
    pub fn new(config: StatsDConfig) -> Self {
        let socket = Self::create_socket(&config);
        Self {
            config,
            socket: Arc::new(socket),
        }
    }

    /// Create a UDP socket for sending metrics
    fn create_socket(config: &StatsDConfig) -> Option<UdpSocket> {
        UdpSocket::bind("0.0.0.0:0")
            .and_then(|socket| {
                socket.connect(format!("{}:{}", config.host, config.port))?;
                socket.set_nonblocking(true)?;
                Ok(socket)
            })
            .ok()
    }

    /// Get the full metric name with prefix
    fn full_name(&self, name: &str) -> String {
        match &self.config.prefix {
            Some(prefix) => format!("{}.{}", prefix, name),
            None => name.to_string(),
        }
    }

    /// Format tags including default labels
    fn format_tags(&self, additional: &[(&str, &str)]) -> String {
        let default_tags = self.config.default_labels.format_statsd();

        if additional.is_empty() {
            return default_tags;
        }

        let additional_tags: Vec<String> = additional
            .iter()
            .map(|(k, v)| format!("{}:{}", escape_tag(k), escape_tag(v)))
            .collect();

        if default_tags.is_empty() {
            format!("|#{}", additional_tags.join(","))
        } else {
            format!("{},{}", default_tags, additional_tags.join(","))
        }
    }

    /// Format the sample rate suffix
    fn sample_rate_suffix(&self) -> String {
        if (self.config.sample_rate - 1.0).abs() < f64::EPSILON {
            String::new()
        } else {
            format!("|@{}", self.config.sample_rate)
        }
    }

    /// Send a metric message
    fn send(&self, message: &str) -> io::Result<()> {
        if let Some(ref socket) = *self.socket {
            socket.send(message.as_bytes())?;
        }
        Ok(())
    }

    /// Send a counter metric
    ///
    /// Counters track how many times something happened per second.
    pub fn counter(&self, name: &str, value: i64, tags: &[(&str, &str)]) {
        let msg = format!(
            "{}:{}|c{}{}",
            self.full_name(name),
            value,
            self.sample_rate_suffix(),
            self.format_tags(tags)
        );
        let _ = self.send(&msg);
    }

    /// Send a gauge metric
    ///
    /// Gauges track the current value of something.
    pub fn gauge(&self, name: &str, value: i64, tags: &[(&str, &str)]) {
        let msg = format!(
            "{}:{}|g{}",
            self.full_name(name),
            value,
            self.format_tags(tags)
        );
        let _ = self.send(&msg);
    }

    /// Send a timing metric (milliseconds)
    ///
    /// Timings track how long something took.
    pub fn timing(&self, name: &str, ms: u64, tags: &[(&str, &str)]) {
        let msg = format!(
            "{}:{}|ms{}{}",
            self.full_name(name),
            ms,
            self.sample_rate_suffix(),
            self.format_tags(tags)
        );
        let _ = self.send(&msg);
    }

    /// Send a histogram metric
    ///
    /// Histograms track the distribution of values (DogStatsD extension).
    pub fn histogram(&self, name: &str, value: f64, tags: &[(&str, &str)]) {
        let msg = format!(
            "{}:{}|h{}{}",
            self.full_name(name),
            value,
            self.sample_rate_suffix(),
            self.format_tags(tags)
        );
        let _ = self.send(&msg);
    }

    /// Send a distribution metric
    ///
    /// Distributions are similar to histograms (DogStatsD extension).
    pub fn distribution(&self, name: &str, value: f64, tags: &[(&str, &str)]) {
        let msg = format!(
            "{}:{}|d{}{}",
            self.full_name(name),
            value,
            self.sample_rate_suffix(),
            self.format_tags(tags)
        );
        let _ = self.send(&msg);
    }

    /// Send a set metric
    ///
    /// Sets count unique occurrences.
    pub fn set(&self, name: &str, value: &str, tags: &[(&str, &str)]) {
        let msg = format!(
            "{}:{}|s{}",
            self.full_name(name),
            value,
            self.format_tags(tags)
        );
        let _ = self.send(&msg);
    }

    /// Export a full metrics snapshot
    pub fn export_snapshot(&self, snapshot: &MetricSnapshot) {
        // Export counters
        for (name, counter) in &snapshot.counters {
            self.counter(name, counter.value as i64, &[]);
        }

        // Export gauges
        for (name, gauge) in &snapshot.gauges {
            self.gauge(name, gauge.value, &[]);
        }

        // Export histograms (as timing based on mean)
        for (name, histogram) in &snapshot.histograms {
            // Send various percentile values
            self.histogram(&format!("{}.p50", name), histogram.p50, &[]);
            self.histogram(&format!("{}.p90", name), histogram.p90, &[]);
            self.histogram(&format!("{}.p99", name), histogram.p99, &[]);
        }
    }

    /// Export current metrics from the global registry
    pub fn export(&self) {
        let snapshot = crate::observe::metrics::snapshot();
        self.export_snapshot(&snapshot);
    }

    /// Flush any pending metrics (no-op for UDP, included for API consistency)
    pub fn flush(&self) -> io::Result<()> {
        // UDP is connectionless, no flushing needed
        Ok(())
    }
}

impl Clone for StatsDWriter {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            socket: Arc::clone(&self.socket),
        }
    }
}

/// Escape a tag key or value for StatsD
fn escape_tag(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_statsd_config_builder() {
        let config = StatsDConfig::new("localhost", 8125)
            .prefix("myapp")
            .sample_rate(0.5)
            .max_packet_size(1400);

        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 8125);
        assert_eq!(config.prefix, Some("myapp".to_string()));
        assert!((config.sample_rate - 0.5).abs() < f64::EPSILON);
        assert_eq!(config.max_packet_size, 1400);
    }

    #[test]
    fn test_sample_rate_clamping() {
        let config = StatsDConfig::default().sample_rate(1.5);
        assert!((config.sample_rate - 1.0).abs() < f64::EPSILON);

        let config = StatsDConfig::default().sample_rate(-0.5);
        assert!((config.sample_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_full_name() {
        let writer = StatsDWriter::new(StatsDConfig::default().prefix("myapp"));
        assert_eq!(writer.full_name("requests"), "myapp.requests");

        let writer_no_prefix = StatsDWriter::new(StatsDConfig::default());
        assert_eq!(writer_no_prefix.full_name("requests"), "requests");
    }

    #[test]
    fn test_format_tags() {
        let writer = StatsDWriter::new(
            StatsDConfig::default().default_labels(DefaultLabels::new().environment("prod")),
        );

        let tags = writer.format_tags(&[("method", "GET")]);
        assert!(tags.contains("|#"));
        assert!(tags.contains("env:prod"));
        assert!(tags.contains("method:GET"));
    }

    #[test]
    fn test_format_tags_empty() {
        let writer = StatsDWriter::new(StatsDConfig::default());
        let tags = writer.format_tags(&[]);
        assert_eq!(tags, "");
    }

    #[test]
    fn test_sample_rate_suffix() {
        let writer_full = StatsDWriter::new(StatsDConfig::default());
        assert_eq!(writer_full.sample_rate_suffix(), "");

        let writer_sampled = StatsDWriter::new(StatsDConfig::default().sample_rate(0.5));
        assert_eq!(writer_sampled.sample_rate_suffix(), "|@0.5");
    }

    #[test]
    fn test_escape_tag() {
        assert_eq!(escape_tag("valid_tag"), "valid_tag");
        assert_eq!(escape_tag("tag-with-dashes"), "tag-with-dashes");
        assert_eq!(escape_tag("tag.with.dots"), "tag.with.dots");
        assert_eq!(escape_tag("tag with spaces"), "tagwithspaces");
        assert_eq!(escape_tag("tag:with:colons"), "tagwithcolons");
    }

    #[test]
    fn test_writer_clone() {
        let writer = StatsDWriter::new(StatsDConfig::default());
        let cloned = writer.clone();

        assert_eq!(cloned.config.host, writer.config.host);
        assert_eq!(cloned.config.port, writer.config.port);
    }
}

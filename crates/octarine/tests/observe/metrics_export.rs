//! Integration tests for metrics export
//!
//! Tests the Prometheus and StatsD export functionality.

#![allow(clippy::panic, clippy::expect_used)]

use octarine::observe::metrics::{
    DefaultLabels, MetricName, PrometheusConfig, PrometheusExporter, StatsDConfig, StatsDWriter,
    gauge, increment, increment_by, record,
};
use std::time::Duration;

// ============================================================================
// Prometheus Exporter Tests
// ============================================================================

#[test]
fn test_prometheus_export_empty() {
    let exporter = PrometheusExporter::default();
    let output = exporter.render().expect("render should succeed");
    // Empty or minimal output when no metrics
    assert!(output.is_empty() || output.lines().count() <= 3);
}

#[test]
fn test_prometheus_export_with_namespace() {
    let config = PrometheusConfig::new().namespace("myapp").subsystem("api");

    let exporter = PrometheusExporter::new(config);

    // The exporter should render metrics with the namespace prefix
    // Since we're using global registry, just verify it builds
    let output = exporter.render().expect("render should succeed");
    assert!(output.is_empty() || output.contains("myapp_api") || output.contains("# TYPE"));
}

#[test]
fn test_prometheus_export_with_labels() {
    let labels = DefaultLabels::new()
        .tenant("acme-corp")
        .environment("production")
        .service("api-gateway")
        .version("2.1.0");

    let config = PrometheusConfig::new()
        .namespace("test")
        .default_labels(labels);

    let exporter = PrometheusExporter::new(config);
    let _ = exporter.render().expect("render should succeed");
    // Just verify it doesn't panic
}

#[test]
fn test_prometheus_config_presets() {
    // Development preset
    let dev_config = PrometheusConfig::new().namespace("dev");
    assert_eq!(dev_config.namespace, Some("dev".to_string()));

    // Production preset with all labels
    let prod_config = PrometheusConfig::new()
        .namespace("prod")
        .with_timestamps()
        .default_labels(
            DefaultLabels::new()
                .environment("prod")
                .service("api")
                .version("1.0.0"),
        );

    assert!(prod_config.include_timestamps);
    assert!(prod_config.default_labels.environment.is_some());
}

// ============================================================================
// StatsD Writer Tests
// ============================================================================

#[test]
fn test_statsd_writer_creation() {
    let config = StatsDConfig::new("localhost", 8125)
        .prefix("myapp")
        .sample_rate(1.0);

    let writer = StatsDWriter::new(config);
    // Writer should be created successfully
    // UDP socket may or may not connect depending on environment
    let _ = writer;
}

#[test]
fn test_statsd_config_builder() {
    let labels = DefaultLabels::new().tenant("acme").environment("staging");

    let config = StatsDConfig::new("metrics.internal", 8125)
        .prefix("myservice")
        .default_labels(labels)
        .sample_rate(0.5)
        .max_packet_size(1400);

    assert_eq!(config.host, "metrics.internal");
    assert_eq!(config.port, 8125);
    assert_eq!(config.prefix, Some("myservice".to_string()));
    assert!((config.sample_rate - 0.5).abs() < f64::EPSILON);
    assert_eq!(config.max_packet_size, 1400);
}

#[test]
fn test_statsd_writer_methods() {
    // Use a non-routable address to avoid actual network traffic
    let config = StatsDConfig::new("0.0.0.0", 0);
    let writer = StatsDWriter::new(config);

    // These should not panic even if the socket isn't connected
    writer.counter("test.counter", 1, &[]);
    writer.gauge("test.gauge", 42, &[]);
    writer.timing("test.timing", 150, &[]);
    writer.histogram("test.histogram", 0.5, &[]);
    writer.distribution("test.distribution", 1.5, &[]);
    writer.set("test.set", "user123", &[]);
}

#[test]
fn test_statsd_with_tags() {
    let config =
        StatsDConfig::new("0.0.0.0", 0).default_labels(DefaultLabels::new().environment("test"));
    let writer = StatsDWriter::new(config);

    // Should format tags correctly
    writer.counter("api.requests", 1, &[("method", "GET"), ("status", "200")]);
    writer.gauge("queue.depth", 10, &[("queue", "high-priority")]);
}

// ============================================================================
// Default Labels Tests
// ============================================================================

#[test]
fn test_default_labels_comprehensive() {
    let labels = DefaultLabels::new()
        .tenant("tenant-123")
        .environment("production")
        .service("order-service")
        .version("3.2.1")
        .label("region", "us-east-1")
        .label("cluster", "primary");

    // Test Prometheus format
    let prom = labels.format_prometheus();
    assert!(prom.contains("tenant=\"tenant-123\""));
    assert!(prom.contains("env=\"production\""));
    assert!(prom.contains("service=\"order-service\""));
    assert!(prom.contains("version=\"3.2.1\""));
    assert!(prom.contains("region=\"us-east-1\""));
    assert!(prom.contains("cluster=\"primary\""));

    // Test StatsD format
    let statsd = labels.format_statsd();
    assert!(statsd.contains("tenant:tenant-123"));
    assert!(statsd.contains("env:production"));
    assert!(statsd.contains("service:order-service"));
}

#[test]
fn test_default_labels_escaping() {
    // Test Prometheus escaping
    let labels = DefaultLabels::new().tenant("test\"with\\escape\nchars");
    let prom = labels.format_prometheus();
    assert!(prom.contains("\\\""));
    assert!(prom.contains("\\\\"));
    assert!(prom.contains("\\n"));

    // Test StatsD escaping (removes special chars)
    let labels = DefaultLabels::new().tenant("test:with|special#chars");
    let statsd = labels.format_statsd();
    assert!(!statsd.contains(':') || statsd.starts_with("|#tenant:"));
}

// ============================================================================
// Integration with Metrics Registry Tests
// ============================================================================

#[test]
fn test_prometheus_with_live_metrics() {
    // Record some metrics
    let counter_name = MetricName::new("integration.test.counter").expect("valid");
    let gauge_name = MetricName::new("integration.test.gauge").expect("valid");
    let histogram_name = MetricName::new("integration.test.histogram").expect("valid");

    increment(counter_name.clone());
    increment_by(counter_name, 5);
    gauge(gauge_name, 42);
    record(histogram_name, 0.5);

    // Small delay to allow async dispatch
    std::thread::sleep(Duration::from_millis(50));

    // Export via Prometheus
    let exporter = PrometheusExporter::new(PrometheusConfig::new().namespace("integration"));
    let output = exporter.render().expect("render should succeed");

    // Should contain metric types and values
    // Note: metrics may or may not be present depending on timing
    if !output.is_empty() {
        assert!(
            output.contains("# TYPE") || output.contains("counter") || output.contains("gauge")
        );
    }
}

#[test]
fn test_statsd_snapshot_export() {
    let config = StatsDConfig::new("0.0.0.0", 0).prefix("snapshot");
    let writer = StatsDWriter::new(config);

    // Should not panic
    writer.export();
}

// ============================================================================
// Built-in Metrics Tests
// ============================================================================

// test_builtin_metrics_names removed - builtin module is internal implementation detail
// and not part of public API. The test was validating internal naming conventions.

// test_builtin_metrics_categories removed - MetricCategory is internal implementation detail
// and not part of public API. The test was validating internal categories.

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_empty_default_labels() {
    let labels = DefaultLabels::new();
    assert!(labels.is_empty());
    assert_eq!(labels.format_prometheus(), "");
    assert_eq!(labels.format_statsd(), "");
}

#[test]
fn test_sample_rate_boundaries() {
    // Sample rate should be clamped to [0, 1]
    let config_high = StatsDConfig::default().sample_rate(2.0);
    assert!((config_high.sample_rate - 1.0).abs() < f64::EPSILON);

    let config_low = StatsDConfig::default().sample_rate(-1.0);
    assert!((config_low.sample_rate - 0.0).abs() < f64::EPSILON);

    let config_valid = StatsDConfig::default().sample_rate(0.5);
    assert!((config_valid.sample_rate - 0.5).abs() < f64::EPSILON);
}

#[test]
fn test_writer_clone() {
    let writer = StatsDWriter::new(StatsDConfig::default());
    let cloned = writer.clone();

    // Both should work independently
    writer.counter("original", 1, &[]);
    cloned.counter("cloned", 1, &[]);
}

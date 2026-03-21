//! Prometheus metrics export example
//!
//! This example demonstrates:
//! - Counter, gauge, and histogram metrics
//! - Timer-based duration tracking
//! - Prometheus text format export
//! - Metric labeling patterns

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::arithmetic_side_effects
)]

use octarine::observe::metrics::{
    MetricName, gauge, increment, increment_by, record, snapshot, time_fn, timer,
};
use std::thread;
use std::time::Duration;

/// Simulate processing requests with metrics
fn process_request(endpoint: &str, success: bool) {
    // Increment request counter
    let requests = MetricName::new("http.requests.total").unwrap();
    increment(requests);

    // Track request by endpoint (in production, use labels)
    let endpoint_metric = MetricName::new(format!("http.requests.{}", endpoint)).unwrap();
    increment(endpoint_metric);

    // Track success/failure
    if success {
        let success_metric = MetricName::new("http.requests.success").unwrap();
        increment(success_metric);
    } else {
        let errors = MetricName::new("http.requests.errors").unwrap();
        increment(errors);
    }
}

/// Simulate tracking active connections
fn update_connection_metric_gauge(active: i64) {
    let connections = MetricName::new("tcp.connections.active").unwrap();
    gauge(connections, active);
}

/// Simulate tracking queue depth
fn update_queue_depth(depth: i64) {
    let queue = MetricName::new("job.queue.depth").unwrap();
    gauge(queue, depth);
}

/// Simulate recording response sizes
fn record_response_size(bytes: f64) {
    let size = MetricName::new("http.response.size.bytes").unwrap();
    record(size, bytes);
}

/// Simulate recording response times
fn record_response_time(duration_ms: f64) {
    let latency = MetricName::new("http.response.latency.ms").unwrap();
    record(latency, duration_ms);
}

/// Demonstrate timer-based metrics
fn timed_operation() {
    // Timer automatically records duration on drop
    let _timer = timer("db.query.duration");

    // Simulate database query
    thread::sleep(Duration::from_millis(50));

    // Timer records when dropped
}

/// Demonstrate time_fn for inline timing
fn inline_timed_operation() -> i32 {
    time_fn("compute.intensive", || {
        // Simulate computation
        thread::sleep(Duration::from_millis(25));
        42
    })
}

/// Format metrics in Prometheus text format
fn format_prometheus_text() -> String {
    let snap = snapshot();
    let mut output = String::new();

    // Format counters
    output.push_str("# HELP http_requests_total Total HTTP requests\n");
    output.push_str("# TYPE http_requests_total counter\n");

    for (name, counter) in &snap.counters {
        let prometheus_name = name.replace('.', "_");
        output.push_str(&format!("{} {}\n", prometheus_name, counter.value));
    }

    output.push('\n');

    // Format gauges
    output.push_str("# HELP active_connections Current active connections\n");
    output.push_str("# TYPE active_connections gauge\n");

    for (name, gauge_val) in &snap.gauges {
        let prometheus_name = name.replace('.', "_");
        output.push_str(&format!("{} {}\n", prometheus_name, gauge_val.value));
    }

    output.push('\n');

    // Format histograms
    output.push_str("# HELP http_response_size_bytes Response size distribution\n");
    output.push_str("# TYPE http_response_size_bytes histogram\n");

    for (name, histogram) in &snap.histograms {
        let prometheus_name = name.replace('.', "_");

        // Bucket boundaries (example: standard latency buckets)
        let buckets = [
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ];
        for bucket in &buckets {
            // In production, calculate actual bucket counts
            output.push_str(&format!(
                "{}_bucket{{le=\"{}\"}} {}\n",
                prometheus_name, bucket, histogram.count
            ));
        }
        output.push_str(&format!(
            "{}_bucket{{le=\"+Inf\"}} {}\n",
            prometheus_name, histogram.count
        ));
        output.push_str(&format!("{}_sum {}\n", prometheus_name, histogram.sum));
        output.push_str(&format!("{}_count {}\n", prometheus_name, histogram.count));
    }

    output
}

/// Demonstrate metric-based alerting thresholds
fn check_alerting_thresholds() {
    let snap = snapshot();

    println!("Checking alerting thresholds...\n");

    // Check error rate
    let total = snap
        .counters
        .get("http.requests.total")
        .map(|c| c.value)
        .unwrap_or(0);

    let errors = snap
        .counters
        .get("http.requests.errors")
        .map(|c| c.value)
        .unwrap_or(0);

    if total > 0 {
        let error_rate = (errors as f64 / total as f64) * 100.0;
        println!("  Error rate: {:.2}%", error_rate);

        if error_rate > 5.0 {
            println!("  ALERT: Error rate exceeds 5% threshold!");
        }
    }

    // Check connection count
    let connections = snap
        .gauges
        .get("tcp.connections.active")
        .map(|g| g.value)
        .unwrap_or(0);

    println!("  Active connections: {}", connections);

    if connections > 100 {
        println!("  ALERT: Connection count exceeds 100!");
    }

    // Check queue depth
    let queue_depth = snap
        .gauges
        .get("job.queue.depth")
        .map(|g| g.value)
        .unwrap_or(0);

    println!("  Queue depth: {}", queue_depth);

    if queue_depth > 1000 {
        println!("  ALERT: Queue depth exceeds 1000!");
    }
}

fn main() {
    println!("=== Observe Module Prometheus Metrics Example ===\n");

    // 1. Counter metrics
    println!("--- Counter Metrics ---\n");

    println!("Processing simulated requests...");
    for i in 0..10 {
        let success = i % 3 != 0; // 30% error rate for demo
        let endpoint = if i % 2 == 0 { "api" } else { "health" };
        process_request(endpoint, success);
    }
    println!("Processed 10 requests\n");

    // 2. Gauge metrics
    println!("--- Gauge Metrics ---\n");

    update_connection_metric_gauge(42);
    println!("Active connections: 42");

    update_queue_depth(150);
    println!("Queue depth: 150\n");

    // 3. Histogram metrics
    println!("--- Histogram Metrics ---\n");

    println!("Recording response sizes...");
    for size in [1024.0, 2048.0, 512.0, 4096.0, 768.0] {
        record_response_size(size);
    }

    println!("Recording response times...");
    for latency in [10.5, 25.3, 5.2, 100.1, 15.7] {
        record_response_time(latency);
    }
    println!();

    // 4. Timer metrics
    println!("--- Timer Metrics ---\n");

    println!("Running timed database query...");
    timed_operation();
    println!("Query completed\n");

    println!("Running inline timed computation...");
    let result = inline_timed_operation();
    println!("Computation result: {}\n", result);

    // 5. Increment by specific amount
    println!("--- Batch Increments ---\n");

    let batch_processed = MetricName::new("jobs.batch.processed").unwrap();
    increment_by(batch_processed, 100);
    println!("Incremented batch counter by 100\n");

    // 6. Prometheus export format
    println!("--- Prometheus Text Format ---\n");

    let prometheus_output = format_prometheus_text();
    println!("{}", prometheus_output);

    // 7. Alerting thresholds
    println!("--- Alerting Thresholds ---\n");

    check_alerting_thresholds();

    // 8. Metric snapshot summary
    println!("\n--- Metrics Snapshot ---\n");

    let snap = snapshot();

    println!("Counters:");
    for (name, counter) in &snap.counters {
        println!("  {}: {}", name, counter.value);
    }

    println!("\nGauges:");
    for (name, gauge_val) in &snap.gauges {
        println!("  {}: {}", name, gauge_val.value);
    }

    println!("\nHistograms:");
    for (name, histogram) in &snap.histograms {
        println!(
            "  {}: count={}, sum={:.2}, min={:.2}, max={:.2}",
            name, histogram.count, histogram.sum, histogram.min, histogram.max
        );
    }

    // 9. Best practices
    println!("\n--- Prometheus Best Practices ---\n");
    println!("1. Use consistent naming: snake_case with units as suffix");
    println!("2. Include units in metric names (bytes, seconds, total)");
    println!("3. Use counters for things that only increase");
    println!("4. Use gauges for values that go up and down");
    println!("5. Use histograms for request durations and sizes");
    println!("6. Add HELP and TYPE annotations for documentation");
    println!("7. Use labels sparingly - high cardinality causes issues");
    println!("8. Set appropriate histogram bucket boundaries");

    println!("\n=== Example Complete ===");
}

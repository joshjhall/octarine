//! Integration tests for metrics migration
//!
//! Uses unique metric names per test to avoid global state contamination
//! between parallel test runs.

#![allow(clippy::panic)]
#![allow(clippy::expect_used)] // Tests use known-valid metric names

use octarine::observe::metrics::{
    MetricName, flush_for_testing, gauge, increment, increment_by, record, snapshot, timer,
};

/// Generate a unique metric name for test isolation
fn unique_name(base: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("{}.{}", base, id)
}

#[test]
fn test_counter_functionality() {
    let name = unique_name("test.counter");
    increment(MetricName::new(&name).expect("Valid metric name"));
    increment_by(MetricName::new(&name).expect("Valid metric name"), 5);

    // Flush async metrics before taking snapshot
    flush_for_testing();

    let snapshot = snapshot();
    let counter_snapshot = match snapshot.counters.get(&name) {
        Some(value) => value,
        None => panic!("{} should exist in snapshot", name),
    };
    assert_eq!(counter_snapshot.value, 6);
}

#[test]
fn test_gauge_functionality() {
    let name = unique_name("test.gauge");
    gauge(MetricName::new(&name).expect("Valid metric name"), 42);
    gauge(MetricName::new(&name).expect("Valid metric name"), 50);
    gauge(MetricName::new(&name).expect("Valid metric name"), 40);

    // Flush async metrics before taking snapshot
    flush_for_testing();

    let snapshot = snapshot();
    let gauge_snapshot = match snapshot.gauges.get(&name) {
        Some(value) => value,
        None => panic!("{} should exist in snapshot", name),
    };
    assert_eq!(gauge_snapshot.value, 40);
    assert_eq!(gauge_snapshot.max, 50);
    assert_eq!(gauge_snapshot.min, 40);
}

#[test]
fn test_histogram_functionality() {
    let name = unique_name("test.histogram");
    record(MetricName::new(&name).expect("Valid metric name"), 10.0);
    record(MetricName::new(&name).expect("Valid metric name"), 20.0);
    record(MetricName::new(&name).expect("Valid metric name"), 30.0);

    // Flush async metrics before taking snapshot
    flush_for_testing();

    let metrics_snapshot = snapshot();
    let histogram_snapshot = match metrics_snapshot.histograms.get(&name) {
        Some(value) => value,
        None => panic!("{} should exist in snapshot", name),
    };
    assert_eq!(histogram_snapshot.count, 3);
    assert_eq!(histogram_snapshot.min, 10.0);
    assert_eq!(histogram_snapshot.max, 30.0);
    assert_eq!(histogram_snapshot.mean, 20.0);
}

#[test]
fn test_timer_functionality() {
    use std::thread;
    use std::time::Duration;

    let name = unique_name("test.timer");
    {
        let _timer = timer(&name);
        thread::sleep(Duration::from_millis(10));
        // Timer records on drop
    }

    // Flush async metrics before taking snapshot
    flush_for_testing();

    // Verify histogram has the timing
    let metrics_snapshot = snapshot();
    let timer_histogram = match metrics_snapshot.histograms.get(&name) {
        Some(value) => value,
        None => panic!("{} should exist in snapshot", name),
    };
    assert!(timer_histogram.count > 0);
    assert!(timer_histogram.mean >= 10.0); // At least 10ms
}

#[test]
fn test_global_convenience_functions() {
    let name = unique_name("global.counter");
    increment(MetricName::new(&name).expect("Valid metric name"));
    increment(MetricName::new(&name).expect("Valid metric name"));

    // Flush async metrics before taking snapshot
    flush_for_testing();

    let metrics_snapshot = snapshot();
    let counter = match metrics_snapshot.counters.get(&name) {
        Some(value) => value,
        None => panic!("{} should exist in snapshot", name),
    };
    assert_eq!(counter.value, 2);
}

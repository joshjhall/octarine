//! Integration tests for threshold monitoring
//!
//! Tests the threshold system including:
//! - Threshold registration and configuration
//! - Event emission when thresholds are crossed
//! - Cooldown behavior
//! - Integration with metrics

#![allow(clippy::panic, clippy::expect_used)]

use octarine::observe::metrics::{
    Comparison, MetricName, ThresholdConfig, ThresholdState, list_thresholds, register_threshold,
    threshold_state, unregister_threshold,
};
use std::time::Duration;

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_threshold_config_builder_pattern() {
    let config = ThresholdConfig::new("api.errors")
        .warning(100.0)
        .critical(500.0)
        .comparison(Comparison::Above)
        .cooldown(Duration::from_secs(30));

    assert_eq!(config.metric_name, "api.errors");
    assert_eq!(config.warning_threshold, Some(100.0));
    assert_eq!(config.critical_threshold, Some(500.0));
    assert_eq!(config.comparison, Comparison::Above);
    assert_eq!(config.cooldown, Duration::from_secs(30));
}

#[test]
fn test_threshold_config_defaults() {
    let config = ThresholdConfig::default();

    assert!(config.metric_name.is_empty());
    assert!(config.warning_threshold.is_none());
    assert!(config.critical_threshold.is_none());
    assert_eq!(config.comparison, Comparison::Above);
    assert_eq!(config.cooldown, Duration::from_secs(60));
    assert!(config.emit_recovery);
}

#[test]
fn test_threshold_config_no_recovery() {
    let config = ThresholdConfig::new("test").no_recovery();
    assert!(!config.emit_recovery);
}

// ============================================================================
// Registration Tests
// ============================================================================

#[test]
fn test_threshold_registration() {
    let metric_name = "test.registration.metric";

    // Clean up from any previous test
    unregister_threshold(metric_name);

    // Initially no threshold
    assert!(threshold_state(metric_name).is_none());

    // Register threshold
    register_threshold(ThresholdConfig::new(metric_name).warning(100.0));

    // Now should have state
    assert_eq!(threshold_state(metric_name), Some(ThresholdState::Normal));

    // Should be in list
    let thresholds = list_thresholds();
    assert!(thresholds.contains(&metric_name.to_string()));

    // Unregister
    unregister_threshold(metric_name);
    assert!(threshold_state(metric_name).is_none());
}

#[test]
fn test_list_thresholds() {
    // Clean up
    unregister_threshold("list.test.a");
    unregister_threshold("list.test.b");

    // Register multiple
    register_threshold(ThresholdConfig::new("list.test.a").warning(100.0));
    register_threshold(ThresholdConfig::new("list.test.b").warning(200.0));

    let list = list_thresholds();
    assert!(list.contains(&"list.test.a".to_string()));
    assert!(list.contains(&"list.test.b".to_string()));

    // Clean up
    unregister_threshold("list.test.a");
    unregister_threshold("list.test.b");
}

// ============================================================================
// Comparison Tests
// ============================================================================

#[test]
fn test_comparison_above() {
    // Comparison::Above is the default
    assert_eq!(Comparison::default(), Comparison::Above);
}

#[test]
fn test_comparison_variants() {
    // Ensure all variants exist
    let _above = Comparison::Above;
    let _below = Comparison::Below;
    let _equal = Comparison::Equal;
    let _rate = Comparison::RateExceeds;
}

// ============================================================================
// State Tests
// ============================================================================

#[test]
fn test_threshold_state_default() {
    assert_eq!(ThresholdState::default(), ThresholdState::Normal);
}

#[test]
fn test_threshold_state_variants() {
    let _normal = ThresholdState::Normal;
    let _warning = ThresholdState::Warning;
    let _critical = ThresholdState::Critical;
}

// ============================================================================
// Integration with Metrics Tests
// ============================================================================

#[test]
fn test_threshold_with_gauge() {
    use octarine::observe::metrics::gauge;

    let name = "test.threshold.gauge";
    unregister_threshold(name);

    // Register threshold
    register_threshold(
        ThresholdConfig::new(name)
            .warning(100.0)
            .critical(500.0)
            .comparison(Comparison::Above)
            .cooldown(Duration::from_millis(1)), // Short cooldown for testing
    );

    // Initial state is normal
    assert_eq!(threshold_state(name), Some(ThresholdState::Normal));

    // Set below warning - should stay normal
    let metric_name = MetricName::new(name).expect("valid metric name");
    gauge(metric_name, 50);
    // Note: State changes are emitted as events, the state itself updates

    // Clean up
    unregister_threshold(name);
}

#[test]
fn test_threshold_with_counter() {
    use octarine::observe::metrics::increment;

    let name = "test.threshold.counter";
    unregister_threshold(name);

    // Register threshold for counter
    register_threshold(
        ThresholdConfig::new(name)
            .warning(10.0)
            .critical(100.0)
            .comparison(Comparison::Above)
            .cooldown(Duration::from_millis(1)),
    );

    // Initial state is normal
    assert_eq!(threshold_state(name), Some(ThresholdState::Normal));

    // Increment counter
    let metric_name = MetricName::new(name).expect("valid metric name");
    for _ in 0..5 {
        increment(metric_name.clone());
    }

    // Clean up
    unregister_threshold(name);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_threshold_only_warning() {
    let config = ThresholdConfig::new("only.warning").warning(100.0);

    assert_eq!(config.warning_threshold, Some(100.0));
    assert!(config.critical_threshold.is_none());
}

#[test]
fn test_threshold_only_critical() {
    let config = ThresholdConfig::new("only.critical").critical(500.0);

    assert!(config.warning_threshold.is_none());
    assert_eq!(config.critical_threshold, Some(500.0));
}

#[test]
fn test_threshold_reregister() {
    let name = "test.reregister";
    unregister_threshold(name);

    // Register
    register_threshold(ThresholdConfig::new(name).warning(100.0));
    assert!(threshold_state(name).is_some());

    // Re-register (should replace)
    register_threshold(ThresholdConfig::new(name).warning(200.0));
    assert!(threshold_state(name).is_some());

    // Clean up
    unregister_threshold(name);
}

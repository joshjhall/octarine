//! Threshold monitoring for metrics
//!
//! Provides configurable thresholds that emit events when metric values
//! cross defined boundaries. Supports cooldown periods to prevent alert storms.
//!
//! # Features
//!
//! - Warning and critical threshold levels
//! - Multiple comparison operators (above, below, equal, rate-based)
//! - Cooldown periods to prevent repeated alerts
//! - Recovery events when values return to normal
//! - Thread-safe concurrent access
//!
//! # Example
//!
//! ```rust
//! use octarine::observe::metrics::{register_threshold, ThresholdConfig, Comparison};
//! use std::time::Duration;
//!
//! // Alert when error rate exceeds thresholds
//! register_threshold(
//!     ThresholdConfig::new("api.errors")
//!         .warning(100.0)
//!         .critical(500.0)
//!         .comparison(Comparison::Above)
//!         .cooldown(Duration::from_secs(60))
//! );
//! ```

use crate::observe::types::{Event, EventType, Severity};
use crate::observe::writers::dispatch;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

// =============================================================================
// Configuration Types
// =============================================================================

/// How to compare metric values against thresholds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Comparison {
    /// Trigger when value is above threshold
    #[default]
    Above,
    /// Trigger when value is below threshold
    Below,
    /// Trigger when value equals threshold (with epsilon for floats)
    Equal,
    /// Trigger when rate of change exceeds threshold (per second)
    RateExceeds,
}

/// Current state of a threshold
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThresholdState {
    /// Value is within normal range
    #[default]
    Normal,
    /// Value has crossed warning threshold
    Warning,
    /// Value has crossed critical threshold
    Critical,
}

/// Configuration for a metric threshold
#[derive(Debug, Clone)]
pub struct ThresholdConfig {
    /// Name of the metric to monitor
    pub metric_name: String,

    /// Warning threshold value (optional)
    ///
    /// If set, a `ThresholdWarning` event is emitted when the value
    /// crosses this threshold (according to the comparison operator).
    pub warning_threshold: Option<f64>,

    /// Critical threshold value (optional)
    ///
    /// If set, a `ThresholdCritical` event is emitted when the value
    /// crosses this threshold. Critical should be more severe than warning.
    pub critical_threshold: Option<f64>,

    /// How to compare the metric value against thresholds
    pub comparison: Comparison,

    /// Minimum time between alerts for the same condition
    ///
    /// Prevents alert storms when a value hovers around a threshold.
    /// Default: 60 seconds
    pub cooldown: Duration,

    /// Whether to emit recovery events when value returns to normal
    ///
    /// Default: true
    pub emit_recovery: bool,
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            metric_name: String::new(),
            warning_threshold: None,
            critical_threshold: None,
            comparison: Comparison::Above,
            cooldown: Duration::from_secs(60),
            emit_recovery: true,
        }
    }
}

impl ThresholdConfig {
    /// Create a new threshold configuration for a metric
    #[must_use]
    pub fn new(metric_name: impl Into<String>) -> Self {
        Self {
            metric_name: metric_name.into(),
            ..Default::default()
        }
    }

    /// Set warning threshold (builder pattern)
    #[must_use]
    pub fn warning(mut self, threshold: f64) -> Self {
        self.warning_threshold = Some(threshold);
        self
    }

    /// Set critical threshold (builder pattern)
    #[must_use]
    pub fn critical(mut self, threshold: f64) -> Self {
        self.critical_threshold = Some(threshold);
        self
    }

    /// Set comparison operator (builder pattern)
    #[must_use]
    pub fn comparison(mut self, comparison: Comparison) -> Self {
        self.comparison = comparison;
        self
    }

    /// Set cooldown period (builder pattern)
    #[must_use]
    pub fn cooldown(mut self, duration: Duration) -> Self {
        self.cooldown = duration;
        self
    }

    /// Disable recovery events (builder pattern)
    #[must_use]
    pub fn no_recovery(mut self) -> Self {
        self.emit_recovery = false;
        self
    }
}

// =============================================================================
// Threshold State Tracking
// =============================================================================

/// Tracks the state of a single threshold
#[derive(Debug)]
struct ThresholdTracker {
    config: ThresholdConfig,
    state: ThresholdState,
    last_alert: Option<Instant>,
    last_value: Option<f64>,
    last_check: Instant,
}

impl ThresholdTracker {
    fn new(config: ThresholdConfig) -> Self {
        Self {
            config,
            state: ThresholdState::Normal,
            last_alert: None,
            last_value: None,
            last_check: Instant::now(),
        }
    }

    /// Check if a value crosses any thresholds and emit events if needed
    fn check(&mut self, value: f64) {
        let new_state = self.evaluate_state(value);
        let old_state = self.state;

        // Track rate if needed
        if self.config.comparison == Comparison::RateExceeds {
            self.last_value = Some(value);
            self.last_check = Instant::now();
        }

        // State changed
        if new_state != old_state {
            self.handle_state_change(old_state, new_state, value);
        } else if new_state != ThresholdState::Normal && self.should_re_alert() {
            // Same state but cooldown expired - re-alert
            self.emit_alert(new_state, value);
        }

        self.state = new_state;
    }

    /// Evaluate which state the current value represents
    fn evaluate_state(&self, value: f64) -> ThresholdState {
        // Check critical first (more severe)
        if let Some(critical) = self.config.critical_threshold
            && self.crosses_threshold(value, critical)
        {
            return ThresholdState::Critical;
        }

        // Then check warning
        if let Some(warning) = self.config.warning_threshold
            && self.crosses_threshold(value, warning)
        {
            return ThresholdState::Warning;
        }

        ThresholdState::Normal
    }

    /// Check if a value crosses a threshold based on comparison type
    fn crosses_threshold(&self, value: f64, threshold: f64) -> bool {
        const EPSILON: f64 = 1e-9;

        match self.config.comparison {
            Comparison::Above => value > threshold,
            Comparison::Below => value < threshold,
            Comparison::Equal => (value - threshold).abs() < EPSILON,
            Comparison::RateExceeds => {
                // Calculate rate of change per second
                if let Some(last_value) = self.last_value {
                    let elapsed = self.last_check.elapsed().as_secs_f64();
                    if elapsed > 0.0 {
                        let rate = (value - last_value).abs() / elapsed;
                        return rate > threshold;
                    }
                }
                false
            }
        }
    }

    /// Handle a state transition
    fn handle_state_change(
        &mut self,
        old_state: ThresholdState,
        new_state: ThresholdState,
        value: f64,
    ) {
        match (old_state, new_state) {
            // Transitioning to a worse state - always alert
            (ThresholdState::Normal, ThresholdState::Warning)
            | (ThresholdState::Normal, ThresholdState::Critical)
            | (ThresholdState::Warning, ThresholdState::Critical) => {
                self.emit_alert(new_state, value);
            }

            // Recovering - emit recovery event if enabled
            (ThresholdState::Critical, ThresholdState::Warning)
            | (ThresholdState::Critical, ThresholdState::Normal)
            | (ThresholdState::Warning, ThresholdState::Normal) => {
                if new_state == ThresholdState::Normal && self.config.emit_recovery {
                    self.emit_recovery(value);
                } else if new_state == ThresholdState::Warning {
                    // Downgraded from critical to warning - still alert
                    self.emit_alert(new_state, value);
                }
            }

            // Same state - handled by re-alert logic
            _ => {}
        }
    }

    /// Check if we should re-alert (cooldown expired)
    fn should_re_alert(&self) -> bool {
        match self.last_alert {
            Some(last) => last.elapsed() >= self.config.cooldown,
            None => true,
        }
    }

    /// Emit a threshold alert event
    fn emit_alert(&mut self, state: ThresholdState, value: f64) {
        self.last_alert = Some(Instant::now());

        let (event_type, severity) = match state {
            ThresholdState::Warning => (EventType::ThresholdWarning, Severity::Warning),
            ThresholdState::Critical => (EventType::ThresholdCritical, Severity::Critical),
            ThresholdState::Normal => return, // No alert for normal state
        };

        let threshold_value = match state {
            ThresholdState::Warning => self.config.warning_threshold,
            ThresholdState::Critical => self.config.critical_threshold,
            ThresholdState::Normal => None,
        };

        let message = format!(
            "Metric '{}' {} threshold: value={:.2}, threshold={:.2}, comparison={:?}",
            self.config.metric_name,
            match state {
                ThresholdState::Warning => "exceeded warning",
                ThresholdState::Critical => "exceeded critical",
                ThresholdState::Normal => "is normal",
            },
            value,
            threshold_value.unwrap_or(0.0),
            self.config.comparison
        );

        let mut event = Event::new(event_type, message);
        event.severity = severity;
        event.context.security_relevant = state == ThresholdState::Critical;

        dispatch(event);
    }

    /// Emit a recovery event
    fn emit_recovery(&mut self, value: f64) {
        self.last_alert = None; // Reset cooldown on recovery

        let message = format!(
            "Metric '{}' recovered to normal: value={:.2}",
            self.config.metric_name, value
        );

        let mut event = Event::new(EventType::ThresholdRecovered, message);
        event.severity = Severity::Info;

        dispatch(event);
    }
}

// =============================================================================
// Threshold Monitor (Global Registry)
// =============================================================================

/// Global threshold monitor that tracks all registered thresholds
pub(crate) struct ThresholdMonitor {
    thresholds: RwLock<HashMap<String, ThresholdTracker>>,
}

impl ThresholdMonitor {
    /// Create a new threshold monitor
    pub(crate) fn new() -> Self {
        Self {
            thresholds: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new threshold configuration
    pub(crate) fn register(&self, config: ThresholdConfig) {
        let name = config.metric_name.clone();
        let mut thresholds = self.thresholds.write();
        thresholds.insert(name, ThresholdTracker::new(config));
    }

    /// Unregister a threshold by metric name
    pub(crate) fn unregister(&self, metric_name: &str) {
        let mut thresholds = self.thresholds.write();
        thresholds.remove(metric_name);
    }

    /// Check a metric value against its threshold (if registered)
    pub(crate) fn check(&self, metric_name: &str, value: f64) {
        let mut thresholds = self.thresholds.write();
        if let Some(tracker) = thresholds.get_mut(metric_name) {
            tracker.check(value);
        }
    }

    /// Get the current state of a threshold
    pub(crate) fn state(&self, metric_name: &str) -> Option<ThresholdState> {
        let thresholds = self.thresholds.read();
        thresholds.get(metric_name).map(|t| t.state)
    }

    /// List all registered threshold metric names
    pub(crate) fn list(&self) -> Vec<String> {
        let thresholds = self.thresholds.read();
        thresholds.keys().cloned().collect()
    }

    /// Clear all thresholds
    pub(crate) fn clear(&self) {
        let mut thresholds = self.thresholds.write();
        thresholds.clear();
    }
}

impl Default for ThresholdMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Global Instance
// =============================================================================

use once_cell::sync::Lazy;

/// Global threshold monitor instance
static THRESHOLD_MONITOR: Lazy<Arc<ThresholdMonitor>> =
    Lazy::new(|| Arc::new(ThresholdMonitor::new()));

/// Get the global threshold monitor
pub(crate) fn global_monitor() -> &'static ThresholdMonitor {
    &THRESHOLD_MONITOR
}

// =============================================================================
// Public API
// =============================================================================

/// Register a threshold configuration for a metric
///
/// When the metric value crosses the configured threshold, an event
/// is automatically emitted. Cooldown prevents alert storms.
///
/// # Example
///
/// ```rust
/// use octarine::observe::metrics::{register_threshold, ThresholdConfig, Comparison};
/// use std::time::Duration;
///
/// // Alert when queue depth exceeds 1000 (warning) or 5000 (critical)
/// register_threshold(
///     ThresholdConfig::new("queue.depth")
///         .warning(1000.0)
///         .critical(5000.0)
///         .comparison(Comparison::Above)
///         .cooldown(Duration::from_secs(60))
/// );
/// ```
pub fn register_threshold(config: ThresholdConfig) {
    global_monitor().register(config);
}

/// Unregister a threshold by metric name
///
/// Stops monitoring the metric. No further alerts will be emitted.
pub fn unregister_threshold(metric_name: &str) {
    global_monitor().unregister(metric_name);
}

/// Get the current threshold state for a metric
///
/// Returns `None` if no threshold is registered for the metric.
pub fn threshold_state(metric_name: &str) -> Option<ThresholdState> {
    global_monitor().state(metric_name)
}

/// List all metrics with registered thresholds
pub fn list_thresholds() -> Vec<String> {
    global_monitor().list()
}

/// Check a metric value against its threshold (internal use)
///
/// Called automatically by metric operations when thresholds are registered.
pub(crate) fn check_threshold(metric_name: &str, value: f64) {
    global_monitor().check(metric_name, value);
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_threshold_config_builder() {
        let config = ThresholdConfig::new("test.metric")
            .warning(100.0)
            .critical(500.0)
            .comparison(Comparison::Above)
            .cooldown(Duration::from_secs(30));

        assert_eq!(config.metric_name, "test.metric");
        assert_eq!(config.warning_threshold, Some(100.0));
        assert_eq!(config.critical_threshold, Some(500.0));
        assert_eq!(config.comparison, Comparison::Above);
        assert_eq!(config.cooldown, Duration::from_secs(30));
        assert!(config.emit_recovery);
    }

    #[test]
    fn test_threshold_config_no_recovery() {
        let config = ThresholdConfig::new("test").no_recovery();
        assert!(!config.emit_recovery);
    }

    #[test]
    fn test_threshold_state_default() {
        assert_eq!(ThresholdState::default(), ThresholdState::Normal);
    }

    #[test]
    fn test_comparison_default() {
        assert_eq!(Comparison::default(), Comparison::Above);
    }

    #[test]
    fn test_tracker_above_threshold() {
        let config = ThresholdConfig::new("test")
            .warning(100.0)
            .critical(500.0)
            .comparison(Comparison::Above);

        let tracker = ThresholdTracker::new(config);

        // Below warning - normal
        assert_eq!(tracker.evaluate_state(50.0), ThresholdState::Normal);

        // Above warning but below critical
        assert_eq!(tracker.evaluate_state(150.0), ThresholdState::Warning);

        // Above critical
        assert_eq!(tracker.evaluate_state(600.0), ThresholdState::Critical);
    }

    #[test]
    fn test_tracker_below_threshold() {
        let config = ThresholdConfig::new("test")
            .warning(100.0)
            .critical(50.0)
            .comparison(Comparison::Below);

        let tracker = ThresholdTracker::new(config);

        // Above warning - normal
        assert_eq!(tracker.evaluate_state(150.0), ThresholdState::Normal);

        // Below warning but above critical
        assert_eq!(tracker.evaluate_state(75.0), ThresholdState::Warning);

        // Below critical
        assert_eq!(tracker.evaluate_state(25.0), ThresholdState::Critical);
    }

    #[test]
    fn test_monitor_register_unregister() {
        let monitor = ThresholdMonitor::new();

        let config = ThresholdConfig::new("test.metric").warning(100.0);
        monitor.register(config);

        assert!(monitor.state("test.metric").is_some());
        assert_eq!(monitor.state("test.metric"), Some(ThresholdState::Normal));

        monitor.unregister("test.metric");
        assert!(monitor.state("test.metric").is_none());
    }

    #[test]
    fn test_monitor_list() {
        let monitor = ThresholdMonitor::new();

        monitor.register(ThresholdConfig::new("metric.a").warning(100.0));
        monitor.register(ThresholdConfig::new("metric.b").warning(200.0));

        let list = monitor.list();
        assert_eq!(list.len(), 2);
        assert!(list.contains(&"metric.a".to_string()));
        assert!(list.contains(&"metric.b".to_string()));
    }

    #[test]
    fn test_threshold_state_transitions() {
        let config = ThresholdConfig::new("test")
            .warning(100.0)
            .critical(500.0)
            .comparison(Comparison::Above)
            .cooldown(Duration::from_millis(1)); // Very short for testing

        let mut tracker = ThresholdTracker::new(config);

        // Start normal
        tracker.check(50.0);
        assert_eq!(tracker.state, ThresholdState::Normal);

        // Cross warning
        tracker.check(150.0);
        assert_eq!(tracker.state, ThresholdState::Warning);

        // Cross critical
        tracker.check(600.0);
        assert_eq!(tracker.state, ThresholdState::Critical);

        // Recover to warning
        tracker.check(150.0);
        assert_eq!(tracker.state, ThresholdState::Warning);

        // Recover to normal
        tracker.check(50.0);
        assert_eq!(tracker.state, ThresholdState::Normal);
    }
}

//! Performance metrics and monitoring
//!
//! Provides specialized metric types for different observability needs:
//! - **Counters**: Track how often things happen (monotonic increments)
//! - **Gauges**: Track current values (can go up or down)
//! - **Histograms**: Track value distributions and percentiles
//! - **Timers**: Track operation durations
//!
//! All metrics are automatically enriched with context (tenant, environment)
//! and can trigger events when thresholds are exceeded.
//!
//! # Architecture
//!
//! ```text
//! metrics/
//! ├── counters/    # HOW OFTEN - event counts, rates
//! ├── gauges/      # HOW MUCH - current values, watermarks
//! ├── histograms/  # DISTRIBUTION - percentiles, statistics
//! ├── timers/      # HOW LONG - operation durations
//! └── aggregation/ # Time windows, exports, thresholds
//! ```
//!
//! # Examples
//!
//! ```rust
//! use octarine::observe::metrics::{increment, increment_by, gauge, record, MetricName};
//!
//! // Create validated metric names
//! let requests = MetricName::new("api.requests").expect("valid metric name");
//! let errors = MetricName::new("api.errors").expect("valid metric name");
//! let queue_size = MetricName::new("queue.size").expect("valid metric name");
//! let response_size = MetricName::new("response.size").expect("valid metric name");
//!
//! // Count events
//! increment(requests);
//! increment_by(errors, 2);
//!
//! // Track current values
//! gauge(queue_size, 42);
//!
//! // Track distributions
//! record(response_size, 1024.0);
//! ```
//!
//! For timing operations, use the timer functions:
//!
//! ```rust,no_run
//! use octarine::observe::metrics::timer;
//!
//! let _timer = timer("db.query");
//! // ... do work ...
//! // Timer automatically records duration on drop
//! ```

// Internal implementation modules
mod aggregation;
mod async_dispatch;
mod counters;
mod gauges;
mod histograms;
mod labels;
mod thresholds;
mod timers;
mod types;

// Private submodules (two-layer API: octarine::observe::metrics::*, not octarine::observe::metrics::export::*)
mod builtin;
mod export;

// Builder pattern for configurable metrics operations
pub(crate) mod builder;

// Re-export builder for observe/builder/ to use
pub(super) use builder::MetricsBuilder;

// Security validation no longer needed - handled by MetricName type

// Public API - Snapshot types for reading metrics
pub use aggregation::MetricSnapshot;
pub use counters::CounterSnapshot;
pub use gauges::GaugeSnapshot;
pub use histograms::HistogramSnapshot;

// Public API - MetricTimer must be public for RAII pattern
pub use timers::MetricTimer;

// Public API - Convenience functions for metrics operations
pub use timers::{time, time_fn, timer};

// Type-safe wrappers - now the primary API
pub use types::{MetricLabel, MetricName};

// Threshold monitoring - public API for configuring alerts
pub use thresholds::{
    Comparison, ThresholdConfig, ThresholdState, list_thresholds, register_threshold,
    threshold_state, unregister_threshold,
};

// Export functionality - re-exported from private export module (three-layer API)
pub use export::{DefaultLabels, PrometheusConfig, PrometheusExporter, StatsDConfig, StatsDWriter};

/// Define static metric names with compile-time validation
///
/// This macro reduces boilerplate when defining multiple metric names that
/// are known to be valid at compile time. It creates a `metric_names` module
/// with functions that return pre-validated `MetricName` instances.
///
/// # Example
///
/// ```rust
/// use octarine::define_metrics;
///
/// // Define your metrics
/// define_metrics! {
///     requests => "api.requests",
///     errors => "api.errors",
///     latency_ms => "api.latency_ms",
/// }
///
/// // Use them in code
/// use octarine::observe::metrics::{increment, record};
///
/// increment(metric_names::requests());
/// record(metric_names::latency_ms(), 42.5);
/// ```
///
/// # Generated Code
///
/// The macro generates a `metric_names` module with:
/// - A function for each metric name that returns `MetricName`
/// - `#[allow(clippy::expect_used)]` since metric names are compile-time constants
/// - Clear panic messages identifying the invalid metric if it somehow fails
#[macro_export]
macro_rules! define_metrics {
    ($($name:ident => $metric:literal),* $(,)?) => {
        #[allow(clippy::expect_used)]
        mod metric_names {
            use $crate::observe::metrics::MetricName;

            $(
                /// Returns the pre-validated metric name.
                #[inline]
                pub fn $name() -> MetricName {
                    MetricName::new($metric).expect(concat!("valid metric: ", $metric))
                }
            )*
        }
    };
}

// Internal types - not exposed to users
use aggregation::Registry;

// Global registry for convenience
use once_cell::sync::Lazy;
use std::sync::Arc;

static GLOBAL_REGISTRY: Lazy<Arc<Registry>> = Lazy::new(|| Arc::new(Registry::new()));

/// Get the global metrics registry (internal use)
fn global() -> &'static Registry {
    &GLOBAL_REGISTRY
}

/// Increment a counter by 1
///
/// Requires a pre-validated `MetricName`, providing compile-time guarantees
/// that the metric name is valid.
///
/// # Example
///
/// ```ignore
/// use octarine::observe::metrics::{increment, MetricName};
///
/// let name = MetricName::new("api.requests")?;
/// increment(name);
/// ```
pub fn increment(name: MetricName) {
    async_dispatch::queue_counter_increment(name.into_string(), 1);
}

/// Increment a counter by a specific amount
///
/// Requires a pre-validated `MetricName`.
///
/// # Example
///
/// ```ignore
/// use octarine::observe::metrics::{increment_by, MetricName};
///
/// let name = MetricName::new("api.requests")?;
/// increment_by(name, 5);
/// ```
pub fn increment_by(name: MetricName, amount: u64) {
    async_dispatch::queue_counter_increment(name.into_string(), amount);
}

/// Set a gauge to a specific value
///
/// Requires a pre-validated `MetricName`.
///
/// # Example
///
/// ```ignore
/// use octarine::observe::metrics::{gauge, MetricName};
///
/// let name = MetricName::new("queue.size")?;
/// gauge(name, 42);
/// ```
pub fn gauge(name: MetricName, value: i64) {
    async_dispatch::queue_gauge_set(name.into_string(), value);
}

/// Record a value in a histogram
///
/// Requires a pre-validated `MetricName`.
///
/// # Example
///
/// ```ignore
/// use octarine::observe::metrics::{record, MetricName};
///
/// let name = MetricName::new("response.size")?;
/// record(name, 1024.0);
/// ```
pub fn record(name: MetricName, value: f64) {
    async_dispatch::queue_histogram_record(name.into_string(), value);
}

/// Get a snapshot of all metrics
pub fn snapshot() -> MetricSnapshot {
    global().snapshot()
}

/// Flush all pending async metrics synchronously (for testing only)
///
/// Call this before `snapshot()` to ensure all queued metrics are available.
#[cfg(any(test, feature = "testing"))]
pub fn flush_for_testing() {
    async_dispatch::flush_for_testing();
}

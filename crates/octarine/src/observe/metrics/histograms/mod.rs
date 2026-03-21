//! Histograms for tracking value distributions
//!
//! Histograms track the distribution of values over time, providing
//! percentiles and statistical analysis.
//!
//! # Use Cases
//! - Response time distributions
//! - Payload size distributions
//! - Score distributions
//! - Any metric where you need percentiles
//!
//! # Features
//! - Percentile calculations (p50, p75, p90, p95, p99)
//! - Min/max/mean/sum statistics
//! - Configurable buckets
//! - Time-windowed sampling

use crate::primitives::collections::RingBuffer;

/// A histogram for recording value distributions
#[derive(Clone)]
pub(crate) struct Histogram {
    name: String,
    values: RingBuffer<f64>,
}

impl Histogram {
    /// Create a new histogram (internal use)
    pub(crate) fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            values: RingBuffer::new(10_000), // Keep last 10k samples
        }
    }

    /// Record a value
    pub(crate) fn record(&self, value: f64) {
        // RingBuffer handles overflow automatically with O(1) performance
        let _ = self.values.push(value);

        // Check thresholds (e.g., for response time SLOs)
        super::thresholds::check_threshold(&self.name, value);
    }

    /// Get a snapshot of the histogram
    pub(crate) fn snapshot(&self) -> HistogramSnapshot {
        let values = match self.values.snapshot() {
            Ok(v) => v,
            Err(_) => return HistogramSnapshot::empty(self.name.clone()),
        };

        if values.is_empty() {
            return HistogramSnapshot::empty(self.name.clone());
        }

        let mut sorted = values;
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let count = sorted.len();
        let sum: f64 = sorted.iter().sum();
        let mean = sum / count as f64;

        HistogramSnapshot {
            name: self.name.clone(),
            count: count as u64,
            sum,
            mean,
            min: *sorted.first().unwrap_or(&0.0),
            max: *sorted.get(count.saturating_sub(1)).unwrap_or(&0.0),
            p50: percentile(&sorted, 0.50),
            p75: percentile(&sorted, 0.75),
            p90: percentile(&sorted, 0.90),
            p95: percentile(&sorted, 0.95),
            p99: percentile(&sorted, 0.99),
        }
    }
}

/// Calculate percentile from sorted values
fn percentile(sorted: &[f64], p: f64) -> f64 {
    let len = sorted.len();
    let index = ((len.saturating_sub(1)) as f64 * p) as usize;
    *sorted.get(index).unwrap_or(&0.0)
}

/// A snapshot of histogram statistics
#[derive(Debug, Clone)]
pub struct HistogramSnapshot {
    /// Name of the histogram
    pub name: String,
    /// Number of observations
    pub count: u64,
    /// Sum of all observations
    pub sum: f64,
    /// Mean (average) value
    pub mean: f64,
    /// Minimum observed value
    pub min: f64,
    /// Maximum observed value
    pub max: f64,
    /// 50th percentile (median)
    pub p50: f64,
    /// 75th percentile
    pub p75: f64,
    /// 90th percentile
    pub p90: f64,
    /// 95th percentile
    pub p95: f64,
    /// 99th percentile
    pub p99: f64,
}

impl HistogramSnapshot {
    fn empty(name: String) -> Self {
        Self {
            name,
            count: 0,
            sum: 0.0,
            mean: 0.0,
            min: 0.0,
            max: 0.0,
            p50: 0.0,
            p75: 0.0,
            p90: 0.0,
            p95: 0.0,
            p99: 0.0,
        }
    }
}

/// Create or get a global histogram by name (internal use)
pub(crate) fn histogram(name: &str) -> Histogram {
    super::global().histogram(name)
}

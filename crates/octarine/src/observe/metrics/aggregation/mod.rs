//! Aggregation, export, and threshold management
//!
//! This module handles cross-cutting concerns for all metric types:
//! - Time-window aggregation
//! - Export formats (Prometheus, StatsD)
//! - Threshold monitoring and alerts
//! - Metric registry

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use super::counters::Counter;
use super::gauges::Gauge;
use super::histograms::Histogram;

/// Central registry for all metrics
pub(crate) struct Registry {
    counters: Arc<RwLock<HashMap<String, Counter>>>,
    gauges: Arc<RwLock<HashMap<String, Gauge>>>,
    histograms: Arc<RwLock<HashMap<String, Histogram>>>,
}

impl Registry {
    /// Create a new registry
    pub(crate) fn new() -> Self {
        Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
            gauges: Arc::new(RwLock::new(HashMap::new())),
            histograms: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get or create a counter
    pub(crate) fn counter(&self, name: &str) -> Counter {
        let mut counters = self.counters.write();
        counters
            .entry(name.to_string())
            .or_insert_with(|| Counter::new(name))
            .clone()
    }

    /// Get or create a gauge
    pub(crate) fn gauge(&self, name: &str) -> Gauge {
        let mut gauges = self.gauges.write();
        gauges
            .entry(name.to_string())
            .or_insert_with(|| Gauge::new(name))
            .clone()
    }

    /// Get or create a histogram
    pub(crate) fn histogram(&self, name: &str) -> Histogram {
        let mut histograms = self.histograms.write();
        histograms
            .entry(name.to_string())
            .or_insert_with(|| Histogram::new(name))
            .clone()
    }

    /// Get a snapshot of all metrics
    pub(crate) fn snapshot(&self) -> MetricSnapshot {
        let counters = self.counters.read();
        let gauges = self.gauges.read();
        let histograms = self.histograms.read();

        MetricSnapshot {
            timestamp: Instant::now(),
            counters: counters
                .iter()
                .map(|(k, v)| (k.clone(), v.snapshot()))
                .collect(),
            gauges: gauges
                .iter()
                .map(|(k, v)| (k.clone(), v.snapshot()))
                .collect(),
            histograms: histograms
                .iter()
                .map(|(k, v)| (k.clone(), v.snapshot()))
                .collect(),
        }
    }

    /// Clear all metrics
    pub(crate) fn clear(&self) {
        self.counters.write().clear();
        self.gauges.write().clear();
        self.histograms.write().clear();
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// A snapshot of all metrics at a point in time
#[derive(Debug, Clone)]
pub struct MetricSnapshot {
    /// Time when this snapshot was taken
    pub timestamp: Instant,
    /// Snapshot of all counter metrics
    pub counters: HashMap<String, super::counters::CounterSnapshot>,
    /// Snapshot of all gauge metrics
    pub gauges: HashMap<String, super::gauges::GaugeSnapshot>,
    /// Snapshot of all histogram metrics
    pub histograms: HashMap<String, super::histograms::HistogramSnapshot>,
}

// Export functionality has been moved to the dedicated export module
// See: super::export for PrometheusExporter, StatsDWriter, etc.

// Threshold monitoring is now implemented in the thresholds module
// See: super::thresholds for ThresholdConfig, ThresholdState, etc.

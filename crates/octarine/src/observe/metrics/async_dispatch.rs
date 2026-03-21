//! Async metrics dispatcher
//!
//! Provides non-blocking metric recording with tokio backend and batching.

use crate::primitives::runtime::r#async::{BatchProcessor, interval};
use once_cell::sync::Lazy;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
#[cfg(any(test, feature = "testing"))]
use tokio::sync::oneshot;

use super::global;

/// A metric update operation
#[derive(Debug)]
pub(super) enum MetricUpdate {
    /// Increment a counter by a value
    CounterIncrement { name: String, amount: u64 },
    /// Set a gauge to a value
    GaugeSet { name: String, value: i64 },
    /// Record a histogram value
    HistogramRecord { name: String, value: f64 },
    /// Flush all pending metrics (for testing)
    #[cfg(any(test, feature = "testing"))]
    Flush { ack: oneshot::Sender<()> },
}

/// Metrics dispatcher state
struct MetricsDispatcher {
    sender: mpsc::Sender<MetricUpdate>,
}

/// Global metrics dispatcher (lazily initialized)
static METRICS_DISPATCHER: Lazy<Arc<MetricsDispatcher>> =
    Lazy::new(|| Arc::new(MetricsDispatcher::new()));

impl MetricsDispatcher {
    /// Create and initialize the metrics dispatcher
    fn new() -> Self {
        // Create tokio channel with 100k capacity (per architecture doc)
        let (tx, mut rx) = mpsc::channel::<MetricUpdate>(100_000);

        // Spawn background thread with tokio runtime
        std::thread::spawn(move || {
            // Create tokio runtime for this thread
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => {
                    // Runtime creation failed - fall back to blocking receive
                    // This ensures metrics are still processed even if tokio fails
                    while let Some(update) = rx.blocking_recv() {
                        Self::apply_update(update);
                    }
                    return;
                }
            };

            // Run metrics processing loop with batching
            runtime.block_on(async move {
                // Batch processor: 1000 metrics or 10 seconds max age (per architecture doc)
                let mut batch = BatchProcessor::new(1000, Duration::from_secs(10));
                let mut flush_interval = interval(Duration::from_secs(10));

                loop {
                    tokio::select! {
                        // Process incoming metrics
                        Some(update) = rx.recv() => {
                            #[cfg(any(test, feature = "testing"))]
                            if let MetricUpdate::Flush { ack } = update {
                                // Flush all pending metrics immediately
                                let updates = batch.take();
                                for update in updates {
                                    Self::apply_update(update);
                                }
                                let _ = ack.send(());
                                continue;
                            }

                            if batch.add(update) {
                                // Batch is full, flush it
                                let updates = batch.take();
                                for update in updates {
                                    Self::apply_update(update);
                                }
                            }
                        }

                        // Periodic flush (every 10 seconds)
                        _ = flush_interval.tick() => {
                            if !batch.is_empty() {
                                let updates = batch.take();
                                for update in updates {
                                    Self::apply_update(update);
                                }
                            }
                        }
                    }
                }
            });
        });

        Self { sender: tx }
    }

    /// Apply a metric update to the global registry
    fn apply_update(update: MetricUpdate) {
        let registry = global();
        match update {
            MetricUpdate::CounterIncrement { name, amount } => {
                registry.counter(&name).increment_by(amount);
            }
            MetricUpdate::GaugeSet { name, value } => {
                registry.gauge(&name).set(value);
            }
            MetricUpdate::HistogramRecord { name, value } => {
                registry.histogram(&name).record(value);
            }
            #[cfg(any(test, feature = "testing"))]
            MetricUpdate::Flush { .. } => {
                // Flush is handled before apply_update is called
                unreachable!("Flush should be handled before apply_update");
            }
        }
    }

    /// Queue a metric update (non-blocking)
    fn queue(&self, update: MetricUpdate) {
        // try_send is non-blocking - returns immediately
        // If channel is full, metric is dropped (by design for backpressure)
        let _ = self.sender.try_send(update);
    }

    /// Flush all pending metrics (blocking, for testing only)
    #[cfg(any(test, feature = "testing"))]
    fn flush_sync(&self) {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .try_send(MetricUpdate::Flush { ack: tx })
            .is_ok()
        {
            // Block until flush is complete
            let _ = rx.blocking_recv();
        }
    }
}

/// Queue a counter increment (non-blocking, synchronous API)
///
/// This function returns immediately. Metrics are queued to a tokio channel
/// and processed asynchronously in the background.
pub(super) fn queue_counter_increment(name: String, amount: u64) {
    METRICS_DISPATCHER.queue(MetricUpdate::CounterIncrement { name, amount });
}

/// Queue a gauge set (non-blocking, synchronous API)
pub(super) fn queue_gauge_set(name: String, value: i64) {
    METRICS_DISPATCHER.queue(MetricUpdate::GaugeSet { name, value });
}

/// Queue a histogram record (non-blocking, synchronous API)
pub(super) fn queue_histogram_record(name: String, value: f64) {
    METRICS_DISPATCHER.queue(MetricUpdate::HistogramRecord { name, value });
}

/// Flush all pending metrics synchronously (for testing only)
///
/// This blocks until all queued metrics have been applied to the registry.
#[cfg(any(test, feature = "testing"))]
pub(super) fn flush_for_testing() {
    METRICS_DISPATCHER.flush_sync();
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[tokio::test]
    async fn test_metric_queuing() {
        queue_counter_increment("test_counter".to_string(), 5);
        queue_gauge_set("test_gauge".to_string(), 42);
        queue_histogram_record("test_histogram".to_string(), 123.45);

        // Give time for async processing
        crate::primitives::runtime::r#async::sleep_ms(10).await;
    }
}

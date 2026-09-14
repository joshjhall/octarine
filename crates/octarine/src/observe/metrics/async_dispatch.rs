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
    ///
    /// Also invalidates the registry's snapshot cache so the next
    /// `snapshot()` call reflects the writes that were just flushed.
    /// Without this, tests that call `flush_for_testing()` then
    /// `snapshot()` could be served a stale cached snapshot from an
    /// earlier test in the same process.
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
        global().invalidate_snapshot_cache();
    }
}

// Per-thread tally of metric recordings, for tests that must assert a metric
// was *not* recorded.
//
// The global registry cannot answer that question: it is process-wide, and
// under `cargo test` (one process for the whole crate) an unrelated sibling
// test recording the same metric makes an absolute "did not move" assertion
// fail. Serializing with `metrics_test_lock()` does not help, because that
// lock is opt-in and the vast majority of tests that touch metrics never take
// it.
//
// The queue entry points below run *synchronously on the calling thread*
// before handing the update to the background dispatcher, and each test owns
// its thread, so a thread-local tally attributes every recording to exactly
// the test that caused it. See `local_metric_count`.
#[cfg(any(test, feature = "testing"))]
thread_local! {
    static LOCAL_TALLY: std::cell::RefCell<std::collections::HashMap<String, u64>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// Record one metric recording against the calling thread's tally.
#[cfg(any(test, feature = "testing"))]
fn tally_local(name: &str) {
    LOCAL_TALLY.with(|t| {
        if let Ok(mut map) = t.try_borrow_mut() {
            let entry = map.entry(name.to_string()).or_insert(0);
            *entry = entry.saturating_add(1);
        }
    });
}

/// How many times the **calling thread** has recorded `name`.
///
/// Counts recordings, not the accumulated value: an `increment_by(name, 5)`
/// counts once. Covers the [`queue_counter_increment`] / [`queue_gauge_set`] /
/// [`queue_histogram_record`] path only — a [`crate::observe::metrics::MetricTimer`]
/// writes to the registry directly on drop and is not tallied.
///
/// Needs no `flush_for_testing()`: the tally is updated before the update is
/// queued, so it is current the moment the recording call returns.
#[cfg(any(test, feature = "testing"))]
pub(super) fn local_metric_count(name: &str) -> u64 {
    LOCAL_TALLY.with(|t| t.borrow().get(name).copied().unwrap_or(0))
}

/// Clear the calling thread's tally.
#[cfg(any(test, feature = "testing"))]
pub(super) fn reset_local_metrics() {
    LOCAL_TALLY.with(|t| {
        if let Ok(mut map) = t.try_borrow_mut() {
            map.clear();
        }
    });
}

/// Queue a counter increment (non-blocking, synchronous API)
///
/// This function returns immediately. Metrics are queued to a tokio channel
/// and processed asynchronously in the background.
pub(super) fn queue_counter_increment(name: String, amount: u64) {
    #[cfg(any(test, feature = "testing"))]
    tally_local(&name);
    METRICS_DISPATCHER.queue(MetricUpdate::CounterIncrement { name, amount });
}

/// Queue a gauge set (non-blocking, synchronous API)
pub(super) fn queue_gauge_set(name: String, value: i64) {
    #[cfg(any(test, feature = "testing"))]
    tally_local(&name);
    METRICS_DISPATCHER.queue(MetricUpdate::GaugeSet { name, value });
}

/// Queue a histogram record (non-blocking, synchronous API)
pub(super) fn queue_histogram_record(name: String, value: f64) {
    #[cfg(any(test, feature = "testing"))]
    tally_local(&name);
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

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
use std::time::{Duration, Instant};

use super::counters::Counter;
use super::gauges::Gauge;
use super::histograms::Histogram;

/// Default time-to-live for cached snapshots.
///
/// One second is short enough to be invisible to Prometheus scrapers (typical
/// scrape interval 15–60s) and tighter than the async dispatcher's 10s batch
/// flush window, so the cache never serves data older than the underlying
/// registry would have served anyway.
const DEFAULT_SNAPSHOT_TTL: Duration = Duration::from_secs(1);

/// A cached snapshot with its expiry.
struct CachedSnapshot {
    snapshot: MetricSnapshot,
    expires_at: Instant,
}

/// Central registry for all metrics
pub(crate) struct Registry {
    counters: Arc<RwLock<HashMap<String, Counter>>>,
    gauges: Arc<RwLock<HashMap<String, Gauge>>>,
    histograms: Arc<RwLock<HashMap<String, Histogram>>>,
    snapshot_cache: Arc<RwLock<Option<CachedSnapshot>>>,
    snapshot_ttl: Duration,
    #[cfg(test)]
    build_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl Registry {
    /// Create a new registry with the default snapshot TTL.
    pub(crate) fn new() -> Self {
        Self::with_ttl(DEFAULT_SNAPSHOT_TTL)
    }

    /// Create a new registry with a custom snapshot TTL.
    ///
    /// Used by tests that need to exercise cache expiration without waiting
    /// the full default TTL.
    pub(crate) fn with_ttl(snapshot_ttl: Duration) -> Self {
        Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
            gauges: Arc::new(RwLock::new(HashMap::new())),
            histograms: Arc::new(RwLock::new(HashMap::new())),
            snapshot_cache: Arc::new(RwLock::new(None)),
            snapshot_ttl,
            #[cfg(test)]
            build_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
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

    /// Get a snapshot of all metrics.
    ///
    /// Snapshots are cached for `snapshot_ttl` (default 1 second) to amortize
    /// the cost of deep-cloning every metric on each call. Concurrent calls
    /// during a cache miss use a read-then-double-check pattern so the
    /// underlying snapshot is built at most once per TTL window.
    pub(crate) fn snapshot(&self) -> MetricSnapshot {
        // Fast path: a valid cached snapshot is available under the read lock.
        {
            let cache = self.snapshot_cache.read();
            if let Some(cached) = cache.as_ref()
                && Instant::now() < cached.expires_at
            {
                return cached.snapshot.clone();
            }
        }

        // Slow path: take the write lock and double-check — another thread
        // may have populated the cache while we were waiting.
        let mut cache = self.snapshot_cache.write();
        if let Some(cached) = cache.as_ref()
            && Instant::now() < cached.expires_at
        {
            return cached.snapshot.clone();
        }

        let fresh = self.build_snapshot_uncached();
        let now = Instant::now();
        let expires_at = now.checked_add(self.snapshot_ttl).unwrap_or(now);
        *cache = Some(CachedSnapshot {
            snapshot: fresh.clone(),
            expires_at,
        });
        fresh
    }

    /// Build a snapshot directly from the underlying registry, bypassing the
    /// cache. The cache wraps this method.
    fn build_snapshot_uncached(&self) -> MetricSnapshot {
        #[cfg(test)]
        self.build_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

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

    /// Drop any cached snapshot so the next `snapshot()` call rebuilds.
    ///
    /// Used by `flush_for_testing()` and `clear()` to preserve the contract
    /// that callers see the registry's current state on the next snapshot.
    pub(crate) fn invalidate_snapshot_cache(&self) {
        *self.snapshot_cache.write() = None;
    }

    /// Clear all metrics
    pub(crate) fn clear(&self) {
        self.counters.write().clear();
        self.gauges.write().clear();
        self.histograms.write().clear();
        self.invalidate_snapshot_cache();
    }

    /// Number of times `build_snapshot_uncached` has run on this registry.
    /// Test-only hook for verifying stampede behavior.
    #[cfg(test)]
    pub(crate) fn build_count(&self) -> usize {
        self.build_count.load(std::sync::atomic::Ordering::SeqCst)
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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]

    use super::*;
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn snapshot_returns_cached_value_within_ttl() {
        let registry = Registry::with_ttl(Duration::from_secs(60));
        let counter = registry.counter("cached.counter");
        counter.increment();

        let first = registry.snapshot();
        let first_value = first
            .counters
            .get("cached.counter")
            .expect("counter present")
            .value;
        assert_eq!(first_value, 1);

        // Mutate the underlying counter after the cache is warm.
        counter.increment();

        // The second snapshot must be the cached one, still showing 1.
        let second = registry.snapshot();
        let second_value = second
            .counters
            .get("cached.counter")
            .expect("counter present")
            .value;
        assert_eq!(second_value, 1, "expected cached snapshot to be served");
        assert_eq!(
            registry.build_count(),
            1,
            "snapshot should be built exactly once"
        );
    }

    #[test]
    fn snapshot_refreshes_after_ttl() {
        let registry = Registry::with_ttl(Duration::from_millis(20));
        let counter = registry.counter("refresh.counter");
        counter.increment();

        let first = registry.snapshot();
        assert_eq!(
            first
                .counters
                .get("refresh.counter")
                .expect("present")
                .value,
            1
        );

        counter.increment();

        // Poll until the cache expires and serves the updated value.
        // Fixed sleeps are flaky under CI coverage; see
        // primitives/collections/cache/lru.rs::test_cache_expiration.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let value = registry
                .snapshot()
                .counters
                .get("refresh.counter")
                .expect("present")
                .value;
            if value == 2 {
                break;
            }
            if Instant::now() > deadline {
                panic!("timed out waiting for snapshot cache to expire");
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn clear_invalidates_snapshot_cache() {
        let registry = Registry::with_ttl(Duration::from_secs(60));
        let counter = registry.counter("clear.counter");
        counter.increment();
        let _ = registry.snapshot();

        registry.clear();
        // Recreating the counter must show 0, not the stale cached 1.
        let counter_after = registry.counter("clear.counter");
        counter_after.increment_by(7);

        let after = registry.snapshot();
        assert_eq!(
            after.counters.get("clear.counter").expect("present").value,
            7,
            "snapshot after clear must reflect post-clear state"
        );
    }

    #[test]
    fn invalidate_snapshot_cache_forces_rebuild() {
        let registry = Registry::with_ttl(Duration::from_secs(60));
        registry.counter("invalidate.counter").increment();

        let _ = registry.snapshot();
        let _ = registry.snapshot();
        assert_eq!(registry.build_count(), 1, "second call should be cached");

        registry.invalidate_snapshot_cache();
        let _ = registry.snapshot();
        assert_eq!(
            registry.build_count(),
            2,
            "snapshot after invalidate should rebuild"
        );
    }

    #[test]
    fn concurrent_snapshot_no_stampede() {
        let registry = Arc::new(Registry::with_ttl(Duration::from_secs(60)));
        registry.counter("stampede.counter").increment();

        const THREADS: usize = 16;
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                registry.snapshot();
            }));
        }
        for handle in handles {
            handle.join().expect("worker thread");
        }

        // The double-check pattern means only one thread should hit the
        // slow path. A few extra rebuilds are tolerable if the OS schedules
        // a writer between read-lock release and write-lock acquisition,
        // but it must never approach THREADS.
        let builds = registry.build_count();
        assert!(
            (1..THREADS).contains(&builds),
            "expected 1..{} snapshot builds under concurrency, got {}",
            THREADS,
            builds
        );
    }
}

//! Timers for tracking operation durations
//!
//! Timers measure how long operations take, automatically recording
//! durations to histograms when they complete.
//!
//! # Use Cases
//! - API endpoint latency
//! - Database query duration
//! - External service calls
//! - Any timed operation
//!
//! # Features
//! - Auto-record on drop (RAII pattern)
//! - Nested timing spans
//! - Manual or automatic recording
//! - Integration with histograms

use std::time::Instant;

use super::histograms::Histogram;

/// A timer that records duration when dropped
pub struct MetricTimer {
    name: String,
    start: Instant,
    histogram: Histogram,
    recorded: bool,
}

impl MetricTimer {
    /// Create a new timer (starts immediately)
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        let histogram = super::global().histogram(&name);
        Self {
            histogram,
            name,
            start: Instant::now(),
            recorded: false,
        }
    }

    /// Manually record the duration (prevents auto-record on drop)
    pub fn record(mut self) -> std::time::Duration {
        let duration = self.start.elapsed();
        self.histogram.record(duration.as_secs_f64() * 1000.0); // Convert to ms
        self.recorded = true;
        duration
    }

    /// Get elapsed time without recording
    pub fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }

    /// Cancel the timer (prevents recording)
    pub fn cancel(mut self) {
        self.recorded = true;
    }
}

impl Drop for MetricTimer {
    fn drop(&mut self) {
        if !self.recorded {
            let duration = self.start.elapsed();
            self.histogram.record(duration.as_secs_f64() * 1000.0); // Convert to ms
        }
    }
}

/// Create a timer for the given operation name
pub fn timer(name: &str) -> MetricTimer {
    MetricTimer::new(name)
}

/// Time a function and record the duration
pub fn time_fn<F, R>(name: &str, f: F) -> R
where
    F: FnOnce() -> R,
{
    let _timer = timer(name);
    f()
}

/// Time an async function and record the duration
pub async fn time<F, R>(name: &str, future: F) -> R
where
    F: std::future::Future<Output = R>,
{
    let _timer = timer(name);
    future.await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_timer_auto_record() {
        {
            let _timer = timer("test_operation");
            thread::sleep(Duration::from_millis(10));
            // Timer records on drop
        }
    }

    #[test]
    fn test_timer_manual_record() {
        let timer = timer("test_operation");
        thread::sleep(Duration::from_millis(10));
        let duration = timer.record();
        assert!(duration.as_millis() >= 10);
    }

    #[test]
    fn test_time_fn() {
        let result = time_fn("test_operation", || {
            thread::sleep(Duration::from_millis(10));
            42
        });
        assert_eq!(result, 42);
    }
}

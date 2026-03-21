//! Pre-shutdown draining phase
//!
//! This module handles the draining phase before shutdown hooks run,
//! allowing in-flight requests to complete gracefully.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use crate::observe;

use super::coordinator::ShutdownCoordinator;
use super::types::ShutdownPhase;

/// Tracker for in-flight requests during draining
///
/// Use this to track active requests and signal when draining is complete.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::shutdown::{ShutdownCoordinator, DrainTracker};
/// use std::time::Duration;
///
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// let coordinator = ShutdownCoordinator::new()
///     .with_drain_timeout(Duration::from_secs(10));
///
/// // Get a tracker for in-flight requests
/// let tracker = coordinator.drain_tracker();
///
/// // In your request handler:
/// let _guard = tracker.start_request();
/// // ... handle request ...
/// // guard is dropped automatically when request completes
///
/// // During shutdown, draining will wait for all guards to be dropped
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct DrainTracker {
    /// Number of in-flight requests
    in_flight: Arc<AtomicUsize>,
}

impl Default for DrainTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl DrainTracker {
    /// Create a new drain tracker
    pub fn new() -> Self {
        Self {
            in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Start tracking a request
    ///
    /// Returns a guard that decrements the in-flight count when dropped.
    pub fn start_request(&self) -> DrainGuard {
        self.in_flight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        DrainGuard {
            in_flight: Arc::clone(&self.in_flight),
        }
    }

    /// Get the current number of in-flight requests
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Check if all requests have completed
    pub fn is_drained(&self) -> bool {
        self.in_flight_count() == 0
    }

    /// Wait for all in-flight requests to complete
    ///
    /// Returns `true` if drained within timeout, `false` if timed out.
    pub async fn wait_for_drain(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(50);

        loop {
            if self.is_drained() {
                return true;
            }

            if start.elapsed() >= timeout {
                return false;
            }

            tokio::time::sleep(poll_interval).await;
        }
    }
}

/// Guard that tracks an in-flight request
///
/// When dropped, decrements the in-flight count in the tracker.
pub struct DrainGuard {
    in_flight: Arc<AtomicUsize>,
}

impl Drop for DrainGuard {
    fn drop(&mut self) {
        self.in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl ShutdownCoordinator {
    /// Get a drain tracker for tracking in-flight requests
    ///
    /// The returned tracker can be cloned and shared across request handlers.
    /// During the draining phase, shutdown will wait for all tracked requests
    /// to complete (or until the drain timeout is reached).
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::runtime::shutdown::ShutdownCoordinator;
    /// use std::time::Duration;
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let coordinator = ShutdownCoordinator::new()
    ///     .with_drain_timeout(Duration::from_secs(10));
    ///
    /// let tracker = coordinator.drain_tracker();
    ///
    /// // Use in request handler
    /// let guard = tracker.start_request();
    /// // ... process request ...
    /// drop(guard); // Or let it drop naturally
    /// # });
    /// ```
    pub fn drain_tracker(&self) -> DrainTracker {
        DrainTracker::new()
    }

    /// Start the draining phase
    ///
    /// This transitions the coordinator to the `Draining` phase and waits
    /// for in-flight requests to complete (using the provided tracker) or
    /// until the drain timeout is reached.
    ///
    /// # Arguments
    ///
    /// * `tracker` - The drain tracker monitoring in-flight requests
    ///
    /// # Returns
    ///
    /// `true` if all requests drained, `false` if timeout was reached.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use octarine::runtime::shutdown::ShutdownCoordinator;
    /// use std::time::Duration;
    ///
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let coordinator = ShutdownCoordinator::new()
    ///     .with_drain_timeout(Duration::from_secs(10));
    ///
    /// let tracker = coordinator.drain_tracker();
    ///
    /// // When shutdown signal received:
    /// coordinator.trigger().await;
    ///
    /// // Wait for requests to drain
    /// let drained = coordinator.drain(&tracker).await;
    /// if !drained {
    ///     println!("Warning: drain timeout reached with {} requests in flight",
    ///         tracker.in_flight_count());
    /// }
    ///
    /// // Now run hooks
    /// coordinator.run_hooks().await;
    /// # });
    /// ```
    pub async fn drain(&self, tracker: &DrainTracker) -> bool {
        // Only drain if we're in the right phase
        let current_phase = *self.phase.read().await;
        if current_phase != ShutdownPhase::ShuttingDown {
            observe::warn(
                "drain_skipped",
                format!(
                    "Cannot drain in phase '{}', must be 'shutting_down'",
                    current_phase
                ),
            );
            return true;
        }

        // Transition to draining phase
        *self.phase.write().await = ShutdownPhase::Draining;

        let in_flight = tracker.in_flight_count();
        observe::info(
            "drain_started",
            format!(
                "Starting drain phase with {} in-flight requests, {}ms timeout",
                in_flight,
                self.drain_timeout.as_millis()
            ),
        );

        let drained = tracker.wait_for_drain(self.drain_timeout).await;

        if drained {
            observe::info("drain_complete", "All in-flight requests completed");
        } else {
            observe::warn(
                "drain_timeout",
                format!(
                    "Drain timeout reached with {} requests still in flight",
                    tracker.in_flight_count()
                ),
            );
        }

        // Transition back to shutting down for hooks
        *self.phase.write().await = ShutdownPhase::ShuttingDown;

        drained
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn test_drain_tracker_creation() {
        let tracker = DrainTracker::new();
        assert_eq!(tracker.in_flight_count(), 0);
        assert!(tracker.is_drained());
    }

    #[test]
    fn test_drain_guard_increments_and_decrements() {
        let tracker = DrainTracker::new();

        {
            let _guard1 = tracker.start_request();
            assert_eq!(tracker.in_flight_count(), 1);
            assert!(!tracker.is_drained());

            let _guard2 = tracker.start_request();
            assert_eq!(tracker.in_flight_count(), 2);
        }

        // Both guards dropped
        assert_eq!(tracker.in_flight_count(), 0);
        assert!(tracker.is_drained());
    }

    #[tokio::test]
    async fn test_wait_for_drain_immediate() {
        let tracker = DrainTracker::new();

        // Already drained
        let result = tracker.wait_for_drain(Duration::from_millis(100)).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_wait_for_drain_with_requests() {
        let tracker = DrainTracker::new();
        let tracker_clone = tracker.clone();

        let guard = tracker.start_request();
        assert_eq!(tracker.in_flight_count(), 1);

        // Spawn task to complete request after a delay
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(guard);
        });

        // Wait for drain
        let result = tracker_clone
            .wait_for_drain(Duration::from_millis(200))
            .await;
        assert!(result);
        assert!(tracker_clone.is_drained());
    }

    #[tokio::test]
    async fn test_wait_for_drain_timeout() {
        let tracker = DrainTracker::new();

        let _guard = tracker.start_request();

        // Short timeout, request won't complete
        let result = tracker.wait_for_drain(Duration::from_millis(50)).await;
        assert!(!result);
        assert_eq!(tracker.in_flight_count(), 1);
    }

    #[tokio::test]
    async fn test_coordinator_drain() {
        let coordinator = ShutdownCoordinator::new().with_drain_timeout(Duration::from_millis(100));

        let tracker = coordinator.drain_tracker();

        // Start a request
        let guard = tracker.start_request();
        let tracker_clone = tracker.clone();

        // Trigger shutdown first
        coordinator.trigger().await;

        // Spawn task to complete request
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            drop(guard);
        });

        // Drain should succeed
        let drained = coordinator.drain(&tracker_clone).await;
        assert!(drained);
    }

    #[tokio::test]
    async fn test_coordinator_drain_timeout() {
        let coordinator = ShutdownCoordinator::new().with_drain_timeout(Duration::from_millis(50));

        let tracker = coordinator.drain_tracker();

        // Start a request that won't complete
        let _guard = tracker.start_request();

        // Trigger shutdown
        coordinator.trigger().await;

        // Drain should timeout
        let drained = coordinator.drain(&tracker).await;
        assert!(!drained);
        assert_eq!(tracker.in_flight_count(), 1);
    }

    #[tokio::test]
    async fn test_phase_transitions_during_drain() {
        use std::sync::Arc;
        use tokio::sync::Barrier;

        let coordinator = ShutdownCoordinator::new().with_drain_timeout(Duration::from_millis(200));
        let tracker = coordinator.drain_tracker();

        // Trigger and check phase
        coordinator.trigger().await;
        assert_eq!(coordinator.phase().await, ShutdownPhase::ShuttingDown);

        // Start a request that will complete during drain
        let guard = tracker.start_request();
        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = Arc::clone(&barrier);

        // Complete request after barrier sync
        tokio::spawn(async move {
            barrier_clone.wait().await;
            tokio::time::sleep(Duration::from_millis(30)).await;
            drop(guard);
        });

        // Start drain and sync with the spawned task
        let drain_task = tokio::spawn({
            let tracker = tracker.clone();
            let phase = Arc::clone(&coordinator.phase);
            let drain_timeout = coordinator.drain_timeout;
            async move {
                // Check phase is Draining during wait
                tokio::time::sleep(Duration::from_millis(10)).await;
                let current_phase = *phase.read().await;
                (current_phase, tracker.wait_for_drain(drain_timeout).await)
            }
        });

        // Sync with spawned task
        barrier.wait().await;

        // Wait for drain
        coordinator.drain(&tracker).await;

        // After drain, phase should be back to ShuttingDown
        assert_eq!(coordinator.phase().await, ShutdownPhase::ShuttingDown);

        // Verify the phase was Draining during the wait
        let (phase_during, drained) = drain_task.await.expect("drain task should complete");
        assert_eq!(phase_during, ShutdownPhase::Draining);
        assert!(drained);
    }
}

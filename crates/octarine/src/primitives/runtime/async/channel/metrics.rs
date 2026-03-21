//! Channel metrics (internal)
//!
//! Internal metrics tracking for channel operations.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::stats::ChannelStats;

/// Internal metrics tracking for the channel
#[derive(Debug, Default)]
pub(super) struct ChannelMetrics {
    /// Total items successfully sent
    sent: AtomicUsize,
    /// Total items dropped due to overflow
    dropped: AtomicUsize,
    /// Total items rejected (Reject policy)
    rejected: AtomicUsize,
    /// Total receive operations
    received: AtomicUsize,
}

impl ChannelMetrics {
    pub(super) fn increment_sent(&self) {
        self.sent.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn increment_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn increment_rejected(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn increment_received(&self) {
        self.received.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn snapshot(&self, capacity: usize, current_size: usize) -> ChannelStats {
        ChannelStats {
            capacity,
            current_size,
            total_sent: self.sent.load(Ordering::Relaxed),
            total_dropped: self.dropped.load(Ordering::Relaxed),
            total_rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
}

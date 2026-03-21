//! Buffer statistics
//!
//! Shared statistics types for all buffer implementations.

/// Statistics for a buffer
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Used by higher layers
pub struct BufferStats {
    /// Current number of items in the buffer
    pub current_size: usize,

    /// Maximum capacity of the buffer
    pub capacity: usize,

    /// Total items written to the buffer
    pub total_written: usize,

    /// Total items dropped due to overflow
    pub total_dropped: usize,
}

#[allow(dead_code)] // Used by higher layers
impl BufferStats {
    /// Calculate the drop rate as a percentage
    pub fn drop_rate(&self) -> f64 {
        if self.total_written == 0 {
            0.0
        } else {
            (self.total_dropped as f64 / self.total_written as f64) * 100.0
        }
    }

    /// Calculate the current utilization as a percentage
    pub fn utilization(&self) -> f64 {
        if self.capacity == 0 {
            0.0
        } else {
            (self.current_size as f64 / self.capacity as f64) * 100.0
        }
    }
}

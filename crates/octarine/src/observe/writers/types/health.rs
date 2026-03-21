//! Writer health status types
//!
//! Types for monitoring and reporting writer health.

/// Health status for a writer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WriterHealthStatus {
    /// Writer is healthy and accepting events
    #[default]
    Healthy,

    /// Writer is degraded but still functioning
    Degraded,

    /// Writer is unhealthy and may not accept events
    Unhealthy,
}

impl WriterHealthStatus {
    /// Check if the writer is healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Check if the writer can accept events (healthy or degraded)
    pub fn can_accept(&self) -> bool {
        !matches!(self, Self::Unhealthy)
    }

    /// Create a degraded status
    pub fn degraded() -> Self {
        Self::Degraded
    }
}

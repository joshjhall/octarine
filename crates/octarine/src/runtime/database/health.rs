//! Health check types for database pools

use std::time::Duration;

/// Health status of a database pool
///
/// Provides information for health/readiness endpoints.
#[derive(Debug, Clone)]
pub struct PoolHealth {
    /// Whether the pool can connect to the database
    pub is_healthy: bool,

    /// Round-trip latency to database (if connected)
    pub latency: Option<Duration>,

    /// Current number of active connections
    pub active_connections: u32,

    /// Current number of idle connections
    pub idle_connections: u32,

    /// Maximum connections configured
    pub max_connections: u32,

    /// Error message if unhealthy
    pub error: Option<String>,
}

impl PoolHealth {
    /// Create a healthy status
    pub fn healthy(latency: Duration, active: u32, idle: u32, max: u32) -> Self {
        Self {
            is_healthy: true,
            latency: Some(latency),
            active_connections: active,
            idle_connections: idle,
            max_connections: max,
            error: None,
        }
    }

    /// Create an unhealthy status
    pub fn unhealthy(error: impl Into<String>, active: u32, idle: u32, max: u32) -> Self {
        Self {
            is_healthy: false,
            latency: None,
            active_connections: active,
            idle_connections: idle,
            max_connections: max,
            error: Some(error.into()),
        }
    }

    /// Pool utilization as a percentage (0.0 - 1.0)
    pub fn utilization(&self) -> f64 {
        if self.max_connections == 0 {
            return 0.0;
        }
        f64::from(self.active_connections) / f64::from(self.max_connections)
    }

    /// Whether the pool is under high load (>80% utilization)
    pub fn is_high_load(&self) -> bool {
        self.utilization() > 0.8
    }
}

impl Default for PoolHealth {
    fn default() -> Self {
        Self {
            is_healthy: false,
            latency: None,
            active_connections: 0,
            idle_connections: 0,
            max_connections: 0,
            error: Some("not initialized".to_string()),
        }
    }
}

/// Current pool statistics for monitoring
///
/// Provides a snapshot of the pool's current state. These are the values
/// that sqlx actually exposes - we don't include fields that would always
/// be zero (like lifetime counters that sqlx doesn't track).
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Current active connections (in use)
    active: u32,

    /// Current idle connections (available)
    idle: u32,

    /// Maximum connections configured
    max: u32,
}

impl PoolStats {
    /// Create stats from current pool state
    pub fn new(active: u32, idle: u32, max: u32) -> Self {
        Self { active, idle, max }
    }

    /// Get active connection count
    pub fn active(&self) -> u32 {
        self.active
    }

    /// Get idle connection count
    pub fn idle(&self) -> u32 {
        self.idle
    }

    /// Get maximum connection count
    pub fn max(&self) -> u32 {
        self.max
    }

    /// Get total current connections (active + idle)
    pub fn total(&self) -> u32 {
        self.active.saturating_add(self.idle)
    }

    /// Pool utilization as a ratio (0.0 - 1.0)
    pub fn utilization(&self) -> f64 {
        if self.max == 0 {
            return 0.0;
        }
        f64::from(self.active) / f64::from(self.max)
    }

    /// Whether the pool is under high load (>80% utilization)
    pub fn is_high_load(&self) -> bool {
        self.utilization() > 0.8
    }

    /// Whether the pool has available connections
    pub fn is_available(&self) -> bool {
        self.idle > 0 || self.active < self.max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_healthy_status() {
        let health = PoolHealth::healthy(Duration::from_millis(5), 3, 7, 10);
        assert!(health.is_healthy);
        assert_eq!(health.latency, Some(Duration::from_millis(5)));
        assert_eq!(health.active_connections, 3);
        assert!(health.error.is_none());
    }

    #[test]
    fn test_unhealthy_status() {
        let health = PoolHealth::unhealthy("connection refused", 0, 0, 10);
        assert!(!health.is_healthy);
        assert!(health.latency.is_none());
        assert_eq!(health.error, Some("connection refused".to_string()));
    }

    #[test]
    fn test_utilization() {
        let health = PoolHealth::healthy(Duration::from_millis(1), 5, 5, 10);
        assert!((health.utilization() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_high_load() {
        let normal = PoolHealth::healthy(Duration::from_millis(1), 7, 3, 10);
        assert!(!normal.is_high_load());

        let high = PoolHealth::healthy(Duration::from_millis(1), 9, 1, 10);
        assert!(high.is_high_load());
    }

    #[test]
    fn test_zero_max_connections() {
        let health = PoolHealth::healthy(Duration::from_millis(1), 0, 0, 0);
        assert!((health.utilization() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pool_stats_new() {
        let stats = PoolStats::new(3, 7, 10);
        assert_eq!(stats.active(), 3);
        assert_eq!(stats.idle(), 7);
        assert_eq!(stats.max(), 10);
        assert_eq!(stats.total(), 10);
    }

    #[test]
    fn test_pool_stats_utilization() {
        let stats = PoolStats::new(5, 5, 10);
        assert!((stats.utilization() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pool_stats_high_load() {
        let normal = PoolStats::new(7, 3, 10);
        assert!(!normal.is_high_load());

        let high = PoolStats::new(9, 1, 10);
        assert!(high.is_high_load());
    }

    #[test]
    fn test_pool_stats_is_available() {
        let available = PoolStats::new(5, 5, 10);
        assert!(available.is_available());

        let full_but_idle = PoolStats::new(10, 0, 10);
        assert!(!full_but_idle.is_available());

        let has_idle = PoolStats::new(8, 2, 10);
        assert!(has_idle.is_available());
    }
}

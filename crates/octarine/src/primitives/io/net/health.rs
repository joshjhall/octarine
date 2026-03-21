//! Health check trait for network services
//!
//! Defines a common interface for health checking network services.
//! Implementations live in higher layers (observe, public API).

#![allow(dead_code)] // API types for higher layers

use std::future::Future;
use std::pin::Pin;

/// Health status of a service
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkHealthStatus {
    /// Service is healthy and operational
    Healthy,
    /// Service is degraded but still functional
    Degraded(String),
    /// Service is unhealthy/unavailable
    Unhealthy(String),
}

impl NetworkHealthStatus {
    /// Check if the status is healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Check if the status is degraded
    pub fn is_degraded(&self) -> bool {
        matches!(self, Self::Degraded(_))
    }

    /// Check if the status is unhealthy
    pub fn is_unhealthy(&self) -> bool {
        matches!(self, Self::Unhealthy(_))
    }

    /// Get the reason if degraded or unhealthy
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Healthy => None,
            Self::Degraded(reason) | Self::Unhealthy(reason) => Some(reason),
        }
    }
}

impl std::fmt::Display for NetworkHealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded(reason) => write!(f, "degraded: {}", reason),
            Self::Unhealthy(reason) => write!(f, "unhealthy: {}", reason),
        }
    }
}

/// Health check trait for network services
///
/// This trait defines a common interface for health checking. Implementations
/// should perform actual health checks (ping, query, etc.) and return the
/// current health status.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::primitives::io::net::{HealthCheck, NetworkHealthStatus};
///
/// struct DatabaseClient { /* ... */ }
///
/// impl HealthCheck for DatabaseClient {
///     fn check_health(&self) -> Pin<Box<dyn Future<Output = NetworkHealthStatus> + Send + '_>> {
///         Box::pin(async move {
///             // Perform health check
///             match self.ping().await {
///                 Ok(_) => NetworkHealthStatus::Healthy,
///                 Err(e) => NetworkHealthStatus::Unhealthy(e.to_string()),
///             }
///         })
///     }
///
///     fn service_name(&self) -> &str {
///         "database"
///     }
/// }
/// ```
pub trait HealthCheck: Send + Sync {
    /// Perform a health check
    ///
    /// Returns the current health status of the service.
    fn check_health(&self) -> Pin<Box<dyn Future<Output = NetworkHealthStatus> + Send + '_>>;

    /// Get the service name for logging/metrics
    fn service_name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_health_status_healthy() {
        let status = NetworkHealthStatus::Healthy;
        assert!(status.is_healthy());
        assert!(!status.is_degraded());
        assert!(!status.is_unhealthy());
        assert!(status.reason().is_none());
        assert_eq!(status.to_string(), "healthy");
    }

    #[test]
    fn test_health_status_degraded() {
        let status = NetworkHealthStatus::Degraded("high latency".to_string());
        assert!(!status.is_healthy());
        assert!(status.is_degraded());
        assert!(!status.is_unhealthy());
        assert_eq!(status.reason(), Some("high latency"));
        assert!(status.to_string().contains("degraded"));
    }

    #[test]
    fn test_health_status_unhealthy() {
        let status = NetworkHealthStatus::Unhealthy("connection refused".to_string());
        assert!(!status.is_healthy());
        assert!(!status.is_degraded());
        assert!(status.is_unhealthy());
        assert_eq!(status.reason(), Some("connection refused"));
        assert!(status.to_string().contains("unhealthy"));
    }
}

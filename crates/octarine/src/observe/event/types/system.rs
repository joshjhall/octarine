//! System-level audit events
//!
//! Track system lifecycle, health, and operational events.

/// System events for audit trail
#[derive(Debug, Clone)]
pub(super) enum SystemEvent {
    /// System startup
    SystemStartup {
        version: String,
        environment: String, // dev, staging, prod
    },

    /// System shutdown
    SystemShutdown { reason: String, graceful: bool },

    /// Health check
    HealthCheck {
        status: String, // healthy, degraded, unhealthy
        details: Vec<String>,
    },

    /// Configuration changed
    ConfigurationChanged {
        setting: String,
        old_value: Option<String>,
        new_value: String,
    },

    /// Service connected
    ServiceConnected {
        service_name: String,
        endpoint: String,
    },

    /// Service disconnected
    ServiceDisconnected {
        service_name: String,
        reason: String,
    },
}

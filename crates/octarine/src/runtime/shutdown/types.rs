//! Shutdown types and data structures
//!
//! This module contains the core types used by the shutdown coordination system.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::observe::Problem;

// ============================================================================
// Type Aliases
// ============================================================================

/// Result type for shutdown hook execution
pub type HookResult = Result<(), Problem>;

/// A shutdown hook function that returns a pinned future
pub type HookFn = Box<dyn Fn() -> Pin<Box<dyn Future<Output = HookResult> + Send>> + Send + Sync>;

// ============================================================================
// ShutdownSignal
// ============================================================================

/// The signal that triggered shutdown
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownSignal {
    /// SIGINT (Ctrl+C)
    Interrupt,
    /// SIGTERM
    Terminate,
    /// Manual trigger via `trigger()`
    Manual,
    /// Timeout during shutdown
    Timeout,
}

// ============================================================================
// ShutdownReason
// ============================================================================

/// Reason for triggering shutdown
///
/// Provides structured context about why shutdown was initiated.
/// This is useful for logging, debugging, and compliance auditing.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::shutdown::{ShutdownCoordinator, ShutdownReason};
///
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// let coordinator = ShutdownCoordinator::new();
///
/// // Trigger shutdown with a reason
/// coordinator.trigger_with_reason(ShutdownReason::FatalError {
///     component: "database".to_string(),
///     message: "Connection pool exhausted".to_string(),
/// }).await;
/// # });
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownReason {
    /// Normal shutdown requested by operator
    Requested,
    /// Fatal error that cannot be recovered
    FatalError {
        /// Component that encountered the error
        component: String,
        /// Error description
        message: String,
    },
    /// Resource exhaustion (memory, connections, etc.)
    ResourceExhausted {
        /// Resource type
        resource: String,
        /// Current usage
        current: String,
        /// Maximum allowed
        limit: String,
    },
    /// Configuration error detected
    ConfigurationError {
        /// Configuration key or section
        key: String,
        /// Error description
        message: String,
    },
    /// Dependency failure (external service unavailable)
    DependencyFailure {
        /// Dependency name
        dependency: String,
        /// Failure description
        message: String,
    },
    /// Maintenance shutdown (planned)
    Maintenance {
        /// Reason for maintenance
        reason: String,
    },
    /// Custom reason
    Custom {
        /// Custom reason code
        code: String,
        /// Custom message
        message: String,
    },
}

impl std::fmt::Display for ShutdownReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Requested => write!(f, "shutdown requested"),
            Self::FatalError { component, message } => {
                write!(f, "fatal error in {}: {}", component, message)
            }
            Self::ResourceExhausted {
                resource,
                current,
                limit,
            } => {
                write!(f, "{} exhausted ({} / {})", resource, current, limit)
            }
            Self::ConfigurationError { key, message } => {
                write!(f, "configuration error for '{}': {}", key, message)
            }
            Self::DependencyFailure {
                dependency,
                message,
            } => {
                write!(f, "dependency '{}' failed: {}", dependency, message)
            }
            Self::Maintenance { reason } => write!(f, "maintenance: {}", reason),
            Self::Custom { code, message } => write!(f, "[{}] {}", code, message),
        }
    }
}

impl std::fmt::Display for ShutdownSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Interrupt => write!(f, "SIGINT"),
            Self::Terminate => write!(f, "SIGTERM"),
            Self::Manual => write!(f, "manual"),
            Self::Timeout => write!(f, "timeout"),
        }
    }
}

// ============================================================================
// ShutdownPhase
// ============================================================================

/// Current phase of shutdown
///
/// The shutdown process follows these phases:
///
/// ```text
/// Running → Draining → ShuttingDown → Complete
///                ↓            ↓
///          ForcedShutdown ←───┘
/// ```
///
/// - **Running**: Normal operation, accepting traffic
/// - **Draining**: Stop accepting new traffic, wait for in-flight requests
/// - **ShuttingDown**: Running shutdown hooks
/// - **Complete**: All hooks finished successfully
/// - **ForcedShutdown**: Timeout reached, forced exit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownPhase {
    /// Normal operation
    Running,
    /// Draining in-flight requests (not accepting new traffic)
    Draining,
    /// Shutdown initiated, running hooks
    ShuttingDown,
    /// All hooks completed
    Complete,
    /// Forced shutdown due to timeout
    ForcedShutdown,
}

impl ShutdownPhase {
    /// Check if the service should accept new traffic
    ///
    /// Returns `true` only in the `Running` phase.
    pub fn accepts_traffic(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Check if shutdown has been initiated
    ///
    /// Returns `true` for `Draining`, `ShuttingDown`, `Complete`, and `ForcedShutdown`.
    pub fn is_shutdown_initiated(&self) -> bool {
        !matches!(self, Self::Running)
    }

    /// Check if shutdown is still in progress
    ///
    /// Returns `true` for `Draining` and `ShuttingDown`.
    pub fn is_in_progress(&self) -> bool {
        matches!(self, Self::Draining | Self::ShuttingDown)
    }

    /// Check if shutdown has finished (successfully or not)
    ///
    /// Returns `true` for `Complete` and `ForcedShutdown`.
    pub fn is_finished(&self) -> bool {
        matches!(self, Self::Complete | Self::ForcedShutdown)
    }
}

impl std::fmt::Display for ShutdownPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::Draining => write!(f, "draining"),
            Self::ShuttingDown => write!(f, "shutting_down"),
            Self::Complete => write!(f, "complete"),
            Self::ForcedShutdown => write!(f, "forced_shutdown"),
        }
    }
}

// ============================================================================
// ShutdownHealthStatus
// ============================================================================

/// Health status for Kubernetes-style probes
///
/// This enum provides detailed health information that can be used with
/// liveness and readiness probes.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::shutdown::{ShutdownCoordinator, ShutdownHealthStatus};
///
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// let coordinator = ShutdownCoordinator::new();
///
/// // Check health for readiness probe
/// match coordinator.health_status().await {
///     ShutdownHealthStatus::Healthy => { /* Accept traffic */ }
///     ShutdownHealthStatus::ShuttingDown { phase, .. } => { /* Drain connections */ }
///     ShutdownHealthStatus::Unhealthy { reason } => { /* Report unhealthy */ }
/// }
/// # });
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownHealthStatus {
    /// Service is healthy and accepting traffic
    Healthy,
    /// Service is shutting down (drain connections)
    ShuttingDown {
        /// Current shutdown phase
        phase: ShutdownPhase,
        /// Signal that triggered shutdown
        signal: Option<ShutdownSignal>,
    },
    /// Service is unhealthy (custom reason)
    Unhealthy {
        /// Reason for unhealthy status
        reason: String,
    },
}

impl ShutdownHealthStatus {
    /// Check if the status indicates the service is healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Check if the status indicates the service is shutting down
    pub fn is_shutting_down(&self) -> bool {
        matches!(self, Self::ShuttingDown { .. })
    }

    /// Check if the status indicates the service should accept traffic
    ///
    /// Returns `true` only when `Healthy`. Use this for readiness probes.
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// Check if the status indicates the service is alive
    ///
    /// Returns `true` when `Healthy` or `ShuttingDown`. Use this for liveness probes.
    /// Even during shutdown, the service is still "alive" and processing.
    pub fn is_alive(&self) -> bool {
        matches!(self, Self::Healthy | Self::ShuttingDown { .. })
    }
}

impl std::fmt::Display for ShutdownHealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::ShuttingDown { phase, signal } => {
                if let Some(sig) = signal {
                    write!(f, "shutting_down ({}, triggered by {})", phase, sig)
                } else {
                    write!(f, "shutting_down ({})", phase)
                }
            }
            Self::Unhealthy { reason } => write!(f, "unhealthy: {}", reason),
        }
    }
}

// ============================================================================
// ShutdownStats
// ============================================================================

/// Statistics about shutdown execution
#[derive(Debug, Clone, Default)]
pub struct ShutdownStats {
    /// Total hooks registered
    pub hooks_registered: usize,
    /// Hooks successfully executed
    pub hooks_succeeded: usize,
    /// Hooks that failed (returned error)
    pub hooks_failed: usize,
    /// Hooks that timed out (individual hook timeout)
    pub hooks_timed_out: usize,
    /// Hooks skipped due to global timeout
    pub hooks_skipped: usize,
    /// Total shutdown duration in milliseconds
    pub duration_ms: u64,
}

// ============================================================================
// Hook Handle
// ============================================================================

/// A handle to a registered shutdown hook
///
/// This handle can be used to remove a hook after it has been registered.
/// The handle is returned by `add_hook` and `add_hook_with_config`.
///
/// # Example
///
/// ```rust,no_run
/// use octarine::runtime::shutdown::ShutdownCoordinator;
///
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// let coordinator = ShutdownCoordinator::new();
///
/// // Register a hook and keep the handle
/// let handle = coordinator.add_hook("cleanup", || async { Ok(()) }).await;
///
/// // Later, remove the hook if needed
/// coordinator.deregister_hook(handle).await;
/// # });
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HookHandle(pub(super) u64);

impl HookHandle {
    /// Get the internal ID of this hook
    pub fn id(&self) -> u64 {
        self.0
    }
}

// ============================================================================
// Internal Types
// ============================================================================

/// Represents a registered shutdown hook (internal)
pub(super) struct ShutdownHook {
    /// Unique identifier for this hook
    pub id: u64,
    /// Name of the hook for logging
    pub name: String,
    /// The hook function
    pub func: HookFn,
    /// Priority (lower runs first)
    pub priority: usize,
    /// Individual timeout for this hook (None = use global timeout)
    pub timeout: Option<Duration>,
    /// Maximum retry attempts for transient failures (0 = no retries)
    pub max_retries: u32,
    /// Delay between retry attempts
    pub retry_delay: Duration,
}

// ============================================================================
// Hook Configuration
// ============================================================================

/// Configuration for a shutdown hook
///
/// Use this builder to configure advanced hook options like individual
/// timeouts, explicit priority, and retry behavior.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::shutdown::HookConfig;
/// use std::time::Duration;
///
/// let config = HookConfig::new("cleanup_connections")
///     .with_timeout(Duration::from_secs(10))
///     .with_priority(100)
///     .with_retries(3, Duration::from_millis(100));
/// ```
#[derive(Debug, Clone)]
pub struct HookConfig {
    /// Name of the hook for logging
    pub(super) name: String,
    /// Individual timeout for this hook
    pub(super) timeout: Option<Duration>,
    /// Explicit priority (None = auto-assign based on registration order)
    pub(super) priority: Option<usize>,
    /// Maximum retry attempts (0 = no retries)
    pub(super) max_retries: u32,
    /// Delay between retry attempts
    pub(super) retry_delay: Duration,
}

impl HookConfig {
    /// Create a new hook configuration with the given name
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            timeout: None,
            priority: None,
            max_retries: 0,
            retry_delay: Duration::from_millis(100),
        }
    }

    /// Set the individual timeout for this hook
    ///
    /// If not set, the hook will use a share of the global shutdown timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set an explicit priority for this hook
    ///
    /// Lower values run first. If not set, priority is assigned based on
    /// registration order.
    #[must_use]
    pub fn with_priority(mut self, priority: usize) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Set retry behavior for transient failures
    ///
    /// When a hook fails, it will be retried up to `max_retries` times with
    /// `delay` between attempts. This is useful for hooks that may fail due
    /// to temporary conditions (network timeouts, resource contention, etc.).
    ///
    /// # Arguments
    ///
    /// * `max_retries` - Maximum number of retry attempts (0 = no retries)
    /// * `delay` - Time to wait between retry attempts
    #[must_use]
    pub fn with_retries(mut self, max_retries: u32, delay: Duration) -> Self {
        self.max_retries = max_retries;
        self.retry_delay = delay;
        self
    }
}

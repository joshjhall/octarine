//! Error types for database pool operations

use thiserror::Error;

/// Errors that can occur during pool operations
#[derive(Debug, Error)]
pub enum PoolError {
    /// Configuration error (missing or invalid values)
    #[error("pool configuration error: {0}")]
    Config(String),

    /// Connection error
    #[error("connection error: {0}")]
    Connection(String),

    /// Pool is shutting down
    #[error("pool is shutting down")]
    ShuttingDown,

    /// Health check failed
    #[error("health check failed: {0}")]
    HealthCheckFailed(String),

    /// Timeout waiting for connection
    #[error("timeout waiting for connection")]
    Timeout,

    /// Underlying sqlx error
    #[cfg(feature = "postgres")]
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

// Layer 3 conversion: PoolError -> observe::Problem
impl From<PoolError> for crate::observe::Problem {
    fn from(err: PoolError) -> Self {
        match err {
            PoolError::Config(msg) => crate::observe::Problem::config(msg),
            PoolError::Connection(msg) => crate::observe::Problem::network(msg),
            PoolError::ShuttingDown => {
                crate::observe::Problem::operation_failed("pool is shutting down")
            }
            PoolError::HealthCheckFailed(msg) => crate::observe::Problem::database(msg),
            PoolError::Timeout => {
                crate::observe::Problem::timeout("waiting for database connection")
            }
            #[cfg(feature = "postgres")]
            PoolError::Sqlx(e) => crate::observe::Problem::database(e.to_string()),
        }
    }
}

//! Core database configuration primitives
//!
//! Internal configuration type for database connections. For the public API,
//! see `runtime::database::DatabaseConfig`.

use std::time::Duration;

/// Core database connection configuration (internal primitive)
///
/// This is the internal representation. The public API is
/// `octarine::runtime::database::DatabaseConfig`.
#[derive(Debug, Clone)]
pub(crate) struct DatabaseConfigCore {
    /// Database connection URL
    ///
    /// Format: `postgres://user:password@host:port/database`
    pub url: String,

    /// Maximum number of connections in the pool
    pub max_connections: u32,

    /// Minimum number of idle connections to maintain
    pub min_connections: u32,

    /// Timeout for acquiring a connection from the pool
    pub acquire_timeout: Duration,

    /// Timeout for establishing a new connection
    pub connect_timeout: Duration,

    /// Maximum time a connection can remain idle before being closed
    pub idle_timeout: Duration,

    /// Maximum lifetime of a connection (for credential rotation)
    pub max_lifetime: Duration,
}

impl Default for DatabaseConfigCore {
    fn default() -> Self {
        Self {
            url: String::new(),
            max_connections: 10,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(1800),
        }
    }
}

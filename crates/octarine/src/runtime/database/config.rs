//! Database pool configuration
//!
//! Public configuration types for database connection pools. This module
//! re-defines the primitive types as the public API, following the pattern
//! where primitives are internal and public types are explicitly defined.

use std::time::Duration;

use super::error::PoolError;

// =============================================================================
// DatabaseConfig - Public API (re-defined from primitive)
// =============================================================================

/// Database connection configuration
///
/// Core settings for establishing database connections. This is the public API
/// type - the primitive implementation is internal.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::database::DatabaseConfig;
/// use std::time::Duration;
///
/// let config = DatabaseConfig::builder()
///     .url("postgres://localhost/mydb")
///     .max_connections(20)
///     .connect_timeout(Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// assert_eq!(config.max_connections(), 20);
/// ```
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Database connection URL
    url: String,

    /// Maximum number of connections in the pool
    max_connections: u32,

    /// Minimum number of idle connections to maintain
    min_connections: u32,

    /// Timeout for acquiring a connection from the pool
    acquire_timeout: Duration,

    /// Timeout for establishing a new connection
    connect_timeout: Duration,

    /// Maximum time a connection can remain idle before being closed
    idle_timeout: Duration,

    /// Maximum lifetime of a connection (for credential rotation)
    max_lifetime: Duration,
}

impl DatabaseConfig {
    /// Create a new configuration builder
    pub fn builder() -> DatabaseConfigBuilder {
        DatabaseConfigBuilder::default()
    }

    /// Load configuration from environment variables
    ///
    /// Reads the following environment variables:
    /// - `DATABASE_URL` (required)
    /// - `DB_MAX_CONNECTIONS` (default: 10)
    /// - `DB_MIN_CONNECTIONS` (default: 1)
    /// - `DB_ACQUIRE_TIMEOUT` (default: 30 seconds)
    /// - `DB_CONNECT_TIMEOUT` (default: 30 seconds)
    /// - `DB_IDLE_TIMEOUT` (default: 600 seconds)
    /// - `DB_MAX_LIFETIME` (default: 1800 seconds)
    pub fn from_env() -> Result<Self, PoolError> {
        Self::from_env_with_prefix("")
    }

    /// Load configuration from environment variables with a prefix
    ///
    /// For example, with prefix "APP", reads `APP_DATABASE_URL`, etc.
    pub fn from_env_with_prefix(prefix: &str) -> Result<Self, PoolError> {
        let prefix = if prefix.is_empty() {
            String::new()
        } else {
            format!("{prefix}_")
        };

        let url = std::env::var(format!("{prefix}DATABASE_URL"))
            .map_err(|_| PoolError::Config("DATABASE_URL is required".to_string()))?;

        let max_connections = parse_env_u32(&format!("{prefix}DB_MAX_CONNECTIONS"), 10)?;
        let min_connections = parse_env_u32(&format!("{prefix}DB_MIN_CONNECTIONS"), 1)?;
        let acquire_timeout = parse_env_duration(&format!("{prefix}DB_ACQUIRE_TIMEOUT"), 30)?;
        let connect_timeout = parse_env_duration(&format!("{prefix}DB_CONNECT_TIMEOUT"), 30)?;
        let idle_timeout = parse_env_duration(&format!("{prefix}DB_IDLE_TIMEOUT"), 600)?;
        let max_lifetime = parse_env_duration(&format!("{prefix}DB_MAX_LIFETIME"), 1800)?;

        Ok(Self {
            url,
            max_connections,
            min_connections,
            acquire_timeout,
            connect_timeout,
            idle_timeout,
            max_lifetime,
        })
    }

    /// Production configuration with sensible defaults
    ///
    /// - 10 max connections
    /// - 30 second timeouts
    /// - 10 minute idle timeout
    /// - 30 minute max lifetime
    pub fn production(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            max_connections: 10,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(1800),
        }
    }

    /// Development configuration with smaller pool
    ///
    /// - 5 max connections
    /// - 5 second timeouts
    /// - 1 minute idle timeout
    /// - 5 minute max lifetime
    pub fn development(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(300),
        }
    }

    /// Test configuration with minimal pool
    ///
    /// - 2 max connections
    /// - 2 second timeouts
    /// - Short lifetimes
    pub fn test(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            max_connections: 2,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(30),
            max_lifetime: Duration::from_secs(60),
        }
    }

    // Accessors (controlled public API)

    /// Get the database URL
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get maximum connections
    pub fn max_connections(&self) -> u32 {
        self.max_connections
    }

    /// Get minimum connections
    pub fn min_connections(&self) -> u32 {
        self.min_connections
    }

    /// Get acquire timeout
    pub fn acquire_timeout(&self) -> Duration {
        self.acquire_timeout
    }

    /// Get connect timeout
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Get idle timeout
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Get max lifetime
    pub fn max_lifetime(&self) -> Duration {
        self.max_lifetime
    }
}

impl Default for DatabaseConfig {
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

// Manual Debug implementation to redact credentials
impl std::fmt::Display for DatabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DatabaseConfig {{ url: [REDACTED], max_connections: {}, min_connections: {} }}",
            self.max_connections, self.min_connections
        )
    }
}

/// Builder for DatabaseConfig
#[derive(Debug, Default)]
pub struct DatabaseConfigBuilder {
    url: Option<String>,
    max_connections: Option<u32>,
    min_connections: Option<u32>,
    acquire_timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
    max_lifetime: Option<Duration>,
}

impl DatabaseConfigBuilder {
    /// Set the database URL (required)
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Set maximum connections (default: 10)
    pub fn max_connections(mut self, n: u32) -> Self {
        self.max_connections = Some(n);
        self
    }

    /// Set minimum idle connections (default: 1)
    pub fn min_connections(mut self, n: u32) -> Self {
        self.min_connections = Some(n);
        self
    }

    /// Set acquire timeout (default: 30 seconds)
    pub fn acquire_timeout(mut self, timeout: Duration) -> Self {
        self.acquire_timeout = Some(timeout);
        self
    }

    /// Set connection timeout (default: 30 seconds)
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Set idle timeout (default: 600 seconds)
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = Some(timeout);
        self
    }

    /// Set max connection lifetime (default: 1800 seconds)
    pub fn max_lifetime(mut self, lifetime: Duration) -> Self {
        self.max_lifetime = Some(lifetime);
        self
    }

    /// Build the configuration
    ///
    /// # Errors
    ///
    /// Returns an error if URL is not set or is empty.
    pub fn build(self) -> Result<DatabaseConfig, PoolError> {
        let url = self
            .url
            .ok_or_else(|| PoolError::Config("database URL is required".to_string()))?;

        if url.is_empty() {
            return Err(PoolError::Config(
                "database URL cannot be empty".to_string(),
            ));
        }

        let defaults = DatabaseConfig::default();

        Ok(DatabaseConfig {
            url,
            max_connections: self.max_connections.unwrap_or(defaults.max_connections),
            min_connections: self.min_connections.unwrap_or(defaults.min_connections),
            acquire_timeout: self.acquire_timeout.unwrap_or(defaults.acquire_timeout),
            connect_timeout: self.connect_timeout.unwrap_or(defaults.connect_timeout),
            idle_timeout: self.idle_timeout.unwrap_or(defaults.idle_timeout),
            max_lifetime: self.max_lifetime.unwrap_or(defaults.max_lifetime),
        })
    }
}

// =============================================================================
// PoolConfig - Composes DatabaseConfig with pool lifecycle settings
// =============================================================================

/// Managed pool configuration
///
/// Combines [`DatabaseConfig`] with pool lifecycle settings like drain timeout
/// and shutdown hook naming. Use this when creating a `ManagedPool`.
///
/// # Example
///
/// ```rust
/// use octarine::runtime::database::{DatabaseConfig, PoolConfig};
/// use std::time::Duration;
///
/// let db_config = DatabaseConfig::production("postgres://localhost/mydb");
/// let pool_config = PoolConfig::new(db_config)
///     .with_name("primary")
///     .with_drain_timeout(Duration::from_secs(60));
/// ```
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Database connection configuration
    database: DatabaseConfig,

    /// Name for this pool (used in metrics, logs, shutdown hooks)
    name: String,

    /// Timeout for draining connections during shutdown
    drain_timeout: Duration,
}

impl PoolConfig {
    /// Create a new pool configuration from database config
    pub fn new(database: DatabaseConfig) -> Self {
        Self {
            database,
            name: "database-pool".to_string(),
            drain_timeout: Duration::from_secs(30),
        }
    }

    /// Set the pool name (used in metrics, logs, shutdown hooks)
    ///
    /// Useful when running multiple pools (e.g., "primary", "replica", "analytics").
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set the drain timeout for graceful shutdown
    ///
    /// This is how long to wait for in-flight queries during shutdown.
    #[must_use]
    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    /// Get the database configuration
    pub fn database(&self) -> &DatabaseConfig {
        &self.database
    }

    /// Get the pool name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the drain timeout
    pub fn drain_timeout(&self) -> Duration {
        self.drain_timeout
    }

    // Convenience accessors that delegate to database config

    /// Get the database URL
    pub fn url(&self) -> &str {
        self.database.url()
    }

    /// Get maximum connections
    pub fn max_connections(&self) -> u32 {
        self.database.max_connections()
    }

    /// Get minimum connections
    pub fn min_connections(&self) -> u32 {
        self.database.min_connections()
    }

    /// Get acquire timeout
    pub fn acquire_timeout(&self) -> Duration {
        self.database.acquire_timeout()
    }

    /// Get connect timeout
    pub fn connect_timeout(&self) -> Duration {
        self.database.connect_timeout()
    }

    /// Get idle timeout
    pub fn idle_timeout(&self) -> Duration {
        self.database.idle_timeout()
    }

    /// Get max lifetime
    pub fn max_lifetime(&self) -> Duration {
        self.database.max_lifetime()
    }
}

// Convenience: Create PoolConfig directly from DatabaseConfig
impl From<DatabaseConfig> for PoolConfig {
    fn from(database: DatabaseConfig) -> Self {
        Self::new(database)
    }
}

// =============================================================================
// Helper functions
// =============================================================================

/// Parse environment variable as u32 with default
fn parse_env_u32(name: &str, default: u32) -> Result<u32, PoolError> {
    match std::env::var(name) {
        Ok(val) => val
            .parse()
            .map_err(|_| PoolError::Config(format!("{name} must be a positive integer"))),
        Err(_) => Ok(default),
    }
}

/// Parse environment variable as Duration (seconds) with default
fn parse_env_duration(name: &str, default_secs: u64) -> Result<Duration, PoolError> {
    match std::env::var(name) {
        Ok(val) => {
            let secs: u64 = val.parse().map_err(|_| {
                PoolError::Config(format!("{name} must be a positive integer (seconds)"))
            })?;
            Ok(Duration::from_secs(secs))
        }
        Err(_) => Ok(Duration::from_secs(default_secs)),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_database_config_builder_requires_url() {
        let result = DatabaseConfigBuilder::default().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_database_config_builder_rejects_empty_url() {
        let result = DatabaseConfigBuilder::default().url("").build();
        assert!(result.is_err());
    }

    #[test]
    fn test_database_config_builder_with_url() {
        let config = DatabaseConfigBuilder::default()
            .url("postgres://localhost/test")
            .build()
            .expect("build should succeed with valid URL");

        assert_eq!(config.url(), "postgres://localhost/test");
        assert_eq!(config.max_connections(), 10);
    }

    #[test]
    fn test_database_config_builder_custom_values() {
        let config = DatabaseConfigBuilder::default()
            .url("postgres://localhost/test")
            .max_connections(20)
            .min_connections(5)
            .connect_timeout(Duration::from_secs(60))
            .build()
            .expect("build should succeed with valid config");

        assert_eq!(config.max_connections(), 20);
        assert_eq!(config.min_connections(), 5);
        assert_eq!(config.connect_timeout(), Duration::from_secs(60));
    }

    #[test]
    fn test_database_config_presets() {
        let prod = DatabaseConfig::production("postgres://localhost/prod");
        assert_eq!(prod.max_connections(), 10);
        assert_eq!(prod.idle_timeout(), Duration::from_secs(600));

        let dev = DatabaseConfig::development("postgres://localhost/dev");
        assert_eq!(dev.max_connections(), 5);
        assert_eq!(dev.connect_timeout(), Duration::from_secs(5));

        let test = DatabaseConfig::test("postgres://localhost/test");
        assert_eq!(test.max_connections(), 2);
    }

    #[test]
    fn test_pool_config_composition() {
        let db_config = DatabaseConfig::production("postgres://localhost/mydb");
        let pool_config = PoolConfig::new(db_config)
            .with_name("primary")
            .with_drain_timeout(Duration::from_secs(60));

        assert_eq!(pool_config.name(), "primary");
        assert_eq!(pool_config.drain_timeout(), Duration::from_secs(60));
        assert_eq!(pool_config.max_connections(), 10); // Delegates to database config
    }

    #[test]
    fn test_pool_config_from_database_config() {
        let db_config = DatabaseConfig::test("postgres://localhost/test");
        let pool_config: PoolConfig = db_config.into();

        assert_eq!(pool_config.name(), "database-pool");
        assert_eq!(pool_config.max_connections(), 2);
    }

    #[test]
    fn test_database_config_display_redacts_url() {
        let config = DatabaseConfig::production("postgres://user:secret@localhost/db");
        let display = format!("{config}");

        assert!(display.contains("[REDACTED]"));
        assert!(!display.contains("secret"));
    }

    #[test]
    fn test_pool_config_builder_chaining() {
        let db_config = DatabaseConfig::test("postgres://localhost/test");
        let pool_config = PoolConfig::new(db_config)
            .with_name("my-pool")
            .with_drain_timeout(Duration::from_secs(120));

        assert_eq!(pool_config.name(), "my-pool");
        assert_eq!(pool_config.drain_timeout(), Duration::from_secs(120));
    }

    #[test]
    fn test_database_config_accessors() {
        let config = DatabaseConfig::builder()
            .url("postgres://localhost/test")
            .max_connections(20)
            .min_connections(5)
            .acquire_timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(15))
            .idle_timeout(Duration::from_secs(300))
            .max_lifetime(Duration::from_secs(1800))
            .build()
            .expect("config should build");

        assert_eq!(config.max_connections(), 20);
        assert_eq!(config.min_connections(), 5);
        assert_eq!(config.acquire_timeout(), Duration::from_secs(10));
        assert_eq!(config.connect_timeout(), Duration::from_secs(15));
        assert_eq!(config.idle_timeout(), Duration::from_secs(300));
        assert_eq!(config.max_lifetime(), Duration::from_secs(1800));
    }

    #[test]
    fn test_pool_config_delegates_to_database_config() {
        let db_config = DatabaseConfig::builder()
            .url("postgres://localhost/test")
            .max_connections(15)
            .connect_timeout(Duration::from_secs(20))
            .build()
            .expect("config should build");

        let pool_config = PoolConfig::new(db_config);

        // PoolConfig should delegate these to inner DatabaseConfig
        assert_eq!(pool_config.max_connections(), 15);
        assert_eq!(pool_config.connect_timeout(), Duration::from_secs(20));
        assert!(pool_config.url().contains("localhost"));
    }

    #[test]
    fn test_database_config_default_values() {
        let config = DatabaseConfig::builder()
            .url("postgres://localhost/test")
            .build()
            .expect("config should build");

        // Verify defaults match documented values
        assert_eq!(config.max_connections(), 10);
        assert_eq!(config.min_connections(), 1);
        assert_eq!(config.acquire_timeout(), Duration::from_secs(30));
        assert_eq!(config.connect_timeout(), Duration::from_secs(30));
        assert_eq!(config.idle_timeout(), Duration::from_secs(600));
        assert_eq!(config.max_lifetime(), Duration::from_secs(1800));
    }

    #[test]
    fn test_pool_config_default_values() {
        let db_config = DatabaseConfig::test("postgres://localhost/test");
        let pool_config = PoolConfig::new(db_config);

        // Verify pool-specific defaults
        assert_eq!(pool_config.name(), "database-pool");
        assert_eq!(pool_config.drain_timeout(), Duration::from_secs(30));
    }
}

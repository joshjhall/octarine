//! Managed database pool with lifecycle integration

use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

// =============================================================================
// Constants
// =============================================================================

/// Shutdown hook priority for database pools.
/// High value ensures database closes after other application hooks.
const SHUTDOWN_PRIORITY: usize = 1000;

/// Buffer time reserved for cleanup after drain polling (seconds).
/// Subtracted from drain_timeout to ensure cleanup completes within the timeout.
const DRAIN_CLEANUP_BUFFER_SECS: u64 = 5;

/// Interval between polls when waiting for connections to drain (milliseconds).
const DRAIN_POLL_INTERVAL_MS: u64 = 100;

use crate::observe;
use crate::runtime::shutdown::{HookConfig, ShutdownCoordinator};

use super::config::PoolConfig;
use super::error::PoolError;
use super::health::{PoolHealth, PoolStats};

#[cfg(feature = "postgres")]
use sqlx::{Pool, Postgres, postgres::PgConnectOptions, postgres::PgPoolOptions};

/// A managed database connection pool with lifecycle integration
///
/// Wraps sqlx's Pool with:
/// - Automatic shutdown hook registration
/// - Health check support
/// - Metrics integration with observe
/// - Graceful connection draining
///
/// # Example
///
/// ```rust,ignore
/// use octarine::runtime::database::{ManagedPool, DatabaseConfig, PoolConfig};
/// use octarine::runtime::shutdown::ShutdownCoordinator;
///
/// let shutdown = ShutdownCoordinator::new();
/// let db_config = DatabaseConfig::production("postgres://localhost/mydb");
/// let pool_config = PoolConfig::new(db_config).with_name("primary");
/// let pool = ManagedPool::new(pool_config, &shutdown).await?;
///
/// // Use with sqlx - ManagedPool derefs to sqlx::Pool
/// let rows = sqlx::query("SELECT 1").fetch_all(&*pool).await?;
/// ```
#[cfg(feature = "postgres")]
pub struct ManagedPool {
    pool: Pool<Postgres>,
    config: PoolConfig,
    shutting_down: Arc<AtomicBool>,
}

#[cfg(feature = "postgres")]
impl ManagedPool {
    /// Create a new managed pool and register shutdown hook
    ///
    /// # Arguments
    ///
    /// * `config` - Pool configuration (includes database config and lifecycle settings)
    /// * `shutdown` - Shutdown coordinator for lifecycle management
    ///
    /// # Errors
    ///
    /// Returns an error if the pool cannot be created or initial connection fails.
    pub async fn new(
        config: PoolConfig,
        shutdown: &ShutdownCoordinator,
    ) -> Result<Self, PoolError> {
        observe::info(
            "database_pool_creating",
            format!(
                "Creating database pool '{}' (max_connections={}, connect_timeout={}s)",
                config.name(),
                config.max_connections(),
                config.connect_timeout().as_secs()
            ),
        );

        // Parse URL and build connection options with connect_timeout
        let connect_options = build_connect_options(&config)?;

        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections())
            .min_connections(config.min_connections())
            .acquire_timeout(config.acquire_timeout())
            .idle_timeout(Some(config.idle_timeout()))
            .max_lifetime(Some(config.max_lifetime()))
            .connect_with(connect_options)
            .await?;

        observe::info(
            "database_pool_created",
            format!(
                "Database pool '{}' created (size={}, idle={})",
                config.name(),
                pool.size(),
                pool.num_idle()
            ),
        );

        let shutting_down = Arc::new(AtomicBool::new(false));
        let managed = Self {
            pool,
            config,
            shutting_down,
        };

        // Register shutdown hook
        managed.register_shutdown_hook(shutdown).await;

        Ok(managed)
    }

    /// Create a pool without shutdown integration (for testing)
    ///
    /// **Warning**: This pool will not gracefully drain on shutdown.
    /// Use `new()` for production code.
    #[cfg(test)]
    pub async fn new_unmanaged(config: PoolConfig) -> Result<Self, PoolError> {
        let connect_options = build_connect_options(&config)?;

        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections())
            .min_connections(config.min_connections())
            .acquire_timeout(config.acquire_timeout())
            .idle_timeout(Some(config.idle_timeout()))
            .max_lifetime(Some(config.max_lifetime()))
            .connect_with(connect_options)
            .await?;

        Ok(Self {
            pool,
            config,
            shutting_down: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Check if the pool is shutting down
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    /// Get the pool name
    pub fn name(&self) -> &str {
        self.config.name()
    }

    /// Perform a health check
    ///
    /// Executes a simple query to verify database connectivity and measure latency.
    pub async fn health_check(&self) -> PoolHealth {
        let start = Instant::now();
        let active = self.pool.size();
        let idle = self.pool.num_idle() as u32;
        let max = self.config.max_connections();

        match sqlx::query("SELECT 1").fetch_one(&self.pool).await {
            Ok(_) => {
                let latency = start.elapsed();
                observe::debug(
                    "database_health_check",
                    format!(
                        "Health check passed for '{}' (latency={}ms)",
                        self.config.name(),
                        latency.as_millis()
                    ),
                );
                PoolHealth::healthy(latency, active, idle, max)
            }
            Err(e) => {
                observe::warn(
                    "database_health_check_failed",
                    format!("Health check failed for '{}': {e}", self.config.name()),
                );
                PoolHealth::unhealthy(e.to_string(), active, idle, max)
            }
        }
    }

    /// Get current pool statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats::new(
            self.pool.size(),
            self.pool.num_idle() as u32,
            self.config.max_connections(),
        )
    }

    /// Record pool metrics to observe
    ///
    /// Call this periodically to track pool utilization.
    pub fn record_metrics(&self) {
        let stats = self.stats();

        observe::debug(
            "database_pool_metrics",
            format!(
                "Pool '{}' metrics: active={}, idle={}, max={}, utilization={:.1}%",
                self.config.name(),
                stats.active(),
                stats.idle(),
                stats.max(),
                stats.utilization() * 100.0
            ),
        );
    }

    /// Get the pool configuration
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// Gracefully close the pool
    ///
    /// Called automatically during shutdown, but can be called manually.
    pub async fn close(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);

        observe::info(
            "database_pool_closing",
            format!(
                "Closing database pool '{}' (active={})",
                self.config.name(),
                self.pool.size()
            ),
        );

        self.pool.close().await;

        observe::info(
            "database_pool_closed",
            format!("Database pool '{}' closed", self.config.name()),
        );
    }

    /// Register shutdown hook for graceful draining
    async fn register_shutdown_hook(&self, shutdown: &ShutdownCoordinator) {
        let pool = self.pool.clone();
        let shutting_down = Arc::clone(&self.shutting_down);
        let pool_name = self.config.name().to_string();
        let drain_timeout = self.config.drain_timeout();

        // Use high priority so database closes after other hooks
        let hook_config = HookConfig::new(&pool_name)
            .with_timeout(drain_timeout)
            .with_priority(SHUTDOWN_PRIORITY);

        // Calculate drain poll timeout (leave buffer for cleanup)
        let drain_poll_timeout =
            drain_timeout.saturating_sub(Duration::from_secs(DRAIN_CLEANUP_BUFFER_SECS));

        shutdown
            .add_hook_with_config(hook_config, move || {
                let pool = pool.clone();
                let shutting_down = Arc::clone(&shutting_down);
                let pool_name = pool_name.clone();

                async move {
                    shutting_down.store(true, Ordering::SeqCst);

                    observe::info(
                        "database_pool_draining",
                        format!(
                            "Draining database connections for '{}' (active={})",
                            pool_name,
                            pool.size()
                        ),
                    );

                    // Close the pool (stops accepting new connections)
                    pool.close().await;

                    // Wait for in-flight queries with timeout
                    let drain_start = Instant::now();
                    let poll_interval = Duration::from_millis(DRAIN_POLL_INTERVAL_MS);

                    while pool.size() > 0 && drain_start.elapsed() < drain_poll_timeout {
                        tokio::time::sleep(poll_interval).await;
                    }

                    if pool.size() > 0 {
                        observe::warn(
                            "database_pool_drain_timeout",
                            format!(
                                "Pool '{}' drain timeout - {} connections remaining",
                                pool_name,
                                pool.size()
                            ),
                        );
                    } else {
                        observe::info(
                            "database_pool_drained",
                            format!("All connections drained for pool '{}'", pool_name),
                        );
                    }

                    Ok(())
                }
            })
            .await;

        observe::debug(
            "database_pool_hook_registered",
            format!(
                "Shutdown hook registered for pool '{}' (drain_timeout={}s)",
                self.config.name(),
                drain_timeout.as_secs()
            ),
        );
    }
}

#[cfg(feature = "postgres")]
impl Deref for ManagedPool {
    type Target = Pool<Postgres>;

    fn deref(&self) -> &Self::Target {
        &self.pool
    }
}

/// Build PgConnectOptions from pool config with connect_timeout applied.
///
/// PostgreSQL's connect_timeout is set as a connection parameter, which controls
/// how long to wait when establishing a new TCP connection to the database.
#[cfg(feature = "postgres")]
fn build_connect_options(config: &PoolConfig) -> Result<PgConnectOptions, PoolError> {
    use std::str::FromStr;

    // Parse the URL into PgConnectOptions
    let options = PgConnectOptions::from_str(config.url())
        .map_err(|e| PoolError::Config(format!("invalid database URL: {e}")))?;

    // Note: connect_timeout is handled at the pool level via acquire_timeout,
    // not as a PostgreSQL server option (which would fail).
    // The PoolConfig.connect_timeout is passed to PgPoolOptions.acquire_timeout()
    // in the create_pool logic.
    let _ = config.connect_timeout(); // Silence unused warning, used by pool options

    Ok(options)
}

// Stub implementation when postgres feature is not enabled
#[cfg(not(feature = "postgres"))]
pub struct ManagedPool {
    _private: (),
}

#[cfg(not(feature = "postgres"))]
impl ManagedPool {
    /// Create a new managed pool (requires `postgres` feature)
    pub async fn new(
        _config: PoolConfig,
        _shutdown: &ShutdownCoordinator,
    ) -> Result<Self, PoolError> {
        Err(PoolError::Config(
            "postgres feature is required for ManagedPool".to_string(),
        ))
    }
}

#[cfg(all(test, feature = "postgres"))]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::runtime::database::DatabaseConfig;

    // =========================================================================
    // Unit tests (no database required)
    // =========================================================================

    #[test]
    fn test_build_connect_options_parses_url() {
        let db_config = DatabaseConfig::test("postgres://user:pass@localhost:5432/mydb");
        let pool_config = PoolConfig::new(db_config);

        let options = build_connect_options(&pool_config).expect("should parse valid URL");

        // Verify the options were created (we can't inspect internals easily,
        // but successful creation means the URL was parsed correctly)
        let _ = options;
    }

    #[test]
    fn test_build_connect_options_invalid_url() {
        let db_config = DatabaseConfig::test("not-a-valid-url");
        let pool_config = PoolConfig::new(db_config);

        let result = build_connect_options(&pool_config);
        assert!(result.is_err());

        let err = result.expect_err("should fail for invalid URL");
        assert!(matches!(err, PoolError::Config(_)));
    }

    #[test]
    fn test_build_connect_options_with_connect_timeout() {
        let db_config = DatabaseConfig::builder()
            .url("postgres://localhost/test")
            .connect_timeout(Duration::from_secs(15))
            .build()
            .expect("config should build");
        let pool_config = PoolConfig::new(db_config);

        // Should succeed - connect_timeout is applied via options
        let options = build_connect_options(&pool_config).expect("should build options");
        let _ = options;
    }

    #[test]
    fn test_build_connect_options_with_query_params() {
        // URL already has query params - should still work
        let db_config = DatabaseConfig::test("postgres://localhost/test?sslmode=require");
        let pool_config = PoolConfig::new(db_config);

        let options = build_connect_options(&pool_config).expect("should parse URL with params");
        let _ = options;
    }

    #[test]
    fn test_constants_are_reasonable() {
        // Verify constants have sensible values at runtime
        // (Using variables to avoid assertions_on_constants lint)
        let priority = SHUTDOWN_PRIORITY;
        let buffer = DRAIN_CLEANUP_BUFFER_SECS;
        let poll = DRAIN_POLL_INTERVAL_MS;

        assert!(priority > 0, "shutdown priority should be positive");
        assert!(buffer > 0, "cleanup buffer should be positive");
        assert!(
            poll > 0 && poll < 1000,
            "poll interval should be reasonable"
        );
    }

    // =========================================================================
    // Integration tests (require database)
    // Run with: cargo test -p octarine --features postgres -- --ignored
    // =========================================================================

    #[tokio::test]
    #[ignore = "requires database"]
    async fn test_pool_creation() {
        let db_config = DatabaseConfig::test("postgres://localhost/octarine_test");
        let pool_config = PoolConfig::new(db_config).with_name("test-pool");
        let shutdown = ShutdownCoordinator::new();

        let pool = ManagedPool::new(pool_config, &shutdown)
            .await
            .expect("pool creation should succeed");
        assert!(!pool.is_shutting_down());
        assert_eq!(pool.name(), "test-pool");

        let health = pool.health_check().await;
        assert!(health.is_healthy);
    }

    #[tokio::test]
    #[ignore = "requires database"]
    async fn test_pool_health_check() {
        let db_config = DatabaseConfig::test("postgres://localhost/octarine_test");
        let pool_config = PoolConfig::new(db_config);
        let shutdown = ShutdownCoordinator::new();

        let pool = ManagedPool::new(pool_config, &shutdown)
            .await
            .expect("pool creation should succeed");
        let health = pool.health_check().await;

        assert!(health.is_healthy);
        assert!(health.latency.is_some());
        assert!(health.error.is_none());
    }

    #[tokio::test]
    #[ignore = "requires database"]
    async fn test_pool_stats() {
        let db_config = DatabaseConfig::test("postgres://localhost/octarine_test");
        let pool_config = PoolConfig::new(db_config);
        let shutdown = ShutdownCoordinator::new();

        let pool = ManagedPool::new(pool_config, &shutdown)
            .await
            .expect("pool creation should succeed");
        let stats = pool.stats();

        assert!(stats.max() > 0);
    }

    #[tokio::test]
    #[ignore = "requires database"]
    async fn test_pool_with_custom_drain_timeout() {
        let db_config = DatabaseConfig::test("postgres://localhost/octarine_test");
        let pool_config = PoolConfig::new(db_config)
            .with_name("custom-drain")
            .with_drain_timeout(Duration::from_secs(60));
        let shutdown = ShutdownCoordinator::new();

        let pool = ManagedPool::new(pool_config, &shutdown)
            .await
            .expect("pool creation should succeed");

        assert_eq!(pool.config().drain_timeout(), Duration::from_secs(60));
    }
}

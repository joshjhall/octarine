//! Database connection pool management with observability
//!
//! Provides a managed database pool wrapper that integrates with Octarine's
//! shutdown coordination, health checks, and observability system.
//!
//! # Features
//!
//! - **Lifecycle management**: Automatic graceful shutdown with query draining
//! - **Health checks**: Built-in health check for readiness/liveness probes
//! - **Metrics**: Pool utilization metrics via observe
//! - **Configuration**: Environment-based configuration with builder pattern
//! - **Multiple pools**: Named pools for multi-database scenarios
//!
//! # Example
//!
//! ```rust,ignore
//! use octarine::runtime::database::{DatabaseConfig, ManagedPool, PoolConfig};
//! use octarine::runtime::shutdown::ShutdownCoordinator;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let shutdown = ShutdownCoordinator::new();
//!
//!     // Load config from environment (DATABASE_URL, DB_MAX_CONNECTIONS, etc.)
//!     let db_config = DatabaseConfig::from_env()?;
//!     let pool_config = PoolConfig::new(db_config).with_name("primary");
//!
//!     // Create managed pool (auto-registers shutdown hook)
//!     let pool = ManagedPool::new(pool_config, &shutdown).await?;
//!
//!     // Use with sqlx queries - ManagedPool derefs to sqlx::Pool
//!     let rows: Vec<_> = sqlx::query("SELECT * FROM patterns")
//!         .fetch_all(&*pool)
//!         .await?;
//!
//!     // Health check for readiness probe
//!     let health = pool.health_check().await;
//!     if !health.is_healthy {
//!         eprintln!("Database unhealthy: {:?}", health.error);
//!     }
//!
//!     // Shutdown coordinator handles graceful drain
//!     shutdown.wait().await;
//!     Ok(())
//! }
//! ```
//!
//! # Configuration
//!
//! ## DatabaseConfig
//!
//! Core connection settings loaded from environment variables:
//!
//! | Variable | Default | Description |
//! |----------|---------|-------------|
//! | `DATABASE_URL` | (required) | PostgreSQL connection string |
//! | `DB_MAX_CONNECTIONS` | 10 | Maximum pool size |
//! | `DB_MIN_CONNECTIONS` | 1 | Minimum idle connections |
//! | `DB_ACQUIRE_TIMEOUT` | 30 | Acquire timeout in seconds |
//! | `DB_CONNECT_TIMEOUT` | 30 | Connection timeout in seconds |
//! | `DB_IDLE_TIMEOUT` | 600 | Idle connection timeout in seconds |
//! | `DB_MAX_LIFETIME` | 1800 | Maximum connection lifetime in seconds |
//!
//! ## PoolConfig
//!
//! Wraps `DatabaseConfig` with pool lifecycle settings:
//!
//! - `name`: Pool identifier for logs, metrics, and shutdown hooks
//! - `drain_timeout`: How long to wait for queries during shutdown
//!
//! # Shutdown Behavior
//!
//! When shutdown is triggered:
//! 1. Pool stops accepting new connection requests
//! 2. In-flight queries are allowed to complete (with timeout)
//! 3. All connections are gracefully closed
//! 4. Shutdown hook completes
//!
//! # Multiple Pools
//!
//! ```rust,ignore
//! use octarine::runtime::database::{DatabaseConfig, ManagedPool, PoolConfig};
//!
//! // Primary database
//! let primary_config = DatabaseConfig::from_env()?;
//! let primary = ManagedPool::new(
//!     PoolConfig::new(primary_config).with_name("primary"),
//!     &shutdown
//! ).await?;
//!
//! // Read replica
//! let replica_config = DatabaseConfig::from_env_with_prefix("REPLICA")?;
//! let replica = ManagedPool::new(
//!     PoolConfig::new(replica_config).with_name("replica"),
//!     &shutdown
//! ).await?;
//! ```

mod config;
mod error;
mod health;
mod pool;

pub use config::{DatabaseConfig, DatabaseConfigBuilder, PoolConfig};
pub use error::PoolError;
pub use health::{PoolHealth, PoolStats};
pub use pool::ManagedPool;

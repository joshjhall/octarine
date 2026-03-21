//! Configuration management with observability
//!
//! Provides type-safe configuration loading from environment variables and files
//! with validation, secret masking, and audit trails.
//!
//! # Features
//!
//! - **Environment loading**: Load config from environment variables with prefix support
//! - **File loading**: Load config from TOML files with secure permission validation
//! - **Struct deserialization**: Deserialize to typed structs with serde
//! - **Custom validation**: Validate cross-field constraints with `build_validated()`
//! - **Type conversion**: Automatic conversion to bool, integers, Duration, etc.
//! - **Validation**: Required fields, patterns, ranges
//! - **Secret masking**: Sensitive values masked in logs and Debug output
//! - **Audit trails**: All config loads logged via observe
//! - **Layering**: Environment > files > defaults (env vars override everything)
//!
//! # Examples
//!
//! ## Single-value API (environment variables)
//!
//! ```ignore
//! use octarine::runtime::config::ConfigBuilder;
//!
//! let port: u16 = ConfigBuilder::new()
//!     .with_prefix("APP")
//!     .get("PORT")?
//!     .default(8080)
//!     .parse()?;
//! ```
//!
//! ## Struct-based API (files + env vars)
//!
//! ```ignore
//! use octarine::runtime::config::ConfigBuilder;
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, Deserialize, Serialize, Default)]
//! struct AppConfig {
//!     port: u16,
//!     host: String,
//! }
//!
//! let config: AppConfig = ConfigBuilder::new()
//!     .with_defaults(AppConfig::default())
//!     .with_optional_file("app.toml")
//!     .with_prefix("APP")
//!     .build()?;  // or .build_struct() - they're equivalent
//! ```
//!
//! ## Struct-based API with validation
//!
//! Use `build_validated()` for cross-field validation that serde can't express:
//!
//! ```ignore
//! use octarine::runtime::config::{ConfigBuilder, ConfigError};
//!
//! #[derive(Debug, Deserialize, Serialize, Default)]
//! struct AppConfig {
//!     database_url: String,
//!     timeout_secs: u32,
//!     max_retries: u32,
//! }
//!
//! let config: AppConfig = ConfigBuilder::new()
//!     .with_defaults(AppConfig::default())
//!     .with_optional_file("app.toml")
//!     .with_prefix("APP")
//!     .build_validated(|c| {
//!         if c.database_url.is_empty() {
//!             return Err(ConfigError::validation("database_url", "required", "cannot be empty"));
//!         }
//!         if c.timeout_secs < c.max_retries {
//!             return Err(ConfigError::validation(
//!                 "timeout_secs", "consistency", "must be >= max_retries"
//!             ));
//!         }
//!         Ok(())
//!     })?;
//! ```
//!
//! # Security
//!
//! - Secret values are masked in Debug output
//! - Config load events are logged for audit
//! - Missing required values fail fast with clear errors
//! - `with_secure_file()` validates file permissions (0600 on Unix)

mod builder;
mod error;
mod figment_adapter;
mod value;

pub use builder::{ConfigBuilder, LoadedConfig};
pub use error::ConfigError;
pub use value::ConfigValue;

// Re-export secret types for convenient access
pub use crate::crypto::secrets::{
    Classification, RotationPolicy, SecretState, SecretType, TypedSecret,
};

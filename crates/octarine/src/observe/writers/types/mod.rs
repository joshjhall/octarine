//! Type-safe wrappers for writer configuration
//!
//! This module provides compile-time safety through newtype wrappers that
//! guarantee validation has occurred before values can be used.
//!
//! It also provides error types and configuration for writers.
//!
//! ## Module Organization
//!
//! - `error` - WriterError type for writer operation failures
//! - `health` - HealthStatus for writer health monitoring
//! - `filter` - SeverityFilter for event filtering
//! - `config` - WriterConfig, RotationConfig, LogFormat, DurabilityMode
//! - `paths` - LogDirectory, LogFilename, FilenamePattern

mod config;
mod error;
mod filter;
mod health;
mod paths;

// Re-export all public types
pub use config::{
    DurabilityMode, LogFormat, RotationConfig, RotationConfigBuilder, RotationSchedule,
    WriterConfig,
};
pub use error::WriterError;
pub use filter::SeverityFilter;
pub use health::WriterHealthStatus;
pub use paths::{FilenamePattern, LogDirectory, LogFilename};

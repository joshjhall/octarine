//! SecureFileOps - Unified file operations with audit trails and metrics
//!
//! Provides a high-level API for file operations that automatically:
//! - Logs all operations via observe
//! - Records metrics (timing, counts, sizes)
//! - Supports configurable audit levels
//! - Validates file types via magic bytes
//!
//! Split from the original 1036-LOC `ops.rs` into per-section submodules:
//!
//! - `config`: `AuditLevel`, `SecureFileOpsConfig`, three preset constructors
//! - `core`: `SecureFileOps` struct + all read/write/info/locked/permission methods
//! - `builder`: `SecureFileOpsBuilder` fluent configuration API
//! - `tests`: all `#[cfg(test)]` unit tests
//!
//! # Design Philosophy
//!
//! SecureFileOps follows async-first design:
//! - All primary operations are async to avoid blocking
//! - Sync variants available with `_sync` suffix for use in sync contexts
//! - All operations are logged for audit trails
//! - Metrics are collected for monitoring
//!
//! # Examples
//!
//! Pre-existing example - ignored at compile until adapted.
//! ```ignore
//! use octarine::io::SecureFileOps;
//!
//! // Create with default settings (audit enabled)
//! let ops = SecureFileOps::new();
//!
//! // Read file with audit trail (async)
//! let contents = ops.read_file("config.json").await?;
//!
//! // Write file atomically with audit trail (async)
//! ops.write_file("output.txt", b"data".to_vec()).await?;
//!
//! // Sync variants for use in sync contexts
//! let contents = ops.read_file_sync("config.json")?;
//! ```

mod builder;
mod config;
mod core;

pub use builder::SecureFileOpsBuilder;
pub use config::{AuditLevel, SecureFileOpsConfig};
pub use core::SecureFileOps;

#[cfg(test)]
mod tests;

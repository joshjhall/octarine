//! I/O Primitives
//!
//! Foundation utilities for I/O operations with ZERO internal dependencies.
//!
//! ## Architecture Layer
//!
//! This is **Layer 1 (primitives)** - pure utilities with no observe dependencies.
//!
//! - **Layer 1 (primitives)**: Pure utilities, no internal dependencies ← YOU ARE HERE
//! - **Layer 2 (observe)**: Uses primitives only (FileWriter uses these)
//! - **Layer 3 (io)**: Uses primitives + observe (public API at `octarine::io`)
//!
//! ## Naming Convention
//!
//! These types do NOT use the `Primitive*` prefix because:
//! - They are configuration types (`FileMode`, `WriteOptions`) re-exported directly
//! - Functions are wrapped with observe at Layer 3, not types
//! - No new wrapper types are created - just instrumentation added
//!
//! This follows the same pattern as `primitives/collections`.
//!
//! ## Module Structure
//!
//! - `file` - Secure file I/O operations (atomic writes, locking, permissions)
//! - `net` - Network configuration types and traits (health checks, database config)
//!
//! ## Import Pattern
//!
//! Access types via their domain module:
//! ```rust,ignore
//! use crate::primitives::io::file::{FileMode, path_exists, write_atomic};
//! use crate::primitives::io::net::{NetworkConfig, TlsConfig, RetryConfig};
//! ```
//!
//! For database configuration, use the public API:
//! ```rust,ignore
//! use crate::runtime::database::{DatabaseConfig, PoolConfig};
//! ```

// Layer 1 primitives - used by Layer 2/3
#![allow(dead_code)]

pub(crate) mod database;
pub(crate) mod file;
#[cfg(feature = "formats")]
pub(crate) mod formats;
pub(crate) mod net;

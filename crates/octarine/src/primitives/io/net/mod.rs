//! Network I/O primitives
//!
//! Configuration types and traits for network operations. This module provides
//! foundational types that can be used by the observe and public API modules.
//!
//! ## Architecture Note
//!
//! This is **Layer 1 (primitives)** - pure configuration types with no observe
//! dependencies. It provides types and traits only - implementations that
//! require external crates (sqlx, tokio, etc.) live in higher layers.
//!
//! ## Module Contents
//!
//! - `config` - Network connection configuration types
//! - `health` - Health check trait for network services

// Layer 1 primitives - private submodules with re-exports
mod config;
mod health;

// Re-export for Layer 2/3 consumers (not yet used but available)
#[allow(unused_imports)]
pub use config::{NetworkConfig, RetryConfig, TlsConfig};
#[allow(unused_imports)]
pub use health::{HealthCheck, NetworkHealthStatus};

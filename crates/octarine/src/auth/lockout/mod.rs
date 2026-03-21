//! Account lockout with observe integration
//!
//! This module wraps lockout primitives with observe instrumentation for
//! compliance-grade audit trails.
//!
//! # Features
//!
//! - Brute-force protection with exponential backoff
//! - Pluggable storage backends
//! - Audit events for all lockout operations
//!
//! # Audit Events
//!
//! All operations emit observe events:
//! - `auth.lockout.failure_recorded` - Authentication failure recorded
//! - `auth.lockout.triggered` - Account locked due to failures
//! - `auth.lockout.expired` - Lockout period expired
//! - `auth.lockout.cleared` - Lockout manually cleared

mod manager;
mod store;

pub use manager::LockoutManager;
pub use store::{LockoutStore, MemoryLockoutStore};

// Re-export types from primitives
pub use crate::primitives::auth::lockout::{
    FailureRecord, LockoutConfig, LockoutConfigBuilder, LockoutDecision, LockoutIdentifier,
    LockoutStatus,
};

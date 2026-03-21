//! Session management with observe integration
//!
//! This module wraps session primitives with observe instrumentation for
//! compliance-grade audit trails.
//!
//! # Features
//!
//! - Session creation with automatic audit events
//! - Session validation with binding checks
//! - Session termination with cleanup
//! - Pluggable storage backends
//!
//! # Audit Events
//!
//! All operations emit observe events:
//! - `auth.session.created` - New session created
//! - `auth.session.validated` - Session passed validation
//! - `auth.session.expired` - Session expired (absolute or idle)
//! - `auth.session.binding_mismatch` - Session binding validation failed
//! - `auth.session.terminated` - Session explicitly terminated

mod manager;
mod store;

pub use manager::SessionManager;
pub use store::{MemorySessionStore, SessionStore};

// Re-export types from primitives
pub use crate::primitives::auth::session::config::SameSite;
pub use crate::primitives::auth::session::{
    Session, SessionBinding, SessionConfig, SessionConfigBuilder, SessionId,
};

//! Session-stable token vault — the persistence foundation for reversible
//! pseudonymization.
//!
//! This module defines the backend-agnostic surface every vault backend and
//! the InstanceCounter operators build on:
//!
//! - [`SessionId`] — the opaque per-session handle that scopes a run of
//!   pseudonymization.
//! - [`EntityKey`] — the composite `entity_type` + `original` key a single
//!   value is stored under.
//! - [`StateStore`] — the `async` trait that records each
//!   `(session, key) → token` mapping, implemented by pluggable backends.
//!
//! Presidio has no equivalent abstraction: its `InstanceCounterAnonymizer`
//! lives in a sample notebook with a hand-rolled dict that explicitly disclaims
//! thread safety. Octarine ships the trait first-class so backends own their
//! own atomicity.
//!
//! The default [`InMemoryStore`] backend and the [`SessionManager`] lifecycle
//! API (open/close/touch + TTL expiry) ship here; Redis and Postgres backends
//! and the InstanceCounter operators that consume this surface land as
//! follow-up work; see `docs/anonymize/token-vault.md`.

mod backends;
mod session;
mod store;
mod types;

#[cfg(test)]
mod tests;

pub use backends::InMemoryStore;
pub use session::{DEFAULT_SWEEP_INTERVAL, SessionManager, SessionOptions};
pub use store::StateStore;
pub use types::{EntityKey, SessionId};

//! Concrete [`StateStore`](super::StateStore) backends.
//!
//! Each backend trades off dependencies against durability and reach:
//!
//! - [`InMemoryStore`] — zero-dependency, single-process. The default; used by
//!   tests and demos, and the reference impl every other backend's
//!   trait-conformance suite is checked against.
//!
//! Redis (multi-process) and Postgres (durable, auditable) backends land as
//! follow-up work; see `docs/anonymize/token-vault.md`.

mod memory;

pub use memory::InMemoryStore;

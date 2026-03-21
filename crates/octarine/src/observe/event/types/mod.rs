//! Event type definitions
//!
//! These are the various event types used in the system.
//! They are data structures only - the implementation for creating
//! and dispatching events is in the parent module's dispatch.rs

pub mod business;
pub mod errors;
pub mod security;
pub mod system;

// Note: Event types (BusinessEvent, SecurityEvent, etc.) are internal
// to their respective submodules and not re-exported here.

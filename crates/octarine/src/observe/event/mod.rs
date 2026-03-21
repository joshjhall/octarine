//! Event type definitions
//!
//! This module organizes different types of observability events by category.
//! All events flow through the same system for consistent handling.

// Core implementation (internal only)
mod dispatch;

// Event type definitions
mod types;

// Builder pattern for configurable event operations
mod builder;

// Builder exports - these are the main way to work with events
// Internal to observe module only
pub(super) use builder::EventBuilder;

// Shortcuts module (internal to observe)
pub(super) mod shortcuts;

// Re-export shortcut functions directly on event module for crate-wide use
// These are public API for external consumers
#[allow(unused_imports)]
pub use shortcuts::{
    // Security events
    auth_failure,
    auth_success,
    // Logging functions
    critical,
    debug,
    error,
    info,
    trace,
    warn,
};

// EventType is available through observe::types

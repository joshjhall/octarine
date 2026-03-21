//! Context extensions for ObserveBuilder
//!
//! NOTE: Context is automatically captured and does not need explicit builder methods.
//!
//! Context (who/what/where/when) is populated automatically through:
//! - Thread-local storage (tenant, user, session)
//! - Environment detection (development, production, CI)
//! - Macro capture (file, line, module_path)
//!
//! Users should not need to manually configure context - it's handled
//! automatically when events are dispatched through:
//! - `observe::context::set_tenant()` - Set thread-local tenant context
//! - `observe::context::with_tenant()` - Execute with tenant context
//! - Middleware integration - Auto-capture from request context
//!
//! The ObserveBuilder does provide manual context overrides through:
//! - `.operation(name)` - Set operation name
//! - `.user(id)` - Override user ID
//! - `.tenant(id)` - Override tenant ID
//! - `.session(id)` - Override session ID
//!
//! But these are optional - context is auto-captured if not specified.
//!
//! The `build_context()` method (in mod.rs) handles automatic population
//! by merging manual overrides with auto-captured values.

use super::ObserveBuilder;

/// Extensions for ObserveBuilder related to context building
impl ObserveBuilder {
    // Context building is handled in mod.rs via build_context()
    // This file exists for pattern consistency and documentation

    /// Build context only (without triggering event/problem)
    ///
    /// Useful for testing or when you need to inspect the context
    /// that would be auto-generated.
    pub(crate) fn build_only_context(self) -> super::super::EventContext {
        self.build_context()
    }
}

// No additional public API - context is automatically populated

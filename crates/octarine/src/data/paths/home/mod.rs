//! Home directory operations
//!
//! Provides expansion and collapse of home directory references (~).
//! These are application-level operations that depend on the runtime environment.

mod core;

// Internal API - only accessible within data/paths
pub(super) use core::{collapse_home, expand_home, is_home_reference_present};

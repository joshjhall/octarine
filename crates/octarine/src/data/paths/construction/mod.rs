//! Path construction and building
//!
//! Provides safe path construction from components with validation.
//! This is the OWASP-recommended approach: validate components, then construct safely.

mod core;

// Internal API - only accessible within data/paths
pub(super) use core::{
    build_absolute_path, build_config_path, build_file_path, build_path, build_temp_path,
    join_path_components,
};

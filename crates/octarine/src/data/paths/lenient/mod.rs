//! Lenient sanitization functions
//!
//! These functions always return a valid value, never failing.
//! They're useful when you need a safe default rather than an error.

mod core;

// Internal API - only accessible within data/paths
pub(super) use core::{clean_filename, clean_path, clean_separators, clean_user_path};

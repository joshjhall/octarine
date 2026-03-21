//! Format-aware file I/O operations
//!
//! Provides file operations with automatic format detection and handling.
//!
//! ## Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with no observe dependencies.
//! Uses `io::file` for underlying file operations.
//!
//! ## Features
//!
//! - Read files with automatic format detection
//! - Write files with format-specific handling
//! - Extension-based format inference

mod builder;
mod reading;
mod types;
mod writing;

// Types are public since they're part of the API
pub use types::{FormatReadOptions, FormatWriteOptions, ReadResult};

// Builder is crate-internal (wrapped at Layer 3)
pub(crate) use builder::FormatIoBuilder;

// Functions available through builder (may be used for low-level access)
#[allow(unused_imports)]
pub(crate) use reading::{read_format_file, read_format_string};
#[allow(unused_imports)]
pub(crate) use writing::{write_format_file, write_format_string};

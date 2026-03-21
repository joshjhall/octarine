//! Format-aware file I/O operations with observability (Layer 3)
//!
//! Provides file read/write operations with automatic format detection
//! and observe instrumentation for audit trails.
//!
//! # Features
//!
//! - Read files with automatic format detection
//! - Write files with format-specific handling
//! - Extension and content-based format detection
//! - Atomic writes for safety
//!
//! # Examples
//!
//! ```ignore
//! use octarine::io::formats::{read_format_file, write_format_file, FormatType};
//! use std::path::Path;
//!
//! // Read with auto-detect
//! let result = read_format_file(Path::new("config.json"))?;
//! println!("Format: {:?}", result.format);
//!
//! // Write with format validation
//! write_format_file(Path::new("data.yaml"), "key: value", FormatType::Yaml)?;
//! ```

mod builder;
mod shortcuts;
mod types;

// Re-export builder
pub use builder::FormatIoBuilder;

// Re-export types
pub use types::{FormatReadOptions, FormatWriteOptions, ReadResult};

// Re-export FormatType from primitives
pub use crate::primitives::data::formats::FormatType;

// Re-export shortcuts
pub use shortcuts::*;

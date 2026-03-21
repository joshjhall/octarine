//! Builder pattern for path operations
//!
//! Provides the main entry point for all path detection, validation,
//! sanitization, and construction operations.
//!
//! ## Design Philosophy
//!
//! - **Single entry point**: All path operations through one builder
//! - **Domain delegation**: Routes to domain-specific modules
//! - **Pure functions**: No logging, no side effects (Layer 1)
//! - **Platform-aware**: Supports both Unix and Windows conventions
//!
//! ## Module Organization
//!
//! - [`core`] - PathBuilder struct and constructors
//! - [`type_detection`] - Path type and platform detection
//! - [`characteristics`] - Path characteristic detection
//! - [`filetype_detection`] - File type detection
//! - [`security`] - Security detection and validation
//! - [`format_conversion`] - Format conversion methods
//! - [`format_detection`] - Format detection methods
//! - [`construction`] - Path construction methods
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::primitives::paths::PathBuilder;
//!
//! let builder = PathBuilder::new();
//!
//! // Detection
//! let path_type = builder.detect_path_type("/etc/passwd");
//! let threats = builder.detect_threats("../../../etc/passwd");
//!
//! // Validation (returns bool)
//! let is_safe = builder.is_safe("/home/user/file.txt");
//!
//! // Characteristics
//! let is_abs = builder.is_absolute("/etc/passwd");
//! let is_rel = builder.is_relative("path/to/file");
//!
//! // Construction
//! let full = builder.join("base", "file.txt");
//! let parent = builder.find_parent("/app/data/file.txt");
//! ```

mod characteristics;
mod construction;
mod core;
mod filetype_detection;
mod format_conversion;
mod format_detection;
mod security;
mod type_detection;

pub use self::core::PathBuilder;

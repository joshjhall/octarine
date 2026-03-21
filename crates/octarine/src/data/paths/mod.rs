//! Path operations with built-in security and observability
//!
//! This module provides comprehensive path handling with automatic threat detection,
//! validation, and sanitization. All operations are instrumented with observe for
//! compliance-grade audit trails.
//!
//! # Features
//!
//! - **Detection**: Identify path types, threats, file categories
//! - **Validation**: Enforce security policies on paths
//! - **Sanitization**: Clean and normalize paths safely
//! - **Boundary Enforcement**: Directory jailing and containment
//! - **Cross-Platform**: Unix, Windows, WSL support
//! - **Home Directory**: Expand/collapse ~ paths
//! - **Context-Specific**: Specialized handling for env, ssh, credentials
//!
//! # Builder Organization
//!
//! This module provides multiple specialized builders for different use cases:
//!
//! - [`PathBuilder`] - Unified API for all path operations
//! - [`SecurityBuilder`] - Security detection, validation, and sanitization
//! - [`BoundaryBuilder`] - Directory jailing and containment
//! - [`FilenameBuilder`] - Filename operations (validation, sanitization, construction)
//! - [`CharacteristicBuilder`] - Path type and platform detection
//! - [`FiletypeBuilder`] - File category detection
//! - [`FormatBuilder`] - Format detection and conversion
//! - [`HomeBuilder`] - Home directory expansion and collapse
//! - [`PathContextBuilder`] - Context-specific sanitization (env, ssh, credential, op)
//! - [`ConstructionBuilder`] - Safe path building
//! - [`LenientBuilder`] - Lenient sanitization (always returns a value)
//!
//! # Usage
//!
//! ## Shortcuts (Recommended for Common Operations)
//!
//! ```
//! use octarine::data::paths::{validate_path, validate_filename, is_valid_path, is_path_traversal_present};
//! use octarine::data::paths::{sanitize_path, sanitize_filename};
//!
//! // Validation (returns Result)
//! validate_path("safe/path").unwrap();
//! validate_filename("document.pdf").unwrap();
//!
//! // Detection (returns bool)
//! let is_valid = is_valid_path("safe/path");
//! let has_threat = is_path_traversal_present("../etc/passwd");
//!
//! // Sanitization (returns Result<String>)
//! let clean = sanitize_path("../etc/passwd").unwrap();
//! let safe_name = sanitize_filename("file<>.txt").unwrap();
//! ```
//!
//! ## PathBuilder (Unified API)
//!
//! ```
//! use octarine::data::paths::PathBuilder;
//!
//! let builder = PathBuilder::new();
//!
//! // Detection
//! let threats = builder.detect_threats("../$(cmd)");
//! let file_type = builder.detect_file_category("config.json");
//!
//! // Validation with boundary
//! let jailed = builder.boundary("/app/data");
//! jailed.validate_path("user/file.txt").unwrap();
//!
//! // Sanitization
//! let clean = PathBuilder::new().sanitize("file.txt").unwrap();
//! ```
//!
//! ## Specialized Builders
//!
//! ```
//! use octarine::data::paths::{SecurityBuilder, FilenameBuilder, HomeBuilder};
//!
//! // Security operations
//! let security = SecurityBuilder::new();
//! if security.is_traversal_present("../secret") {
//!     // Handle threat
//! }
//!
//! // Filename operations
//! let fb = FilenameBuilder::new();
//! let safe = fb.set_extension("document.txt", "pdf");
//! let numbered = fb.with_number("file.txt", 1); // file_1.txt
//!
//! // Home directory operations
//! let home = HomeBuilder::new();
//! let expanded = home.expand("~/Documents");
//! ```
//!
//! # Security Standards
//!
//! All operations follow OWASP guidelines and address:
//! - **CWE-22**: Path Traversal
//! - **CWE-78**: OS Command Injection
//! - **CWE-158**: Null Byte Injection
//! - **CWE-175**: Improper Handling of Mixed Encoding
//! - **CWE-707**: Improper Neutralization
//!
//! # Observe Integration
//!
//! All operations emit:
//! - **Events**: DEBUG for success, WARN for validation failures, CRITICAL for attacks
//! - **Metrics**: Operation counts, timing, threat detection rates

// Private submodules - re-export at paths level
mod builder;
mod shortcuts;
mod types;

// Internal implementation modules - private, accessed via relative imports in builder/
mod construction;
mod context;
mod home;
mod lenient;

// Re-export the main PathBuilder
pub use builder::PathBuilder;

// Re-export all specialized builders (except SecurityBuilder, which is in security::paths)
pub use builder::{
    BoundaryBuilder, CharacteristicBuilder, ConstructionBuilder, FilenameBuilder, FiletypeBuilder,
    FormatBuilder, HomeBuilder, LenientBuilder, PathContextBuilder,
};

// Re-export SecurityBuilder from security::paths for backwards compatibility
pub use crate::security::paths::SecurityBuilder;

// Re-export types for public API
pub use types::{
    BoundaryStrategy, FileCategory, FilenameSanitizationStrategy, PathDetectionResult, PathFormat,
    PathType, PathValidationResult, Platform, SanitizationContext, SeparatorStyle,
};

// Re-export security types from their canonical location (security::paths)
pub use crate::security::paths::{PathSanitizationStrategy, SecurityThreat};

// Re-export shortcuts at module level for convenience
pub use shortcuts::*;

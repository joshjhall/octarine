//! File type validation using magic bytes with observability
//!
//! Provides content-based file type detection with automatic audit trails.
//! Unlike extension-based detection, magic bytes cannot be easily spoofed,
//! making this essential for security-critical file handling.
//!
//! # Features
//!
//! - **Content-Based Detection**: Examines actual file bytes, not extensions
//! - **Audit Trails**: All detections logged via observe
//! - **Validation**: Reject files that don't match expected types
//! - **Security Checks**: Detect potentially dangerous file types
//!
//! # Module Structure
//!
//! - [`detection`] - Magic byte detection (in-memory and file-based)
//! - [`validation`] - File type validation with observe logging
//!
//! # Examples
//!
//! ## Detect File Type
//!
//! ```ignore
//! use octarine::io::magic::{detect_file_type, MagicFileType};
//!
//! let result = detect_file_type("image.png")?;
//! if result.file_type == Some(MagicFileType::Png) {
//!     println!("Confirmed PNG image");
//! }
//! ```
//!
//! ## Validate Upload
//!
//! ```ignore
//! use octarine::io::magic::{validate_image, validate_not_dangerous};
//!
//! // Ensure file is actually an image
//! validate_image("upload.jpg")?;
//!
//! // Reject executables, scripts, and archives
//! validate_not_dangerous("user_upload.bin")?;
//! ```
//!
//! ## Check Data Directly
//!
//! ```ignore
//! use octarine::io::magic::{detect_magic, is_dangerous_magic};
//!
//! let data = std::fs::read("file.bin")?;
//! if is_dangerous_magic(&data) {
//!     return Err("Dangerous file type detected");
//! }
//! ```

// Public API for magic byte validation
//!
//! Follows async-first design: async functions by default, `_sync` suffix for blocking.
#![allow(dead_code)]

// Private submodules - access via re-exports at this level
mod detection;
mod validation;

// Re-export types from detection
#[allow(unused_imports)]
pub use detection::{
    MAX_MAGIC_BYTES,
    // Types
    MagicFileType,
    MagicResult,
    // File-based detection (async - default)
    detect_file_type,
    // File-based detection (sync - explicit opt-in)
    detect_file_type_sync,
    // In-memory detection (sync, no I/O)
    detect_magic,
    is_archive_file,
    is_archive_file_sync,
    is_archive_magic,
    is_dangerous_file,
    is_dangerous_file_sync,
    is_dangerous_magic,
    is_executable_file,
    is_executable_file_sync,
    is_executable_magic,
    is_image_file,
    is_image_file_sync,
    is_image_magic,
};

// Re-export validation functions (async - default)
pub use validation::{
    validate_extension_matches, validate_file_type, validate_image, validate_not_dangerous,
};

// Re-export validation functions (sync - explicit opt-in)
#[allow(unused_imports)]
pub use validation::{
    validate_extension_matches_sync, validate_file_type_sync, validate_image_sync,
    validate_not_dangerous_sync,
};

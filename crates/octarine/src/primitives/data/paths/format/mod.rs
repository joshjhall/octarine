//! Path format detection and conversion domain module
//!
//! Pure detection and conversion functions for path format operations.
//! Handles cross-platform path format transformations (Unix ↔ Windows ↔ WSL).
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Features
//!
//! - **Format detection**: Detect path format (Unix, Windows, WSL, PowerShell, Portable)
//! - **Separator detection**: Detect separator style (forward, back, mixed, none)
//! - **Format issue detection**: Mixed separators, redundant separators, trailing separators
//! - **Separator conversion**: Convert between forward and back slashes
//! - **Cross-platform conversion**: Convert between Unix, Windows, and WSL formats
//! - **Drive letter handling**: Extract and convert Windows drive letters
//! - **Portable conversion**: Remove platform-specific elements
//!
//! # Usage
//!
//! ## Using FormatBuilder (recommended)
//!
//! ```ignore
//! use octarine::primitives::paths::format::FormatBuilder;
//! use octarine::primitives::paths::format::detection::PathFormat;
//!
//! let format = FormatBuilder::new();
//!
//! // Detection
//! assert_eq!(format.detect("C:\\Windows"), PathFormat::Windows);
//! assert_eq!(format.detect("/mnt/c/Users"), PathFormat::Wsl);
//! assert_eq!(format.detect("/etc/passwd"), PathFormat::Unix);
//!
//! // Format checks
//! assert!(format.has_mixed_separators("path/to\\file"));
//! assert!(format.has_format_issues("path//to\\file/"));
//!
//! // Conversion
//! assert_eq!(format.convert_to_unix("path\\to\\file"), "path/to/file");
//! assert_eq!(format.convert_to_wsl("C:\\Users\\file"), Some("/mnt/c/Users/file".to_string()));
//! assert_eq!(format.wsl_to_windows("/mnt/c/data"), Some("C:\\data".to_string()));
//! ```
//!
//! ## Using functions directly
//!
//! ```ignore
//! use octarine::primitives::paths::format::{
//!     detection::{detect_format, PathFormat, has_mixed_separators},
//!     conversion::{to_unix, windows_drive_to_wsl},
//! };
//!
//! // Detection
//! assert_eq!(detect_format("C:\\Windows"), PathFormat::Windows);
//! assert!(has_mixed_separators("path/to\\file"));
//!
//! // Conversion
//! assert_eq!(to_unix("path\\to\\file"), "path/to/file");
//! assert_eq!(windows_drive_to_wsl("C:\\Users"), Some("/mnt/c/Users".to_string()));
//! ```
//!
//! # Supported Path Formats
//!
//! | Format | Example | Separator | Notes |
//! |--------|---------|-----------|-------|
//! | Unix | `/etc/passwd` | `/` | Absolute Unix paths |
//! | Windows | `C:\Windows` | `\` | Drive letter with backslashes |
//! | PowerShell | `C:/Windows` | `/` | Drive letter with forward slashes |
//! | WSL | `/mnt/c/Users` | `/` | Windows Subsystem for Linux mount |
//! | Portable | `relative/path` | `/` | No platform-specific elements |
//!
//! # Design Principles
//!
//! 1. **Pure Functions**: No logging, no side effects
//! 2. **Zero-Copy Where Possible**: Uses `Cow<str>` for efficiency
//! 3. **Format-Only**: Does NOT validate or sanitize security concerns
//! 4. **Preserves Security Patterns**: Traversal and injection patterns preserved
//!
//! ## Important: Separation of Concerns
//!
//! **Format conversion is NOT sanitization!**
//!
//! Format conversion only changes separators and format-specific elements.
//! It does NOT remove dangerous patterns - those are preserved for validation:
//!
//! ```ignore
//! // Format conversion preserves attack vectors
//! to_unix("path\\..\\..\\etc")
//!     // Returns: "path/../../etc"
//!     // Traversal PRESERVED for validation layer
//!
//! to_unix("path\\$(whoami)\\file")
//!     // Returns: "path/$(whoami)/file"
//!     // Command injection PRESERVED for validation layer
//! ```

pub(crate) mod builder;
pub(crate) mod conversion;
pub(crate) mod detection;

// Re-export builder for convenient access
pub use builder::FormatBuilder;

// Re-export detection types and key functions
pub use detection::{
    // Constants
    MAX_PATH_LENGTH,
    // Types
    PathFormat,
    SeparatorStyle,
    // Detection functions
    detect_format,
    detect_separator_style,
    // Check functions
    exceeds_length_limit,
    find_drive_letter,
    find_wsl_drive_letter,
    is_consistent_format,
    is_drive_letter_present,
    is_format_issues_present,
    is_leading_dot_slash_present,
    is_mixed_separators_present,
    is_posix_separators_present,
    is_redundant_separators_present,
    is_trailing_separator_present,
    is_unc_path,
    is_windows_separators_present,
    is_wsl_path,
};

// Re-export conversion functions
pub use conversion::{
    convert_to_format,
    ensure_trailing_separator,
    normalize_separators,
    // Separator cleanup
    strip_leading_dot_slash,
    strip_redundant_separators,
    strip_trailing_separator,
    to_native,
    to_portable,
    // Separator conversion
    to_unix,
    to_windows,
    unix_to_windows_path,
    windows_drive_to_unix,
    // Cross-platform conversion
    windows_drive_to_wsl,
    wsl_to_windows_drive,
};

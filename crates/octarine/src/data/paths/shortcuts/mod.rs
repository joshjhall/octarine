//! Path operation shortcuts
//!
//! Convenience functions for common path operations. These are the recommended
//! entry points for most use cases.
//!
//! # Naming Conventions (Issue #182)
//!
//! - `validate_*` - Returns `Result<(), Problem>`, strict by default (rejects threats)
//! - `is_*` - Returns `bool`, detection/check functions
//! - `sanitize_*` - Returns `Result<String, Problem>`, modifies input to make safe
//! - `clean_*` - Returns `String`, lenient sanitization (always returns a value)
//!
//! # Module Organization
//!
//! - [`validation`] - Path and filename validation
//! - [`sanitization`] - Path sanitization functions
//! - [`detection`] - Security threat detection
//! - [`path_types`] - Path type checking (absolute, relative, etc.)
//! - [`file_types`] - File type checking by extension
//! - [`manipulation`] - Path manipulation and construction
//! - [`home`] - Home directory operations
//! - [`context`] - Context-specific sanitization
//! - [`targeted_validation`] - Specific security validations
//! - [`building`] - Path building functions
//! - [`lenient`] - Lenient sanitization (always returns value)
//! - [`combined`] - Common workflow combinations
//! - [`filename_construction`] - Filename creation utilities
//! - [`characteristics`] - Path characteristic checks
//! - [`format`] - Path format operations
//! - [`validation_helpers`] - Boundary and extension validation
//!
//! # Examples
//!
//! ```
//! use octarine::data::paths::{validate_path, validate_filename, is_valid_path, sanitize_path, sanitize_filename};
//!
//! // Validation (strict - rejects threats)
//! validate_path("safe/path").unwrap();
//! validate_filename("document.pdf").unwrap();
//!
//! // Detection (returns bool)
//! let is_valid = is_valid_path("safe/path");
//!
//! // Sanitization (modifies to make safe)
//! let clean = sanitize_path("../etc/passwd").unwrap();
//! let safe_name = sanitize_filename("file<>.txt").unwrap();
//! ```

mod building;
mod characteristics;
mod combined;
mod context;
mod detection;
mod file_types;
mod filename_construction;
mod format;
mod home;
mod lenient;
mod manipulation;
mod path_types;
mod sanitization;
mod targeted_validation;
mod validation;
mod validation_helpers;

// Re-export validation shortcuts
pub use validation::{
    is_valid_path, validate_filename, validate_path, validate_path_in_boundary,
    validate_upload_filename,
};

// Re-export sanitization shortcuts
pub use sanitization::{
    sanitize_filename, sanitize_path, sanitize_path_in_boundary, to_safe_filename,
};

// Re-export detection shortcuts
pub use detection::{
    detect_file_category, detect_path, detect_path_type, detect_platform,
    is_command_injection_present, is_null_bytes_present, is_path_threat_present,
    is_path_traversal_present, is_safe_path, is_shell_metacharacters_present,
    is_variable_expansion_present,
};

// Re-export path type shortcuts
pub use path_types::{
    is_absolute_path, is_portable_path, is_relative_path, is_unix_path, is_windows_path,
};

// Re-export file type shortcuts
pub use file_types::{
    is_archive_file, is_audio_file, is_backup_file, is_code_file, is_config_file, is_database_file,
    is_document_file, is_executable_file, is_font_file, is_image_file, is_log_file, is_media_file,
    is_script_file, is_security_sensitive_file, is_temp_file, is_video_file,
};

// Re-export manipulation shortcuts
pub use manipulation::{
    ancestors, clean_path_components, extension, filename, join_path, normalize_path, parent_path,
    stem, to_absolute_path, to_relative_path, to_unix_path, to_windows_path, to_wsl_path,
    wsl_to_windows_path,
};

// Re-export home directory shortcuts
pub use home::{collapse_home, expand_home, is_home_reference_present};

// Re-export context shortcuts
pub use context::{
    is_credential_path, is_env_path, is_op_reference, is_ssh_path, sanitize_path_backup,
    sanitize_path_certificate, sanitize_path_config, sanitize_path_credential, sanitize_path_db,
    sanitize_path_env, sanitize_path_keystore, sanitize_path_op, sanitize_path_secret,
    sanitize_path_ssh, sanitize_path_user,
};

// Re-export targeted validation shortcuts
pub use targeted_validation::{
    normalize_path_secure, validate_path_no_injection, validate_path_no_traversal,
};

// Re-export building shortcuts
pub use building::{
    build_absolute_path, build_config_path, build_file_path, build_path, build_temp_path,
    join_components,
};

// Re-export lenient shortcuts
pub use lenient::{clean_filename, clean_path, clean_separators, clean_user_path};

// Re-export combined shortcuts
pub use combined::{
    expand_and_sanitize, is_safe_for_context, safe_file_path, safe_path_in_boundary,
    sanitize_for_context, validate_upload,
};

// Re-export filename construction shortcuts
pub use filename_construction::{
    add_extension, numbered_filename, set_extension, shell_escape_filename, strip_extension,
    timestamped_filename, uuid_filename,
};

// Re-export characteristic shortcuts
pub use characteristics::{calculate_depth, is_hidden, is_hidden_component_present};

// Re-export format shortcuts
pub use format::{is_format_issues_present, is_mixed_separators_present, to_portable_path};

// Re-export validation helper shortcuts
pub use validation_helpers::{
    calculate_escape_depth, validate_extension, validate_in_boundary, would_escape_boundary,
};

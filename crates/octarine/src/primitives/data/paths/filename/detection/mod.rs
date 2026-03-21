//! Filename pattern detection functions
//!
//! Pure detection functions that identify specific patterns in filenames.
//! These functions are building blocks for validation and sanitization.
//!
//! ## Detection Philosophy
//!
//! Detection functions:
//! - Return `bool` indicating pattern presence
//! - Do NOT validate or sanitize
//! - Are lenient (sensitive to patterns, may have false positives)
//! - Have no side effects
//!
//! ## Security Patterns Detected
//!
//! | Pattern | Risk | Example |
//! |---------|------|---------|
//! | Path separators | Directory traversal | `foo/bar`, `foo\bar` |
//! | Null bytes | C string truncation | `file\0.txt` |
//! | Control characters | Log injection, parsing | `file\n.txt` |
//! | Reserved names | Windows DoS | `CON`, `NUL`, `COM1` |
//! | Dangerous characters | Shell injection | `file;rm.txt` |
//! | Command substitution | Code execution | `$(cmd).txt` |
//! | Double extensions | MIME confusion | `file.txt.exe` |
//! | Dot files | Hidden file access | `.secret` |
//!
//! ## Module Organization
//!
//! - [`constants`] - Security-related constants and character sets
//! - [`separators`] - Path separator detection
//! - [`characters`] - Dangerous character detection
//! - [`injection`] - Command injection detection
//! - [`reserved`] - Reserved name detection
//! - [`dotfiles`] - Dot file detection
//! - [`extensions`] - Extension detection
//! - [`length`] - Length-related detection
//! - [`pattern`] - Glob pattern matching
//! - [`unicode`] - Unicode security detection
//! - [`threat`] - Comprehensive threat detection

mod characters;
mod constants;
mod dotfiles;
mod extensions;
mod injection;
mod length;
mod pattern;
mod reserved;
mod separators;
mod threat;
mod unicode;

// ============================================================================
// Re-exports - Constants
// ============================================================================

pub use constants::{
    DANGEROUS_EXTENSIONS, DANGEROUS_SHELL_CHARS, RESERVED_WINDOWS_CHARS, RESERVED_WINDOWS_NAMES,
};

// ============================================================================
// Re-exports - Path Separator Detection
// ============================================================================

pub use separators::{
    is_path_separators_present, is_unix_separator_present, is_windows_separator_present,
};

// ============================================================================
// Re-exports - Dangerous Character Detection
// ============================================================================

pub use characters::{
    is_control_characters_present, is_dangerous_shell_chars_present, is_null_bytes_present,
    is_reserved_windows_chars_present,
};

// ============================================================================
// Re-exports - Command Injection Detection
// ============================================================================

pub use injection::{
    is_command_substitution_present, is_injection_pattern_present, is_variable_expansion_present,
};

// ============================================================================
// Re-exports - Reserved Name Detection
// ============================================================================

pub use reserved::{is_current_dir, is_directory_ref, is_parent_dir, is_reserved_name};

// ============================================================================
// Re-exports - Dot File Detection
// ============================================================================

pub use dotfiles::{is_dot_file, starts_with_dot};

// ============================================================================
// Re-exports - Extension Detection
// ============================================================================

pub use extensions::{
    find_extension, is_dangerous_extension_present, is_double_extension_present,
    is_extension_found, is_extension_in_list, is_extension_present, stem,
};

// ============================================================================
// Re-exports - Length Detection
// ============================================================================

pub use length::{exceeds_length, is_empty, is_whitespace_only};

// ============================================================================
// Re-exports - Pattern Matching
// ============================================================================

pub use pattern::is_pattern_found;

// ============================================================================
// Re-exports - Unicode Detection
// ============================================================================

pub use unicode::{is_bidi_control_present, is_homoglyphs_present, is_non_ascii_present};

// ============================================================================
// Re-exports - Comprehensive Threat Detection
// ============================================================================

pub use threat::{detect_all_issues, is_threat_present, normalize_case};

//! Common utilities for path detection, validation, and construction
//!
//! This module provides shared primitives used across all path domain modules:
//!
//! - `patterns` - Detection patterns for security threats and path properties
//! - `normalization` - Path format normalization (separators, redundancy)
//! - `construction` - Path building utilities (join, resolve, components)
//!
//! # Design Principles
//!
//! 1. **No Logging**: Pure functions, no trace/debug calls
//! 2. **No Dependencies**: Only `std` library, no observe module
//! 3. **Reusable**: Used by all path domain modules
//! 4. **Zero-Copy Where Possible**: Uses `Cow<str>` for efficiency
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - the foundation layer with:
//! - No observe dependencies
//! - No side effects
//! - Pure functions only
//!
//! # Security Standards
//!
//! All security patterns follow OWASP guidelines:
//! - **CWE-22**: Path Traversal
//! - **CWE-78**: OS Command Injection
//! - **CWE-158**: Null Byte Injection
//! - **CWE-175**: Improper Handling of Mixed Encoding
//! - **CWE-707**: Improper Neutralization

pub mod construction;
pub mod normalization;
pub mod patterns;

// Re-export commonly used items from patterns
pub use patterns::{
    // Traversal
    count_parent_references,
    // Platform
    is_absolute,
    is_absolute_path_present,
    // Injection
    is_any_injection_present,
    is_any_injection_present_strict,
    is_any_traversal_present,
    is_backslashes_present,
    is_command_substitution_present,
    // Characters
    is_control_characters_present,
    is_dangerous_characters_present,
    is_drive_letter_present,
    is_empty,
    is_empty_or_whitespace,
    is_encoded_traversal_present,
    // Encoding
    is_encoding_attack_present,
    is_forward_slashes_present,
    is_mixed_separators_present,
    is_multiple_encoding_present,
    is_null_bytes_present,
    is_parent_references_present,
    is_portable,
    is_redirection_present,
    is_relative,
    is_shell_metacharacters_present,
    is_unc_path,
    is_unix_style,
    is_url_encoding_present,
    is_variable_expansion_present,
    is_whitespace_only,
    is_windows_invalid_chars_present,
    is_windows_style,
    starts_with_current_dir,
    starts_with_home_dir,
    starts_with_parent_dir,
};

// Re-export commonly used items from normalization
pub use normalization::{
    is_redundant_separators_present, is_trailing_separator_present, needs_normalization,
    normalize_unix, normalize_windows, strip_redundant_separators, strip_trailing_separator,
    to_backslashes, to_forward_slashes,
};

// Re-export commonly used items from construction
pub use construction::{
    ancestors, clean_path, clean_path_std, depth, effective_depth, extensions, filename,
    find_extension, find_parent, is_extension_found, join_if_relative, join_unix, join_windows,
    split, stem, to_absolute_path, to_relative_path, with_extension,
};

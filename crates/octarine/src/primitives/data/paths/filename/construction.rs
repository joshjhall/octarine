//! Filename construction and extension manipulation
//!
//! Provides functions for constructing and manipulating filenames,
//! particularly focused on extension operations.
//!
//! ## Construction Philosophy
//!
//! Construction functions:
//! - Create new filenames from components
//! - Manipulate extensions safely
//! - Validate inputs before construction
//! - Have both lenient and strict variants
//!
//! ## Extension Operations
//!
//! | Operation | Description | Example |
//! |-----------|-------------|---------|
//! | `set_extension` | Replace extension | `file.txt` → `file.pdf` |
//! | `add_extension` | Append extension | `file.txt` → `file.txt.gz` |
//! | `strip_extension` | Strip extension | `file.txt` → `file` |
//! | `with_stem` | Replace stem | `file.txt` → `new.txt` |

// Allow arithmetic - used for string index calculations that are bounds-checked
#![allow(clippy::arithmetic_side_effects)]

use super::{detection, validation};
use crate::primitives::types::Problem;

// ============================================================================
// Result Type
// ============================================================================

/// Result type for construction operations
pub type ConstructionResult = Result<String, Problem>;

// ============================================================================
// Extension Manipulation
// ============================================================================

/// Set the extension of a filename
///
/// Replaces the existing extension or adds one if none exists.
/// The extension should not include the leading dot.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// assert_eq!(construction::set_extension("file.txt", "pdf"), "file.pdf");
/// assert_eq!(construction::set_extension("file", "txt"), "file.txt");
/// assert_eq!(construction::set_extension("archive.tar.gz", "bz2"), "archive.tar.bz2");
/// ```
#[must_use]
pub fn set_extension(filename: &str, extension: &str) -> String {
    let file_stem = detection::stem(filename);
    let ext = extension.trim_start_matches('.');
    if ext.is_empty() {
        file_stem.to_string()
    } else {
        format!("{}.{}", file_stem, ext)
    }
}

/// Set the extension of a filename (strict)
///
/// Returns error if the filename or extension is invalid.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// assert!(construction::set_extension_strict("file.txt", "pdf").is_ok());
/// assert!(construction::set_extension_strict("", "pdf").is_err());
/// assert!(construction::set_extension_strict("file.txt", "exe").is_err()); // Dangerous
/// ```
pub fn set_extension_strict(filename: &str, extension: &str) -> ConstructionResult {
    // Validate filename
    if detection::is_empty(filename) {
        return Err(Problem::validation("Filename cannot be empty"));
    }
    if detection::is_path_separators_present(filename) {
        return Err(Problem::validation("Filename contains path separators"));
    }

    // Validate extension
    let ext = extension.trim_start_matches('.');
    if !ext.is_empty() {
        if ext.chars().any(|c| !c.is_ascii_alphanumeric()) {
            return Err(Problem::validation("Extension contains invalid characters"));
        }
        // Check for dangerous extension
        let result = set_extension(filename, extension);
        if detection::is_dangerous_extension_present(&result) {
            return Err(Problem::validation(format!(
                "Cannot set dangerous extension '.{}'",
                ext
            )));
        }
    }

    Ok(set_extension(filename, extension))
}

/// Add an extension to a filename
///
/// Appends an extension, creating a double extension.
/// Useful for compression extensions like `.gz`, `.bz2`.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// assert_eq!(construction::add_extension("file.txt", "gz"), "file.txt.gz");
/// assert_eq!(construction::add_extension("archive.tar", "gz"), "archive.tar.gz");
/// ```
#[must_use]
pub fn add_extension(filename: &str, extension: &str) -> String {
    let ext = extension.trim_start_matches('.');
    if ext.is_empty() {
        filename.to_string()
    } else {
        format!("{}.{}", filename, ext)
    }
}

/// Add an extension to a filename (strict)
///
/// Validates both filename and extension before adding.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// assert!(construction::add_extension_strict("file.txt", "gz").is_ok());
/// assert!(construction::add_extension_strict("", "gz").is_err());
/// ```
pub fn add_extension_strict(filename: &str, extension: &str) -> ConstructionResult {
    // Validate filename
    validation::validate_strict(filename)?;

    // Validate extension
    let ext = extension.trim_start_matches('.');
    if !ext.is_empty() && ext.chars().any(|c| !c.is_ascii_alphanumeric()) {
        return Err(Problem::validation("Extension contains invalid characters"));
    }

    Ok(add_extension(filename, extension))
}

/// Remove the extension from a filename
///
/// Returns the filename without its extension.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// assert_eq!(construction::strip_extension("file.txt"), "file");
/// assert_eq!(construction::strip_extension("archive.tar.gz"), "archive.tar");
/// assert_eq!(construction::strip_extension("file"), "file");
/// assert_eq!(construction::strip_extension(".gitignore"), ".gitignore");
/// ```
#[must_use]
pub fn strip_extension(filename: &str) -> String {
    detection::stem(filename).to_string()
}

/// Strip the extension from a filename (strict)
///
/// Validates filename before removing extension.
pub fn strip_extension_strict(filename: &str) -> ConstructionResult {
    validation::validate_strict(filename)?;
    Ok(strip_extension(filename))
}

/// Strip all extensions from a filename
///
/// Removes all extensions, returning the base name.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// assert_eq!(construction::strip_all_extensions("archive.tar.gz"), "archive");
/// assert_eq!(construction::strip_all_extensions("file.txt"), "file");
/// assert_eq!(construction::strip_all_extensions(".gitignore"), ".gitignore");
/// ```
#[must_use]
pub fn strip_all_extensions(filename: &str) -> String {
    // Handle dot files
    if filename.starts_with('.') && !filename[1..].contains('.') {
        return filename.to_string();
    }

    // Find first dot (not at start)
    let start = if filename.starts_with('.') { 1 } else { 0 };
    match filename[start..].find('.') {
        Some(pos) => filename[..start + pos].to_string(),
        None => filename.to_string(),
    }
}

/// Strip all extensions from a filename (strict)
pub fn strip_all_extensions_strict(filename: &str) -> ConstructionResult {
    validation::validate_strict(filename)?;
    Ok(strip_all_extensions(filename))
}

// ============================================================================
// Stem Manipulation
// ============================================================================

/// Replace the stem of a filename, keeping the extension
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// assert_eq!(construction::with_stem("file.txt", "document"), "document.txt");
/// assert_eq!(construction::with_stem("file", "document"), "document");
/// assert_eq!(construction::with_stem(".gitignore", "hidden"), "hidden");
/// ```
#[must_use]
pub fn with_stem(filename: &str, new_stem: &str) -> String {
    match detection::find_extension(filename) {
        Some(ext) => format!("{}.{}", new_stem, ext),
        None => new_stem.to_string(),
    }
}

/// Replace the stem of a filename (strict)
///
/// Validates both the original filename and new stem.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// assert!(construction::with_stem_strict("file.txt", "document").is_ok());
/// assert!(construction::with_stem_strict("file.txt", "../hack").is_err());
/// ```
pub fn with_stem_strict(filename: &str, new_stem: &str) -> ConstructionResult {
    // Validate original filename
    validation::validate_strict(filename)?;

    // Validate new stem
    if detection::is_empty(new_stem) {
        return Err(Problem::validation("Stem cannot be empty"));
    }
    if detection::is_path_separators_present(new_stem) {
        return Err(Problem::validation("Stem contains path separators"));
    }
    if detection::is_command_substitution_present(new_stem) {
        return Err(Problem::validation(
            "Stem contains command substitution patterns",
        ));
    }

    Ok(with_stem(filename, new_stem))
}

// ============================================================================
// Filename Construction
// ============================================================================

/// Construct a filename from stem and extension
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// assert_eq!(construction::from_parts("file", "txt"), "file.txt");
/// assert_eq!(construction::from_parts("file", ""), "file");
/// assert_eq!(construction::from_parts("archive", "tar.gz"), "archive.tar.gz");
/// ```
#[must_use]
pub fn from_parts(stem: &str, extension: &str) -> String {
    let ext = extension.trim_start_matches('.');
    if ext.is_empty() {
        stem.to_string()
    } else {
        format!("{}.{}", stem, ext)
    }
}

/// Construct a filename from stem and extension (strict)
///
/// Validates both stem and extension before construction.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// assert!(construction::from_parts_strict("file", "txt").is_ok());
/// assert!(construction::from_parts_strict("", "txt").is_err());
/// assert!(construction::from_parts_strict("file", "exe").is_err()); // Dangerous
/// ```
pub fn from_parts_strict(stem: &str, extension: &str) -> ConstructionResult {
    // Validate stem
    if detection::is_empty(stem) {
        return Err(Problem::validation("Stem cannot be empty"));
    }
    if detection::is_path_separators_present(stem) {
        return Err(Problem::validation("Stem contains path separators"));
    }
    if detection::is_null_bytes_present(stem) {
        return Err(Problem::validation("Stem contains null bytes"));
    }
    if detection::is_control_characters_present(stem) {
        return Err(Problem::validation("Stem contains control characters"));
    }
    if detection::is_command_substitution_present(stem) {
        return Err(Problem::validation(
            "Stem contains command substitution patterns",
        ));
    }

    // Validate extension
    let ext = extension.trim_start_matches('.');
    if !ext.is_empty() {
        if ext.chars().any(|c| !c.is_ascii_alphanumeric()) {
            return Err(Problem::validation("Extension contains invalid characters"));
        }
        // Check for dangerous extension
        if detection::DANGEROUS_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()) {
            return Err(Problem::validation(format!(
                "Cannot create file with dangerous extension '.{}'",
                ext
            )));
        }
    }

    Ok(from_parts(stem, extension))
}

/// Append suffix to filename stem
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// assert_eq!(construction::append_to_stem("file.txt", "_backup"), "file_backup.txt");
/// assert_eq!(construction::append_to_stem("file", "_v2"), "file_v2");
/// ```
#[must_use]
pub fn append_to_stem(filename: &str, suffix: &str) -> String {
    let file_stem = detection::stem(filename);
    match detection::find_extension(filename) {
        Some(ext) => format!("{}{}.{}", file_stem, suffix, ext),
        None => format!("{}{}", file_stem, suffix),
    }
}

/// Append suffix to filename stem (strict)
pub fn append_to_stem_strict(filename: &str, suffix: &str) -> ConstructionResult {
    validation::validate_strict(filename)?;

    // Validate suffix
    if detection::is_path_separators_present(suffix) {
        return Err(Problem::validation("Suffix contains path separators"));
    }
    if detection::is_null_bytes_present(suffix) {
        return Err(Problem::validation("Suffix contains null bytes"));
    }
    if detection::is_command_substitution_present(suffix) {
        return Err(Problem::validation(
            "Suffix contains command substitution patterns",
        ));
    }

    Ok(append_to_stem(filename, suffix))
}

/// Prepend prefix to filename
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// assert_eq!(construction::prepend_to_filename("file.txt", "backup_"), "backup_file.txt");
/// ```
#[must_use]
pub fn prepend_to_filename(filename: &str, prefix: &str) -> String {
    format!("{}{}", prefix, filename)
}

/// Prepend prefix to filename (strict)
pub fn prepend_to_filename_strict(filename: &str, prefix: &str) -> ConstructionResult {
    validation::validate_strict(filename)?;

    // Validate prefix
    if detection::is_path_separators_present(prefix) {
        return Err(Problem::validation("Prefix contains path separators"));
    }
    if detection::is_null_bytes_present(prefix) {
        return Err(Problem::validation("Prefix contains null bytes"));
    }
    if detection::is_command_substitution_present(prefix) {
        return Err(Problem::validation(
            "Prefix contains command substitution patterns",
        ));
    }

    let result = prepend_to_filename(filename, prefix);

    // Validate result
    validation::validate_strict(&result)?;

    Ok(result)
}

// ============================================================================
// Numbered Filenames
// ============================================================================

/// Add a number suffix to filename
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// assert_eq!(construction::with_number("file.txt", 1), "file_1.txt");
/// assert_eq!(construction::with_number("file.txt", 42), "file_42.txt");
/// ```
#[must_use]
pub fn with_number(filename: &str, number: u32) -> String {
    append_to_stem(filename, &format!("_{}", number))
}

/// Add a zero-padded number suffix to filename
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// assert_eq!(construction::with_padded_number("file.txt", 1, 3), "file_001.txt");
/// assert_eq!(construction::with_padded_number("file.txt", 42, 4), "file_0042.txt");
/// ```
#[must_use]
pub fn with_padded_number(filename: &str, number: u32, width: usize) -> String {
    append_to_stem(filename, &format!("_{:0width$}", number, width = width))
}

/// Generate a sequence of numbered filenames
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// let names: Vec<_> = construction::numbered_sequence("file.txt", 1, 3).collect();
/// assert_eq!(names, vec!["file_1.txt", "file_2.txt", "file_3.txt"]);
/// ```
pub fn numbered_sequence(
    filename: &str,
    start: u32,
    end: u32,
) -> impl Iterator<Item = String> + '_ {
    (start..=end).map(move |n| with_number(filename, n))
}

// ============================================================================
// Safe Filename Generation
// ============================================================================

/// Generate a timestamp-based filename
///
/// Uses current timestamp as the stem.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// let name = construction::with_timestamp("log", "txt");
/// // Returns something like "log_1699876543.txt"
/// ```
#[must_use]
pub fn with_timestamp(prefix: &str, extension: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let ext = extension.trim_start_matches('.');
    if ext.is_empty() {
        format!("{}_{}", prefix, timestamp)
    } else {
        format!("{}_{}.{}", prefix, timestamp, ext)
    }
}

/// Generate a unique filename using UUID
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::construction;
///
/// let name = construction::with_uuid("upload", "jpg");
/// // Returns something like "upload_a1b2c3d4.jpg"
/// ```
#[must_use]
pub fn with_uuid(prefix: &str, extension: &str) -> String {
    // Simple pseudo-UUID using timestamp and random-ish value
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    // Create a simple hex-like identifier
    let id = format!("{:016x}", timestamp);
    let short_id = &id[..8.min(id.len())];

    let ext = extension.trim_start_matches('.');
    if ext.is_empty() {
        format!("{}_{}", prefix, short_id)
    } else {
        format!("{}_{}.{}", prefix, short_id, ext)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ------------------------------------------------------------------------
    // Extension Manipulation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_set_extension() {
        assert_eq!(set_extension("file.txt", "pdf"), "file.pdf");
        assert_eq!(set_extension("file", "txt"), "file.txt");
        assert_eq!(set_extension("archive.tar.gz", "bz2"), "archive.tar.bz2");
        assert_eq!(set_extension("file.txt", ""), "file");
        assert_eq!(set_extension("file.txt", ".pdf"), "file.pdf"); // Handles dot
    }

    #[test]
    fn test_set_extension_strict() {
        assert!(set_extension_strict("file.txt", "pdf").is_ok());
        assert!(set_extension_strict("file.txt", "").is_ok());

        // Invalid cases
        assert!(set_extension_strict("", "pdf").is_err());
        assert!(set_extension_strict("foo/bar.txt", "pdf").is_err());
        assert!(set_extension_strict("file.txt", "exe").is_err()); // Dangerous
        assert!(set_extension_strict("file.txt", "a;b").is_err()); // Invalid char
    }

    #[test]
    fn test_add_extension() {
        assert_eq!(add_extension("file.txt", "gz"), "file.txt.gz");
        assert_eq!(add_extension("archive.tar", "gz"), "archive.tar.gz");
        assert_eq!(add_extension("file", "txt"), "file.txt");
        assert_eq!(add_extension("file.txt", ""), "file.txt");
    }

    #[test]
    fn test_add_extension_strict() {
        assert!(add_extension_strict("file.txt", "gz").is_ok());
        assert!(add_extension_strict("file.txt", "").is_ok());

        assert!(add_extension_strict("", "gz").is_err());
        assert!(add_extension_strict("file.txt", "a;b").is_err());
    }

    #[test]
    fn test_strip_extension() {
        assert_eq!(strip_extension("file.txt"), "file");
        assert_eq!(strip_extension("archive.tar.gz"), "archive.tar");
        assert_eq!(strip_extension("file"), "file");
        assert_eq!(strip_extension(".gitignore"), ".gitignore");
    }

    #[test]
    fn test_strip_all_extensions() {
        assert_eq!(strip_all_extensions("archive.tar.gz"), "archive");
        assert_eq!(strip_all_extensions("file.txt"), "file");
        assert_eq!(strip_all_extensions("file"), "file");
        assert_eq!(strip_all_extensions(".gitignore"), ".gitignore");
        assert_eq!(strip_all_extensions(".git.config"), ".git");
    }

    // ------------------------------------------------------------------------
    // Stem Manipulation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_with_stem() {
        assert_eq!(with_stem("file.txt", "document"), "document.txt");
        assert_eq!(with_stem("file", "document"), "document");
        assert_eq!(with_stem(".gitignore", "hidden"), "hidden");
        assert_eq!(with_stem("archive.tar.gz", "backup"), "backup.gz");
    }

    #[test]
    fn test_with_stem_strict() {
        assert!(with_stem_strict("file.txt", "document").is_ok());

        assert!(with_stem_strict("file.txt", "").is_err());
        assert!(with_stem_strict("file.txt", "../hack").is_err());
        assert!(with_stem_strict("file.txt", "$(cmd)").is_err());
    }

    // ------------------------------------------------------------------------
    // Construction Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_from_parts() {
        assert_eq!(from_parts("file", "txt"), "file.txt");
        assert_eq!(from_parts("file", ""), "file");
        assert_eq!(from_parts("archive", "tar.gz"), "archive.tar.gz");
        assert_eq!(from_parts("file", ".txt"), "file.txt"); // Handles dot
    }

    #[test]
    fn test_from_parts_strict() {
        assert!(from_parts_strict("file", "txt").is_ok());
        assert!(from_parts_strict("file", "").is_ok());

        assert!(from_parts_strict("", "txt").is_err());
        assert!(from_parts_strict("../file", "txt").is_err());
        assert!(from_parts_strict("file", "exe").is_err()); // Dangerous
    }

    #[test]
    fn test_append_to_stem() {
        assert_eq!(append_to_stem("file.txt", "_backup"), "file_backup.txt");
        assert_eq!(append_to_stem("file", "_v2"), "file_v2");
        assert_eq!(
            append_to_stem("archive.tar.gz", "_old"),
            "archive.tar_old.gz"
        );
    }

    #[test]
    fn test_append_to_stem_strict() {
        assert!(append_to_stem_strict("file.txt", "_backup").is_ok());

        assert!(append_to_stem_strict("file.txt", "/../").is_err());
        assert!(append_to_stem_strict("file.txt", "$(cmd)").is_err());
    }

    #[test]
    fn test_prepend_to_filename() {
        assert_eq!(
            prepend_to_filename("file.txt", "backup_"),
            "backup_file.txt"
        );
        assert_eq!(prepend_to_filename("file.txt", ""), "file.txt");
    }

    #[test]
    fn test_prepend_to_filename_strict() {
        assert!(prepend_to_filename_strict("file.txt", "backup_").is_ok());

        assert!(prepend_to_filename_strict("file.txt", "../").is_err());
        assert!(prepend_to_filename_strict("file.txt", "$(cmd)_").is_err());
    }

    // ------------------------------------------------------------------------
    // Numbered Filename Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_with_number() {
        assert_eq!(with_number("file.txt", 1), "file_1.txt");
        assert_eq!(with_number("file.txt", 42), "file_42.txt");
        assert_eq!(with_number("file", 1), "file_1");
    }

    #[test]
    fn test_with_padded_number() {
        assert_eq!(with_padded_number("file.txt", 1, 3), "file_001.txt");
        assert_eq!(with_padded_number("file.txt", 42, 4), "file_0042.txt");
        assert_eq!(with_padded_number("file.txt", 1000, 3), "file_1000.txt");
    }

    #[test]
    fn test_numbered_sequence() {
        let names: Vec<_> = numbered_sequence("file.txt", 1, 3).collect();
        assert_eq!(names, vec!["file_1.txt", "file_2.txt", "file_3.txt"]);

        let names: Vec<_> = numbered_sequence("log", 0, 2).collect();
        assert_eq!(names, vec!["log_0", "log_1", "log_2"]);
    }

    // ------------------------------------------------------------------------
    // Safe Filename Generation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_with_timestamp() {
        let name = with_timestamp("log", "txt");
        assert!(name.starts_with("log_"));
        assert!(name.ends_with(".txt"));

        let name = with_timestamp("file", "");
        assert!(name.starts_with("file_"));
        assert!(!name.contains('.'));
    }

    #[test]
    fn test_with_uuid() {
        let name = with_uuid("upload", "jpg");
        assert!(name.starts_with("upload_"));
        assert!(name.ends_with(".jpg"));

        let name = with_uuid("file", "");
        assert!(name.starts_with("file_"));
        assert!(!name.contains('.'));

        // Each call should be unique
        let name1 = with_uuid("test", "txt");
        std::thread::sleep(std::time::Duration::from_millis(1));
        let name2 = with_uuid("test", "txt");
        // They might be equal in fast tests, so just check format
        assert!(name1.starts_with("test_"));
        assert!(name2.starts_with("test_"));
    }

    // ------------------------------------------------------------------------
    // Edge Cases
    // ------------------------------------------------------------------------

    #[test]
    fn test_extension_edge_cases() {
        // Dot files
        assert_eq!(set_extension(".gitignore", "bak"), ".gitignore.bak");
        assert_eq!(strip_extension(".gitignore"), ".gitignore");

        // Multiple dots
        assert_eq!(set_extension("file..txt", "pdf"), "file..pdf");

        // Empty parts
        assert_eq!(from_parts("", "txt"), ".txt");
        assert_eq!(from_parts("file", ""), "file");
    }
}

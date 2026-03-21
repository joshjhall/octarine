//! Transformation functions
//!
//! Functions for replacing, normalizing, and transforming filename content.

use std::borrow::Cow;

use super::super::detection;

// ============================================================================
// Replacement Functions
// ============================================================================

/// Replace spaces with underscores
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::replace_spaces("my file.txt").as_ref(), "my_file.txt");
/// ```
#[must_use]
pub fn replace_spaces(filename: &str) -> Cow<'_, str> {
    if filename.contains(' ') {
        Cow::Owned(filename.replace(' ', "_"))
    } else {
        Cow::Borrowed(filename)
    }
}

/// Replace spaces with hyphens
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::replace_spaces_with_hyphens("my file.txt").as_ref(), "my-file.txt");
/// ```
#[must_use]
pub fn replace_spaces_with_hyphens(filename: &str) -> Cow<'_, str> {
    if filename.contains(' ') {
        Cow::Owned(filename.replace(' ', "-"))
    } else {
        Cow::Borrowed(filename)
    }
}

/// Collapse multiple consecutive underscores/hyphens
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::collapse_separators("file___name.txt").as_ref(), "file_name.txt");
/// ```
#[must_use]
pub fn collapse_separators(filename: &str) -> Cow<'_, str> {
    if filename.contains("__") || filename.contains("--") {
        let mut result = filename.to_string();
        while result.contains("__") {
            result = result.replace("__", "_");
        }
        while result.contains("--") {
            result = result.replace("--", "-");
        }
        Cow::Owned(result)
    } else {
        Cow::Borrowed(filename)
    }
}

// ============================================================================
// Normalization Functions
// ============================================================================

/// Normalize filename to lowercase
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::normalize_case("FILE.TXT").as_ref(), "file.txt");
/// ```
#[must_use]
pub fn normalize_case(filename: &str) -> Cow<'_, str> {
    detection::normalize_case(filename)
}

/// Normalize extension to lowercase
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::normalize_extension("file.TXT").as_ref(), "file.txt");
/// ```
#[must_use]
pub fn normalize_extension(filename: &str) -> Cow<'_, str> {
    if let Some(ext) = detection::find_extension(filename) {
        let lower_ext = ext.to_lowercase();
        if ext != lower_ext {
            let file_stem = detection::stem(filename);
            return Cow::Owned(format!("{}.{}", file_stem, lower_ext));
        }
    }
    Cow::Borrowed(filename)
}

/// Trim leading and trailing whitespace/dots
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::trim_filename("  file.txt  ").as_ref(), "file.txt");
/// ```
#[must_use]
pub fn trim_filename(filename: &str) -> Cow<'_, str> {
    let trimmed = filename.trim();
    if trimmed.len() != filename.len() {
        Cow::Owned(trimmed.to_string())
    } else {
        Cow::Borrowed(filename)
    }
}

// ============================================================================
// Prefix Handling
// ============================================================================

/// Add prefix to reserved Windows names
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::prefix_reserved("CON").as_ref(), "_CON");
/// assert_eq!(sanitization::prefix_reserved("file.txt").as_ref(), "file.txt");
/// ```
#[must_use]
pub fn prefix_reserved(filename: &str) -> Cow<'_, str> {
    if detection::is_reserved_name(filename) {
        Cow::Owned(format!("_{}", filename))
    } else {
        Cow::Borrowed(filename)
    }
}

/// Strip leading dots (unhide file)
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::sanitization;
///
/// assert_eq!(sanitization::strip_leading_dots(".hidden").as_ref(), "hidden");
/// assert_eq!(sanitization::strip_leading_dots("file.txt").as_ref(), "file.txt");
/// ```
#[must_use]
pub fn strip_leading_dots(filename: &str) -> Cow<'_, str> {
    if filename.starts_with('.') && !detection::is_directory_ref(filename) {
        Cow::Owned(filename.trim_start_matches('.').to_string())
    } else {
        Cow::Borrowed(filename)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_replace_spaces() {
        assert_eq!(replace_spaces("my file.txt").as_ref(), "my_file.txt");
        assert_eq!(replace_spaces("file.txt").as_ref(), "file.txt");
    }

    #[test]
    fn test_replace_spaces_with_hyphens() {
        assert_eq!(
            replace_spaces_with_hyphens("my file.txt").as_ref(),
            "my-file.txt"
        );
    }

    #[test]
    fn test_collapse_separators() {
        assert_eq!(
            collapse_separators("file___name.txt").as_ref(),
            "file_name.txt"
        );
        assert_eq!(
            collapse_separators("file---name.txt").as_ref(),
            "file-name.txt"
        );
        assert_eq!(
            collapse_separators("file_name.txt").as_ref(),
            "file_name.txt"
        );
    }

    #[test]
    fn test_normalize_case() {
        assert_eq!(normalize_case("FILE.TXT").as_ref(), "file.txt");
        assert_eq!(normalize_case("file.txt").as_ref(), "file.txt");
    }

    #[test]
    fn test_normalize_extension() {
        assert_eq!(normalize_extension("file.TXT").as_ref(), "file.txt");
        assert_eq!(normalize_extension("file.txt").as_ref(), "file.txt");
        assert_eq!(normalize_extension("FILE.TXT").as_ref(), "FILE.txt");
    }

    #[test]
    fn test_trim_filename() {
        assert_eq!(trim_filename("  file.txt  ").as_ref(), "file.txt");
        assert_eq!(trim_filename("file.txt").as_ref(), "file.txt");
    }

    #[test]
    fn test_prefix_reserved() {
        assert_eq!(prefix_reserved("CON").as_ref(), "_CON");
        assert_eq!(prefix_reserved("NUL").as_ref(), "_NUL");
        assert_eq!(prefix_reserved("file.txt").as_ref(), "file.txt");
    }

    #[test]
    fn test_strip_leading_dots() {
        assert_eq!(strip_leading_dots(".hidden").as_ref(), "hidden");
        assert_eq!(strip_leading_dots("..hidden").as_ref(), "hidden");
        assert_eq!(strip_leading_dots("file.txt").as_ref(), "file.txt");
        assert_eq!(strip_leading_dots(".").as_ref(), ".");
        assert_eq!(strip_leading_dots("..").as_ref(), "..");
    }
}

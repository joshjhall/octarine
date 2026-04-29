//! Lenient sanitization delegators for [`PathBuilder`].
//!
//! Methods that delegate to [`LenientBuilder`] — these always return a
//! value (never error), suitable for best-effort cleaning.

use super::super::{LenientBuilder, PathBuilder};

impl PathBuilder {
    /// Clean path (lenient)
    #[must_use]
    pub fn clean_path(&self, path: &str) -> String {
        LenientBuilder::new().clean_path(path)
    }

    /// Clean user path (lenient)
    #[must_use]
    pub fn clean_user_path(&self, path: &str) -> String {
        LenientBuilder::new().clean_user_path(path)
    }

    /// Clean filename (lenient)
    #[must_use]
    pub fn clean_filename(&self, filename: &str) -> String {
        LenientBuilder::new().clean_filename(filename)
    }

    /// Clean separators (lenient)
    #[must_use]
    pub fn clean_separators(&self, path: &str) -> String {
        LenientBuilder::new().clean_separators(path)
    }
}

//! Path type and platform characteristic delegators for [`PathBuilder`].
//!
//! Methods that delegate to [`CharacteristicBuilder`].

use super::super::CharacteristicBuilder;
use super::super::PathBuilder;
use crate::data::paths::types::{PathType, Platform};

impl PathBuilder {
    /// Detect the type of a path
    #[must_use]
    pub fn detect_path_type(&self, path: &str) -> PathType {
        CharacteristicBuilder::new().detect_path_type(path)
    }

    /// Detect the platform of a path
    #[must_use]
    pub fn detect_platform(&self, path: &str) -> Platform {
        CharacteristicBuilder::new().detect_platform(path)
    }

    /// Check if path is absolute
    #[must_use]
    pub fn is_absolute(&self, path: &str) -> bool {
        CharacteristicBuilder::new().is_absolute(path)
    }

    /// Check if path is relative
    #[must_use]
    pub fn is_relative(&self, path: &str) -> bool {
        CharacteristicBuilder::new().is_relative(path)
    }

    /// Check if path is portable
    #[must_use]
    pub fn is_portable(&self, path: &str) -> bool {
        CharacteristicBuilder::new().is_portable(path)
    }

    /// Check if path is Unix-style
    #[must_use]
    pub fn is_unix_style(&self, path: &str) -> bool {
        CharacteristicBuilder::new().is_unix_path(path)
    }

    /// Check if path is Windows-style
    #[must_use]
    pub fn is_windows_style(&self, path: &str) -> bool {
        CharacteristicBuilder::new().is_windows_path(path)
    }
}

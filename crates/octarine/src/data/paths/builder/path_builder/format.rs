//! Path format conversion delegators for [`PathBuilder`].
//!
//! Methods that delegate to [`FormatBuilder`] for detection of path
//! format and conversion between Unix, Windows, and WSL representations.

use super::super::{FormatBuilder, PathBuilder, PathFormat};
use crate::primitives::data::paths::PathBuilder as PrimitivePathBuilder;

impl PathBuilder {
    /// Detect the format of a path
    #[must_use]
    pub fn detect_format(&self, path: &str) -> PathFormat {
        FormatBuilder::new().detect(path)
    }

    /// Convert path to a specific format
    #[must_use]
    pub fn convert_format(&self, path: &str, target: PathFormat) -> String {
        FormatBuilder::new().convert(path, target).into_owned()
    }

    /// Convert to Unix format
    #[must_use]
    pub fn to_unix(&self, path: &str) -> String {
        FormatBuilder::new().convert_to_unix(path).into_owned()
    }

    /// Convert to Windows format
    #[must_use]
    pub fn to_windows(&self, path: &str) -> String {
        FormatBuilder::new().convert_to_windows(path).into_owned()
    }

    /// Normalize path
    #[must_use]
    pub fn normalize(&self, path: &str) -> String {
        PrimitivePathBuilder::new().normalize_unix(path)
    }

    /// Convert to WSL path
    #[must_use]
    pub fn to_wsl(&self, path: &str) -> Option<String> {
        FormatBuilder::new().convert_to_wsl(path)
    }

    /// Convert WSL to Windows path
    #[must_use]
    pub fn wsl_to_windows(&self, path: &str) -> Option<String> {
        FormatBuilder::new().wsl_to_windows(path)
    }
}

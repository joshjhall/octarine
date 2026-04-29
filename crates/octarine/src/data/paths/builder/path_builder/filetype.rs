//! File category and type delegators for [`PathBuilder`].
//!
//! Methods that delegate to [`FiletypeBuilder`].

use super::super::FiletypeBuilder;
use super::super::PathBuilder;
use crate::data::paths::types::FileCategory;

impl PathBuilder {
    /// Detect the file category
    #[must_use]
    pub fn detect_file_category(&self, path: &str) -> FileCategory {
        FiletypeBuilder::new().detect(path)
    }

    /// Check if file is an image
    #[must_use]
    pub fn is_image(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_image(path)
    }

    /// Check if file is audio
    #[must_use]
    pub fn is_audio(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_audio(path)
    }

    /// Check if file is video
    #[must_use]
    pub fn is_video(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_video(path)
    }

    /// Check if file is media
    #[must_use]
    pub fn is_media(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_media(path)
    }

    /// Check if file is a document
    #[must_use]
    pub fn is_document(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_document(path)
    }

    /// Check if file is source code
    #[must_use]
    pub fn is_code(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_code(path)
    }

    /// Check if file is a config file
    #[must_use]
    pub fn is_config(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_config(path)
    }

    /// Check if file is an executable
    #[must_use]
    pub fn is_executable(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_executable(path)
    }

    /// Check if file is an archive
    #[must_use]
    pub fn is_archive(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_archive(path)
    }

    /// Check if file is security-sensitive
    #[must_use]
    pub fn is_security_sensitive(&self, path: &str) -> bool {
        FiletypeBuilder::new().is_security_sensitive(path)
    }
}

//! File type detection builder
//!
//! Provides a builder interface for file type detection operations.
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only

use super::super::types::FileCategory;
use super::detection;

/// Builder for file type detection operations
///
/// Provides a fluent interface for detecting file types based on
/// extensions and filename patterns.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::filetype::FiletypeBuilder;
/// use octarine::primitives::paths::types::FileCategory;
///
/// let filetype = FiletypeBuilder::new();
///
/// // Detect file category
/// assert_eq!(filetype.detect("photo.jpg"), FileCategory::Image);
/// assert_eq!(filetype.detect("main.rs"), FileCategory::SourceCode);
///
/// // Category checks
/// assert!(filetype.is_image("photo.jpg"));
/// assert!(filetype.is_code("main.rs"));
/// assert!(filetype.is_security_sensitive(".env"));
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct FiletypeBuilder;

impl FiletypeBuilder {
    /// Create a new file type builder
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    // ========================================================================
    // Core Detection
    // ========================================================================

    /// Detect file category from path
    ///
    /// Examines the filename and extension to determine the file category.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to analyze (can be full path or just filename)
    ///
    /// # Returns
    ///
    /// `FileCategory` indicating the detected type
    #[must_use]
    pub fn detect(&self, path: &str) -> FileCategory {
        detection::detect_file_category(path)
    }

    /// Find file extension (lowercase)
    ///
    /// # Arguments
    ///
    /// * `path` - Path to extract extension from
    ///
    /// # Returns
    ///
    /// `Some(extension)` in lowercase, or `None` if no extension
    #[must_use]
    pub fn find_extension(&self, path: &str) -> Option<String> {
        detection::find_extension(path)
    }

    /// Check if file has a specific extension (case-insensitive)
    ///
    /// # Arguments
    ///
    /// * `path` - Path to check
    /// * `ext` - Extension to check for (without dot)
    #[must_use]
    pub fn is_extension_found(&self, path: &str, ext: &str) -> bool {
        detection::is_extension_found(path, ext)
    }

    // ========================================================================
    // Media Checks
    // ========================================================================

    /// Check if file is an image
    #[must_use]
    pub fn is_image(&self, path: &str) -> bool {
        detection::is_image(path)
    }

    /// Check if file is audio
    #[must_use]
    pub fn is_audio(&self, path: &str) -> bool {
        detection::is_audio(path)
    }

    /// Check if file is video
    #[must_use]
    pub fn is_video(&self, path: &str) -> bool {
        detection::is_video(path)
    }

    /// Check if file is any media type (image, audio, or video)
    #[must_use]
    pub fn is_media(&self, path: &str) -> bool {
        detection::is_media(path)
    }

    // ========================================================================
    // Document Checks
    // ========================================================================

    /// Check if file is a document (including text, spreadsheets, presentations)
    #[must_use]
    pub fn is_document(&self, path: &str) -> bool {
        detection::is_document(path)
    }

    // ========================================================================
    // Code Checks
    // ========================================================================

    /// Check if file is source code or script
    #[must_use]
    pub fn is_code(&self, path: &str) -> bool {
        detection::is_code(path)
    }

    /// Check if file is a configuration file
    #[must_use]
    pub fn is_config(&self, path: &str) -> bool {
        detection::is_config(path)
    }

    /// Check if file is a data file (databases, structured data)
    #[must_use]
    pub fn is_data(&self, path: &str) -> bool {
        detection::is_data(path)
    }

    // ========================================================================
    // Binary Checks
    // ========================================================================

    /// Check if file is an executable
    #[must_use]
    pub fn is_executable(&self, path: &str) -> bool {
        detection::is_executable(path)
    }

    /// Check if file is a library
    #[must_use]
    pub fn is_library(&self, path: &str) -> bool {
        detection::is_library(path)
    }

    /// Check if file is an archive or compressed
    #[must_use]
    pub fn is_archive(&self, path: &str) -> bool {
        detection::is_archive(path)
    }

    // ========================================================================
    // Security Checks
    // ========================================================================

    /// Check if file is security-sensitive (credentials, keys, certs)
    #[must_use]
    pub fn is_security_sensitive(&self, path: &str) -> bool {
        detection::is_security_sensitive(path)
    }

    // ========================================================================
    // Special File Checks
    // ========================================================================

    /// Check if file is hidden or temporary
    #[must_use]
    pub fn is_hidden_or_temp(&self, path: &str) -> bool {
        detection::is_hidden_or_temp(path)
    }

    /// Check if file is text-based (human-readable)
    #[must_use]
    pub fn is_text_based(&self, path: &str) -> bool {
        detection::is_text_based(path)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_new() {
        let builder = FiletypeBuilder::new();
        assert_eq!(builder.detect("photo.jpg"), FileCategory::Image);
    }

    #[test]
    fn test_builder_default() {
        let builder = FiletypeBuilder;
        assert_eq!(builder.detect("main.rs"), FileCategory::SourceCode);
    }

    #[test]
    fn test_builder_detect() {
        let builder = FiletypeBuilder::new();

        assert_eq!(builder.detect("photo.jpg"), FileCategory::Image);
        assert_eq!(builder.detect("song.mp3"), FileCategory::Audio);
        assert_eq!(builder.detect("movie.mp4"), FileCategory::Video);
        assert_eq!(builder.detect("report.pdf"), FileCategory::Document);
        assert_eq!(builder.detect("main.rs"), FileCategory::SourceCode);
        assert_eq!(builder.detect("script.sh"), FileCategory::Script);
        assert_eq!(builder.detect("config.json"), FileCategory::Config);
        assert_eq!(builder.detect(".env"), FileCategory::Credential);
    }

    #[test]
    fn test_builder_find_extension() {
        let builder = FiletypeBuilder::new();

        assert_eq!(builder.find_extension("photo.JPG"), Some("jpg".to_string()));
        assert_eq!(
            builder.find_extension("/path/file.rs"),
            Some("rs".to_string())
        );
        assert_eq!(builder.find_extension(".gitignore"), None);
        assert_eq!(builder.find_extension("no_ext"), None);
    }

    #[test]
    fn test_builder_is_extension_found() {
        let builder = FiletypeBuilder::new();

        assert!(builder.is_extension_found("photo.JPG", "jpg"));
        assert!(builder.is_extension_found("photo.jpg", "JPG"));
        assert!(!builder.is_extension_found("photo.png", "jpg"));
    }

    #[test]
    fn test_builder_media_checks() {
        let builder = FiletypeBuilder::new();

        assert!(builder.is_image("photo.jpg"));
        assert!(builder.is_audio("song.mp3"));
        assert!(builder.is_video("movie.mp4"));
        assert!(builder.is_media("photo.jpg"));
        assert!(builder.is_media("song.mp3"));
        assert!(builder.is_media("movie.mp4"));
        assert!(!builder.is_media("document.pdf"));
    }

    #[test]
    fn test_builder_document_check() {
        let builder = FiletypeBuilder::new();

        assert!(builder.is_document("report.pdf"));
        assert!(builder.is_document("data.xlsx"));
        assert!(builder.is_document("notes.txt"));
        assert!(!builder.is_document("photo.jpg"));
    }

    #[test]
    fn test_builder_code_checks() {
        let builder = FiletypeBuilder::new();

        assert!(builder.is_code("main.rs"));
        assert!(builder.is_code("script.sh"));
        assert!(builder.is_config("config.json"));
        assert!(builder.is_data("database.sql"));
        assert!(!builder.is_code("photo.jpg"));
    }

    #[test]
    fn test_builder_binary_checks() {
        let builder = FiletypeBuilder::new();

        assert!(builder.is_executable("program.exe"));
        assert!(builder.is_library("libfoo.so"));
        assert!(builder.is_archive("backup.zip"));
        assert!(!builder.is_executable("document.pdf"));
    }

    #[test]
    fn test_builder_security_check() {
        let builder = FiletypeBuilder::new();

        assert!(builder.is_security_sensitive(".env"));
        assert!(builder.is_security_sensitive("server.key"));
        assert!(builder.is_security_sensitive("id_rsa"));
        assert!(!builder.is_security_sensitive("readme.txt"));
    }

    #[test]
    fn test_builder_special_checks() {
        let builder = FiletypeBuilder::new();

        assert!(builder.is_hidden_or_temp(".gitignore"));
        assert!(builder.is_hidden_or_temp("file.tmp"));
        assert!(builder.is_text_based("readme.txt"));
        assert!(builder.is_text_based("main.rs"));
        assert!(!builder.is_text_based("photo.jpg"));
    }
}

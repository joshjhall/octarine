//! File type detection methods
//!
//! Methods for detecting file categories based on path and extension.

use super::super::filetype;
use super::super::types::FileCategory;
use super::core::PathBuilder;

impl PathBuilder {
    /// Detect file category from path
    ///
    /// Examines the filename and extension to determine the file category.
    /// Delegates to [`filetype::detect_file_category`].
    #[must_use]
    pub fn detect_file_category(&self, path: &str) -> FileCategory {
        filetype::detect_file_category(path)
    }

    /// Check if file is an image
    #[must_use]
    pub fn is_image(&self, path: &str) -> bool {
        filetype::is_image(path)
    }

    /// Check if file is audio
    #[must_use]
    pub fn is_audio(&self, path: &str) -> bool {
        filetype::is_audio(path)
    }

    /// Check if file is video
    #[must_use]
    pub fn is_video(&self, path: &str) -> bool {
        filetype::is_video(path)
    }

    /// Check if file is any media type (image, audio, or video)
    #[must_use]
    pub fn is_media(&self, path: &str) -> bool {
        filetype::is_media(path)
    }

    /// Check if file is a document (including text, spreadsheets, presentations)
    #[must_use]
    pub fn is_document(&self, path: &str) -> bool {
        filetype::is_document(path)
    }

    /// Check if file is source code or script
    #[must_use]
    pub fn is_code(&self, path: &str) -> bool {
        filetype::is_code(path)
    }

    /// Check if file is a configuration file
    #[must_use]
    pub fn is_config(&self, path: &str) -> bool {
        filetype::is_config(path)
    }

    /// Check if file is a data file (databases, structured data)
    #[must_use]
    pub fn is_data(&self, path: &str) -> bool {
        filetype::is_data(path)
    }

    /// Check if file is an executable
    #[must_use]
    pub fn is_executable(&self, path: &str) -> bool {
        filetype::is_executable(path)
    }

    /// Check if file is a library
    #[must_use]
    pub fn is_library(&self, path: &str) -> bool {
        filetype::is_library(path)
    }

    /// Check if file is an archive or compressed
    #[must_use]
    pub fn is_archive(&self, path: &str) -> bool {
        filetype::is_archive(path)
    }

    /// Check if file is security-sensitive (credentials, keys, certs)
    #[must_use]
    pub fn is_security_sensitive(&self, path: &str) -> bool {
        filetype::is_security_sensitive(path)
    }

    /// Check if file is hidden or temporary
    #[must_use]
    pub fn is_hidden_or_temp(&self, path: &str) -> bool {
        filetype::is_hidden_or_temp(path)
    }

    /// Check if file is text-based (human-readable)
    #[must_use]
    pub fn is_text_based(&self, path: &str) -> bool {
        filetype::is_text_based(path)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_file_category() {
        let builder = PathBuilder::new();

        assert_eq!(
            builder.detect_file_category("image.png"),
            FileCategory::Image
        );
        assert_eq!(
            builder.detect_file_category("song.mp3"),
            FileCategory::Audio
        );
        assert_eq!(
            builder.detect_file_category("movie.mp4"),
            FileCategory::Video
        );
        assert_eq!(
            builder.detect_file_category("script.rs"),
            FileCategory::SourceCode
        );
    }

    #[test]
    fn test_is_image() {
        let builder = PathBuilder::new();

        assert!(builder.is_image("photo.jpg"));
        assert!(builder.is_image("image.png"));
        assert!(builder.is_image("icon.gif"));

        assert!(!builder.is_image("document.pdf"));
        assert!(!builder.is_image("script.py"));
    }

    #[test]
    fn test_is_audio() {
        let builder = PathBuilder::new();

        assert!(builder.is_audio("song.mp3"));
        assert!(builder.is_audio("audio.wav"));
        assert!(builder.is_audio("music.flac"));

        assert!(!builder.is_audio("video.mp4"));
    }

    #[test]
    fn test_is_video() {
        let builder = PathBuilder::new();

        assert!(builder.is_video("movie.mp4"));
        assert!(builder.is_video("video.avi"));
        assert!(builder.is_video("clip.mov"));

        assert!(!builder.is_video("audio.mp3"));
    }

    #[test]
    fn test_is_media() {
        let builder = PathBuilder::new();

        assert!(builder.is_media("photo.jpg"));
        assert!(builder.is_media("song.mp3"));
        assert!(builder.is_media("video.mp4"));

        assert!(!builder.is_media("document.pdf"));
    }

    #[test]
    fn test_is_code() {
        let builder = PathBuilder::new();

        assert!(builder.is_code("main.rs"));
        assert!(builder.is_code("script.py"));
        assert!(builder.is_code("app.js"));

        assert!(!builder.is_code("document.pdf"));
    }

    #[test]
    fn test_is_archive() {
        let builder = PathBuilder::new();

        assert!(builder.is_archive("archive.zip"));
        assert!(builder.is_archive("package.tar.gz"));
        assert!(builder.is_archive("backup.rar"));

        assert!(!builder.is_archive("document.pdf"));
    }

    #[test]
    fn test_is_security_sensitive() {
        let builder = PathBuilder::new();

        assert!(builder.is_security_sensitive("id_rsa"));
        assert!(builder.is_security_sensitive("cert.pem"));
        assert!(builder.is_security_sensitive(".env"));

        assert!(!builder.is_security_sensitive("readme.txt"));
    }
}

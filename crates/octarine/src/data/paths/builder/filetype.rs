//! File type detection builder with observability
//!
//! Wraps `primitives::data::paths::FiletypeBuilder` with observe instrumentation.
//!
//! Provides file category detection based on extension.
//!
//! # Examples
//!
//! ```rust
//! use octarine::data::paths::FiletypeBuilder;
//!
//! let ft = FiletypeBuilder::new();
//!
//! // Category detection
//! assert!(ft.is_image("photo.jpg"));
//! assert!(ft.is_code("main.rs"));
//! assert!(ft.is_security_sensitive(".env"));
//!
//! // Get category
//! let category = ft.detect("config.json");
//! ```

use crate::observe;
use crate::observe::metrics::increment;
use crate::primitives::data::paths::FiletypeBuilder as PrimitiveFiletypeBuilder;

use crate::data::paths::types::FileCategory;

crate::define_metrics! {
    detected => "data.paths.filetype.detected",
    security_sensitive => "data.paths.filetype.security_sensitive",
}

/// File type detection builder with observability
///
/// Provides file category detection with audit trail.
#[derive(Debug, Clone, Default)]
pub struct FiletypeBuilder {
    emit_events: bool,
}

impl FiletypeBuilder {
    /// Create a new filetype builder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self { emit_events: true }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self { emit_events: false }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // Category Detection
    // ========================================================================

    /// Detect file category from path
    #[must_use]
    pub fn detect(&self, path: &str) -> FileCategory {
        let category = PrimitiveFiletypeBuilder::new().detect(path).into();
        if self.emit_events {
            increment(metric_names::detected());
        }
        category
    }

    /// Find extension (normalized to lowercase)
    #[must_use]
    pub fn find_extension(&self, path: &str) -> Option<String> {
        PrimitiveFiletypeBuilder::new().find_extension(path)
    }

    /// Check if extension matches (case-insensitive)
    #[must_use]
    pub fn is_extension_found(&self, path: &str, ext: &str) -> bool {
        PrimitiveFiletypeBuilder::new().is_extension_found(path, ext)
    }

    // ========================================================================
    // Media Checks
    // ========================================================================

    /// Check if file is an image
    #[must_use]
    pub fn is_image(&self, path: &str) -> bool {
        PrimitiveFiletypeBuilder::new().is_image(path)
    }

    /// Check if file is audio
    #[must_use]
    pub fn is_audio(&self, path: &str) -> bool {
        PrimitiveFiletypeBuilder::new().is_audio(path)
    }

    /// Check if file is video
    #[must_use]
    pub fn is_video(&self, path: &str) -> bool {
        PrimitiveFiletypeBuilder::new().is_video(path)
    }

    /// Check if file is any media type (image, audio, or video)
    #[must_use]
    pub fn is_media(&self, path: &str) -> bool {
        PrimitiveFiletypeBuilder::new().is_media(path)
    }

    // ========================================================================
    // Document Checks
    // ========================================================================

    /// Check if file is a document
    #[must_use]
    pub fn is_document(&self, path: &str) -> bool {
        PrimitiveFiletypeBuilder::new().is_document(path)
    }

    /// Check if file is a spreadsheet
    #[must_use]
    pub fn is_spreadsheet(&self, path: &str) -> bool {
        // Check common spreadsheet extensions
        let ext = self.find_extension(path);
        matches!(
            ext.as_deref(),
            Some("xls") | Some("xlsx") | Some("csv") | Some("ods")
        )
    }

    // ========================================================================
    // Code Checks
    // ========================================================================

    /// Check if file is source code
    #[must_use]
    pub fn is_code(&self, path: &str) -> bool {
        PrimitiveFiletypeBuilder::new().is_code(path)
    }

    /// Check if file is a script
    #[must_use]
    pub fn is_script(&self, path: &str) -> bool {
        let ext = self.find_extension(path);
        matches!(
            ext.as_deref(),
            Some("sh") | Some("bash") | Some("zsh") | Some("ps1") | Some("bat") | Some("cmd")
        )
    }

    /// Check if file is a configuration file
    #[must_use]
    pub fn is_config(&self, path: &str) -> bool {
        PrimitiveFiletypeBuilder::new().is_config(path)
    }

    // ========================================================================
    // Executable Checks
    // ========================================================================

    /// Check if file is an executable
    #[must_use]
    pub fn is_executable(&self, path: &str) -> bool {
        PrimitiveFiletypeBuilder::new().is_executable(path)
    }

    /// Check if file is a library
    #[must_use]
    pub fn is_library(&self, path: &str) -> bool {
        let ext = self.find_extension(path);
        matches!(
            ext.as_deref(),
            Some("so") | Some("dll") | Some("dylib") | Some("a") | Some("lib")
        )
    }

    // ========================================================================
    // Archive Checks
    // ========================================================================

    /// Check if file is an archive
    #[must_use]
    pub fn is_archive(&self, path: &str) -> bool {
        PrimitiveFiletypeBuilder::new().is_archive(path)
    }

    /// Check if file is a compressed file
    #[must_use]
    pub fn is_compressed(&self, path: &str) -> bool {
        let ext = self.find_extension(path);
        matches!(
            ext.as_deref(),
            Some("gz") | Some("bz2") | Some("xz") | Some("lz") | Some("zst")
        )
    }

    // ========================================================================
    // Security-Sensitive Checks
    // ========================================================================

    /// Check if file is security-sensitive (credentials, keys, etc.)
    #[must_use]
    pub fn is_security_sensitive(&self, path: &str) -> bool {
        let result = PrimitiveFiletypeBuilder::new().is_security_sensitive(path);
        if self.emit_events && result {
            observe::warn(
                "security_sensitive_file",
                "Security-sensitive file detected",
            );
            increment(metric_names::security_sensitive());
        }
        result
    }

    /// Check if file is a credential file
    #[must_use]
    pub fn is_credential(&self, path: &str) -> bool {
        let category = PrimitiveFiletypeBuilder::new().detect(path);
        matches!(
            category,
            crate::primitives::data::paths::FileCategory::Credential
        )
    }

    /// Check if file is a certificate
    #[must_use]
    pub fn is_certificate(&self, path: &str) -> bool {
        let ext = self.find_extension(path);
        matches!(
            ext.as_deref(),
            Some("crt") | Some("cer") | Some("pem") | Some("p12") | Some("pfx")
        )
    }

    /// Check if file is a private key
    #[must_use]
    pub fn is_private_key(&self, path: &str) -> bool {
        let ext = self.find_extension(path);
        let is_key = matches!(ext.as_deref(), Some("key") | Some("pem"));
        let has_key_name = path.contains("id_rsa")
            || path.contains("id_ed25519")
            || path.contains("id_ecdsa")
            || path.contains("private");
        is_key || has_key_name
    }

    // ========================================================================
    // Font Checks
    // ========================================================================

    /// Check if file is a font
    #[must_use]
    pub fn is_font(&self, path: &str) -> bool {
        let ext = self.find_extension(path);
        matches!(
            ext.as_deref(),
            Some("ttf") | Some("otf") | Some("woff") | Some("woff2") | Some("eot")
        )
    }

    // ========================================================================
    // Data Checks
    // ========================================================================

    /// Check if file is a data file (json, xml, csv, etc.)
    #[must_use]
    pub fn is_data(&self, path: &str) -> bool {
        PrimitiveFiletypeBuilder::new().is_data(path)
    }

    /// Check if file is a database file
    #[must_use]
    pub fn is_database(&self, path: &str) -> bool {
        let ext = self.find_extension(path);
        matches!(
            ext.as_deref(),
            Some("db") | Some("sqlite") | Some("sqlite3") | Some("mdb")
        )
    }

    /// Check if file is a log file
    #[must_use]
    pub fn is_log(&self, path: &str) -> bool {
        let ext = self.find_extension(path);
        ext.as_deref() == Some("log") || path.contains(".log.")
    }

    /// Check if file is a backup file
    #[must_use]
    pub fn is_backup(&self, path: &str) -> bool {
        let ext = self.find_extension(path);
        matches!(ext.as_deref(), Some("bak") | Some("backup") | Some("old"))
            || path.ends_with('~')
            || path.contains(".bak.")
    }

    /// Check if file is a temporary file
    #[must_use]
    pub fn is_temporary(&self, path: &str) -> bool {
        let ext = self.find_extension(path);
        matches!(ext.as_deref(), Some("tmp") | Some("temp") | Some("swp"))
            || path.starts_with("~")
            || path.contains(".tmp.")
    }

    // ========================================================================
    // Additional Checks
    // ========================================================================

    /// Check if file is hidden or temporary
    #[must_use]
    pub fn is_hidden_or_temp(&self, path: &str) -> bool {
        PrimitiveFiletypeBuilder::new().is_hidden_or_temp(path)
    }

    /// Check if file is text-based (can be opened in text editor)
    #[must_use]
    pub fn is_text_based(&self, path: &str) -> bool {
        PrimitiveFiletypeBuilder::new().is_text_based(path)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = FiletypeBuilder::new();
        assert!(builder.emit_events);

        let silent = FiletypeBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = FiletypeBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_category_detection() {
        let ft = FiletypeBuilder::silent();

        assert_eq!(ft.detect("photo.jpg"), FileCategory::Image);
        assert_eq!(ft.detect("main.rs"), FileCategory::SourceCode);
        assert_eq!(ft.detect("config.json"), FileCategory::Config);
        assert_eq!(ft.detect(".env"), FileCategory::Credential);
    }

    #[test]
    fn test_media_checks() {
        let ft = FiletypeBuilder::silent();

        assert!(ft.is_image("photo.jpg"));
        assert!(ft.is_image("image.PNG"));
        assert!(ft.is_audio("song.mp3"));
        assert!(ft.is_video("movie.mp4"));
        assert!(ft.is_media("photo.jpg"));
    }

    #[test]
    fn test_code_checks() {
        let ft = FiletypeBuilder::silent();

        assert!(ft.is_code("main.rs"));
        assert!(ft.is_code("script.py"));
        assert!(ft.is_config("config.json"));
        assert!(ft.is_config("settings.yaml"));
    }

    #[test]
    fn test_security_sensitive() {
        let ft = FiletypeBuilder::silent();

        assert!(ft.is_security_sensitive(".env"));
        assert!(ft.is_security_sensitive("server.key"));
        assert!(ft.is_security_sensitive("id_rsa"));
        assert!(!ft.is_security_sensitive("readme.txt"));
    }

    #[test]
    fn test_executable_checks() {
        let ft = FiletypeBuilder::silent();

        assert!(ft.is_executable("app.exe"));
        assert!(ft.is_library("lib.so"));
        assert!(ft.is_script("deploy.sh"));
    }

    #[test]
    fn test_archive_checks() {
        let ft = FiletypeBuilder::silent();

        assert!(ft.is_archive("backup.zip"));
        assert!(ft.is_archive("data.tar.gz"));
        assert!(ft.is_compressed("file.gz"));
    }
}

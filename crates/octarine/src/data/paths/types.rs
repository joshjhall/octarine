//! Public types for path operations
//!
//! These types form the public API for path detection, validation, and sanitization.
//! They mirror the internal primitives types but are stable public API.
//!
//! ## Design Philosophy
//!
//! - **Platform-aware**: Types support both Unix and Windows conventions
//! - **Security-focused**: Types capture security threats and validation results
//! - **User-friendly**: Clear documentation and helpful methods
//!
//! ## Security Standards
//!
//! Types support detection and validation per:
//! - **CWE-22**: Path Traversal
//! - **CWE-78**: OS Command Injection
//! - **CWE-158**: Null Byte Injection
//! - **CWE-175**: Improper Handling of Mixed Encoding
//! - **CWE-707**: Improper Neutralization

// Import SecurityThreat from its canonical location
use crate::security::paths::SecurityThreat;

// ============================================================================
// Platform Types
// ============================================================================

/// Platform/OS type for path operations
///
/// Determines which path conventions to use for operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Platform {
    /// Unix-style paths (forward slashes, case-sensitive)
    Unix,
    /// Windows-style paths (backslashes, case-insensitive, drive letters)
    Windows,
    /// Auto-detect platform from path format
    #[default]
    Auto,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unix => write!(f, "Unix"),
            Self::Windows => write!(f, "Windows"),
            Self::Auto => write!(f, "Auto"),
        }
    }
}

impl From<crate::primitives::data::paths::Platform> for Platform {
    fn from(p: crate::primitives::data::paths::Platform) -> Self {
        match p {
            crate::primitives::data::paths::Platform::Unix => Self::Unix,
            crate::primitives::data::paths::Platform::Windows => Self::Windows,
            crate::primitives::data::paths::Platform::Auto => Self::Auto,
        }
    }
}

impl From<Platform> for crate::primitives::data::paths::Platform {
    fn from(p: Platform) -> Self {
        match p {
            Platform::Unix => Self::Unix,
            Platform::Windows => Self::Windows,
            Platform::Auto => Self::Auto,
        }
    }
}

// ============================================================================
// Path Type Detection
// ============================================================================

/// Detected path type/format
///
/// Classifies paths based on their format and platform conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PathType {
    /// Unix absolute path: `/path/to/file`
    UnixAbsolute,
    /// Unix relative path: `path/to/file` or `./path`
    UnixRelative,
    /// Windows absolute with drive: `C:\path`
    WindowsAbsolute,
    /// Windows UNC path: `\\server\share`
    WindowsUnc,
    /// Windows relative: `path\to\file`
    WindowsRelative,
    /// Unknown or ambiguous format
    #[default]
    Unknown,
}

impl PathType {
    /// Check if this path type is absolute
    #[must_use]
    pub const fn is_absolute(&self) -> bool {
        matches!(
            self,
            Self::UnixAbsolute | Self::WindowsAbsolute | Self::WindowsUnc
        )
    }

    /// Check if this path type is relative
    #[must_use]
    pub const fn is_relative(&self) -> bool {
        matches!(self, Self::UnixRelative | Self::WindowsRelative)
    }

    /// Check if this path type is Unix-style
    #[must_use]
    pub const fn is_unix(&self) -> bool {
        matches!(self, Self::UnixAbsolute | Self::UnixRelative)
    }

    /// Check if this path type is Windows-style
    #[must_use]
    pub const fn is_windows(&self) -> bool {
        matches!(
            self,
            Self::WindowsAbsolute | Self::WindowsUnc | Self::WindowsRelative
        )
    }

    /// Get the platform for this path type
    #[must_use]
    pub const fn platform(&self) -> Platform {
        match self {
            Self::UnixAbsolute | Self::UnixRelative => Platform::Unix,
            Self::WindowsAbsolute | Self::WindowsUnc | Self::WindowsRelative => Platform::Windows,
            Self::Unknown => Platform::Auto,
        }
    }
}

impl std::fmt::Display for PathType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnixAbsolute => write!(f, "Unix Absolute"),
            Self::UnixRelative => write!(f, "Unix Relative"),
            Self::WindowsAbsolute => write!(f, "Windows Absolute"),
            Self::WindowsUnc => write!(f, "Windows UNC"),
            Self::WindowsRelative => write!(f, "Windows Relative"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl From<crate::primitives::data::paths::PathType> for PathType {
    fn from(p: crate::primitives::data::paths::PathType) -> Self {
        match p {
            crate::primitives::data::paths::PathType::UnixAbsolute => Self::UnixAbsolute,
            crate::primitives::data::paths::PathType::UnixRelative => Self::UnixRelative,
            crate::primitives::data::paths::PathType::WindowsAbsolute => Self::WindowsAbsolute,
            crate::primitives::data::paths::PathType::WindowsUnc => Self::WindowsUnc,
            crate::primitives::data::paths::PathType::WindowsRelative => Self::WindowsRelative,
            crate::primitives::data::paths::PathType::Unknown => Self::Unknown,
        }
    }
}

// ============================================================================
// File Category Types
// ============================================================================

/// File type category based on extension/pattern
///
/// Used for identifying file types for security decisions
/// (e.g., blocking executables, handling config files specially).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FileCategory {
    // Documents
    /// Plain text files (.txt, .md, .rst)
    Text,
    /// Document files (.doc, .docx, .pdf, .odt)
    Document,
    /// Spreadsheet files (.xls, .xlsx, .csv, .ods)
    Spreadsheet,
    /// Presentation files (.ppt, .pptx, .odp)
    Presentation,

    // Code
    /// Source code files (.rs, .py, .js, .go, .c, .cpp)
    SourceCode,
    /// Script files (.sh, .bash, .ps1, .bat)
    Script,
    /// Configuration files (.toml, .yaml, .json, .ini)
    Config,
    /// Data files (.json, .xml, .csv structured data)
    Data,

    // Media
    /// Image files (.png, .jpg, .gif, .svg, .webp)
    Image,
    /// Audio files (.mp3, .wav, .ogg, .flac)
    Audio,
    /// Video files (.mp4, .mkv, .avi, .webm)
    Video,

    // Archives
    /// Archive files (.tar, .zip, .rar, .7z)
    Archive,
    /// Compressed files (.gz, .bz2, .xz)
    Compressed,

    // Executables
    /// Executable files (.exe, .dll, .so, binary)
    Executable,
    /// Library files (.a, .lib, .dylib)
    Library,

    // System
    /// System files (device nodes, special files)
    System,
    /// Hidden files (dotfiles on Unix)
    Hidden,
    /// Temporary files (.tmp, .temp, .bak)
    Temporary,

    // Security-sensitive
    /// Credential files (.htpasswd, shadow, passwd)
    Credential,
    /// Certificate files (.pem, .crt, .cer)
    Certificate,
    /// Key files (.key, .pem private keys, .ppk)
    Key,

    // Unknown
    /// Unknown or unrecognized file type
    #[default]
    Unknown,
}

impl FileCategory {
    /// Check if this category represents security-sensitive files
    #[must_use]
    pub const fn is_sensitive(&self) -> bool {
        matches!(self, Self::Credential | Self::Certificate | Self::Key)
    }

    /// Check if this category represents executable code
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        matches!(self, Self::Executable | Self::Script | Self::Library)
    }

    /// Check if this category represents human-readable text
    #[must_use]
    pub const fn is_text_based(&self) -> bool {
        matches!(
            self,
            Self::Text | Self::SourceCode | Self::Script | Self::Config | Self::Data
        )
    }

    /// Check if this category represents media files
    #[must_use]
    pub const fn is_media(&self) -> bool {
        matches!(self, Self::Image | Self::Audio | Self::Video)
    }
}

impl std::fmt::Display for FileCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "Text"),
            Self::Document => write!(f, "Document"),
            Self::Spreadsheet => write!(f, "Spreadsheet"),
            Self::Presentation => write!(f, "Presentation"),
            Self::SourceCode => write!(f, "Source Code"),
            Self::Script => write!(f, "Script"),
            Self::Config => write!(f, "Config"),
            Self::Data => write!(f, "Data"),
            Self::Image => write!(f, "Image"),
            Self::Audio => write!(f, "Audio"),
            Self::Video => write!(f, "Video"),
            Self::Archive => write!(f, "Archive"),
            Self::Compressed => write!(f, "Compressed"),
            Self::Executable => write!(f, "Executable"),
            Self::Library => write!(f, "Library"),
            Self::System => write!(f, "System"),
            Self::Hidden => write!(f, "Hidden"),
            Self::Temporary => write!(f, "Temporary"),
            Self::Credential => write!(f, "Credential"),
            Self::Certificate => write!(f, "Certificate"),
            Self::Key => write!(f, "Key"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl From<crate::primitives::data::paths::FileCategory> for FileCategory {
    fn from(c: crate::primitives::data::paths::FileCategory) -> Self {
        use crate::primitives::data::paths::FileCategory as P;
        match c {
            P::Text => Self::Text,
            P::Document => Self::Document,
            P::Spreadsheet => Self::Spreadsheet,
            P::Presentation => Self::Presentation,
            P::SourceCode => Self::SourceCode,
            P::Script => Self::Script,
            P::Config => Self::Config,
            P::Data => Self::Data,
            P::Image => Self::Image,
            P::Audio => Self::Audio,
            P::Video => Self::Video,
            P::Archive => Self::Archive,
            P::Compressed => Self::Compressed,
            P::Executable => Self::Executable,
            P::Library => Self::Library,
            P::System => Self::System,
            P::Hidden => Self::Hidden,
            P::Temporary => Self::Temporary,
            P::Credential => Self::Credential,
            P::Certificate => Self::Certificate,
            P::Key => Self::Key,
            P::Unknown => Self::Unknown,
        }
    }
}

// ============================================================================
// Security Threat Types
// ============================================================================

// SecurityThreat is now in security::paths::types (canonical location)
// Imported at top of file and re-exported via data::paths::mod.rs

// ============================================================================
// Result Types
// ============================================================================

/// Result of comprehensive path detection
///
/// Contains all detected characteristics of a path.
#[derive(Debug, Clone, Default)]
pub struct PathDetectionResult {
    /// Detected path type
    pub path_type: PathType,
    /// Detected platform
    pub platform: Platform,
    /// File category (if detectable from extension)
    pub file_category: Option<FileCategory>,
    /// Is absolute path
    pub is_absolute: bool,
    /// Is hidden file/directory
    pub is_hidden: bool,
    /// Has file extension
    pub has_extension: bool,
    /// File extension if present
    pub extension: Option<String>,
    /// Security threats detected
    pub threats: Vec<SecurityThreat>,
}

impl PathDetectionResult {
    /// Check if the path is safe (no threats detected)
    #[must_use]
    pub fn is_safe(&self) -> bool {
        self.threats.is_empty()
    }

    /// Check if the path has any threats
    #[must_use]
    pub fn is_threat_detected(&self) -> bool {
        !self.threats.is_empty()
    }

    /// Get the highest severity threat (if any)
    #[must_use]
    pub fn max_severity(&self) -> Option<u8> {
        self.threats.iter().map(SecurityThreat::severity).max()
    }

    /// Get the number of threats detected
    #[must_use]
    pub fn threat_count(&self) -> usize {
        self.threats.len()
    }
}

impl From<crate::primitives::data::paths::PathDetectionResult> for PathDetectionResult {
    fn from(r: crate::primitives::data::paths::PathDetectionResult) -> Self {
        Self {
            path_type: r.path_type.into(),
            platform: r.platform.into(),
            file_category: r.file_category.map(Into::into),
            is_absolute: r.is_absolute,
            is_hidden: r.is_hidden,
            has_extension: r.has_extension,
            extension: r.extension,
            threats: r.threats.into_iter().map(Into::into).collect(),
        }
    }
}

/// Validation result with detailed feedback
///
/// Provides information about why validation passed or failed.
#[derive(Debug, Clone, Default)]
pub struct PathValidationResult {
    /// Is the path valid
    pub is_valid: bool,
    /// Validation errors (empty if valid)
    pub errors: Vec<String>,
    /// Warnings (path is valid but has concerns)
    pub warnings: Vec<String>,
}

impl PathValidationResult {
    /// Create a valid result
    pub fn valid() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Create an invalid result with error
    pub fn invalid(error: impl Into<String>) -> Self {
        Self {
            is_valid: false,
            errors: vec![error.into()],
            warnings: Vec::new(),
        }
    }

    /// Check if there are any warnings
    #[must_use]
    pub fn is_warning_present(&self) -> bool {
        !self.warnings.is_empty()
    }
}

impl From<crate::primitives::data::paths::PathValidationResult> for PathValidationResult {
    fn from(r: crate::primitives::data::paths::PathValidationResult) -> Self {
        Self {
            is_valid: r.is_valid,
            errors: r.errors,
            warnings: r.warnings,
        }
    }
}

// ============================================================================
// Strategy Types
// ============================================================================

// PathSanitizationStrategy is now in security::paths::types (canonical location)
// Re-exported from there via data::paths::mod.rs

/// Boundary enforcement strategy
///
/// Determines how paths that escape a boundary are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BoundaryStrategy {
    /// Reject paths that escape boundary (default)
    #[default]
    Reject,
    /// Constrain to boundary (remove traversal)
    Constrain,
    /// Resolve and verify (canonicalize then check)
    Resolve,
}

impl From<BoundaryStrategy> for crate::primitives::data::paths::BoundaryStrategy {
    fn from(s: BoundaryStrategy) -> Self {
        match s {
            BoundaryStrategy::Reject => Self::Reject,
            BoundaryStrategy::Constrain => Self::Constrain,
            BoundaryStrategy::Resolve => Self::Resolve,
        }
    }
}

/// Filename sanitization strategy
///
/// Determines how dangerous characters in filenames are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilenameSanitizationStrategy {
    /// Replace dangerous chars with underscore (default)
    #[default]
    ReplaceWithUnderscore,
    /// Replace dangerous chars with dash
    ReplaceWithDash,
    /// Remove dangerous chars entirely
    Remove,
    /// Reject if dangerous chars present (strict)
    Reject,
}

impl FilenameSanitizationStrategy {
    /// Get the replacement character (if applicable)
    #[must_use]
    pub const fn replacement(&self) -> Option<char> {
        match self {
            Self::ReplaceWithUnderscore => Some('_'),
            Self::ReplaceWithDash => Some('-'),
            Self::Remove | Self::Reject => None,
        }
    }
}

// ============================================================================
// Format Types
// ============================================================================

/// Path format/style detected from path structure
///
/// Identifies the format convention used in a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PathFormat {
    /// Unix-style paths with forward slashes
    Unix,
    /// Windows-style paths with backslashes and optional drive letter
    Windows,
    /// PowerShell-style (Windows with forward slashes)
    PowerShell,
    /// WSL mount paths (/mnt/c/...)
    Wsl,
    /// Portable relative paths (no platform-specific elements)
    #[default]
    Portable,
}

impl PathFormat {
    /// Check if this format is Unix-like
    #[must_use]
    pub const fn is_unix_like(&self) -> bool {
        matches!(self, Self::Unix | Self::Wsl | Self::Portable)
    }

    /// Check if this format is Windows-like
    #[must_use]
    pub const fn is_windows_like(&self) -> bool {
        matches!(self, Self::Windows | Self::PowerShell)
    }
}

impl std::fmt::Display for PathFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unix => write!(f, "Unix"),
            Self::Windows => write!(f, "Windows"),
            Self::PowerShell => write!(f, "PowerShell"),
            Self::Wsl => write!(f, "WSL"),
            Self::Portable => write!(f, "Portable"),
        }
    }
}

impl From<crate::primitives::data::paths::PathFormat> for PathFormat {
    fn from(p: crate::primitives::data::paths::PathFormat) -> Self {
        use crate::primitives::data::paths::PathFormat as P;
        match p {
            P::Unix => Self::Unix,
            P::Windows => Self::Windows,
            P::PowerShell => Self::PowerShell,
            P::Wsl => Self::Wsl,
            P::Portable => Self::Portable,
        }
    }
}

impl From<PathFormat> for crate::primitives::data::paths::PathFormat {
    fn from(p: PathFormat) -> Self {
        match p {
            PathFormat::Unix => Self::Unix,
            PathFormat::Windows => Self::Windows,
            PathFormat::PowerShell => Self::PowerShell,
            PathFormat::Wsl => Self::Wsl,
            PathFormat::Portable => Self::Portable,
        }
    }
}

/// Separator style detected in path
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SeparatorStyle {
    /// Forward slashes only (/)
    Forward,
    /// Backslashes only (\)
    Back,
    /// Both forward and back slashes
    Mixed,
    /// No separators present
    #[default]
    None,
}

impl SeparatorStyle {
    /// Check if this style has any separators
    #[must_use]
    pub const fn has_separators(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Check if this style is consistent (not mixed)
    #[must_use]
    pub const fn is_consistent(&self) -> bool {
        !matches!(self, Self::Mixed)
    }
}

impl std::fmt::Display for SeparatorStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forward => write!(f, "Forward"),
            Self::Back => write!(f, "Back"),
            Self::Mixed => write!(f, "Mixed"),
            Self::None => write!(f, "None"),
        }
    }
}

impl From<crate::primitives::data::paths::SeparatorStyle> for SeparatorStyle {
    fn from(s: crate::primitives::data::paths::SeparatorStyle) -> Self {
        use crate::primitives::data::paths::SeparatorStyle as P;
        match s {
            P::Forward => Self::Forward,
            P::Back => Self::Back,
            P::Mixed => Self::Mixed,
            P::None => Self::None,
        }
    }
}

// ============================================================================
// Filename Sanitization Context
// ============================================================================

/// Context for filename sanitization operations
///
/// Different contexts have different security requirements for filenames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SanitizationContext {
    /// User-generated filenames (medium security)
    /// - Allows Unicode
    /// - Removes dangerous characters
    /// - Preserves dots and extensions
    #[default]
    UserFile,
    /// System/application filenames (high security)
    /// - ASCII only
    /// - Removes all special characters
    /// - Preserves extensions
    SystemFile,
    /// Security-sensitive filenames (maximum security)
    /// - ASCII alphanumeric and limited punctuation only
    /// - Most restrictive
    SecureFile,
    /// Configuration filenames (high security)
    /// - No shell metacharacters
    /// - Allows dots and underscores
    ConfigFile,
    /// Untrusted file uploads (maximum security)
    /// - Most restrictive
    /// - No dangerous extensions
    /// - No double extensions
    UploadFile,
}

impl std::fmt::Display for SanitizationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserFile => write!(f, "User File"),
            Self::SystemFile => write!(f, "System File"),
            Self::SecureFile => write!(f, "Secure File"),
            Self::ConfigFile => write!(f, "Config File"),
            Self::UploadFile => write!(f, "Upload File"),
        }
    }
}

impl From<SanitizationContext> for crate::primitives::data::paths::SanitizationContext {
    fn from(c: SanitizationContext) -> Self {
        match c {
            SanitizationContext::UserFile => Self::UserFile,
            SanitizationContext::SystemFile => Self::SystemFile,
            SanitizationContext::SecureFile => Self::SecureFile,
            SanitizationContext::ConfigFile => Self::ConfigFile,
            SanitizationContext::UploadFile => Self::UploadFile,
        }
    }
}

impl From<crate::primitives::data::paths::SanitizationContext> for SanitizationContext {
    fn from(c: crate::primitives::data::paths::SanitizationContext) -> Self {
        use crate::primitives::data::paths::SanitizationContext as P;
        match c {
            P::UserFile => Self::UserFile,
            P::SystemFile => Self::SystemFile,
            P::SecureFile => Self::SecureFile,
            P::ConfigFile => Self::ConfigFile,
            P::UploadFile => Self::UploadFile,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_platform() {
        assert_eq!(Platform::default(), Platform::Auto);
        assert_eq!(Platform::Unix.to_string(), "Unix");
    }

    #[test]
    fn test_path_type() {
        assert!(PathType::UnixAbsolute.is_absolute());
        assert!(PathType::UnixRelative.is_relative());
        assert!(PathType::UnixAbsolute.is_unix());
        assert!(PathType::WindowsAbsolute.is_windows());
        assert_eq!(PathType::UnixAbsolute.platform(), Platform::Unix);
    }

    #[test]
    fn test_file_category() {
        assert!(FileCategory::Credential.is_sensitive());
        assert!(FileCategory::Executable.is_executable());
        assert!(FileCategory::SourceCode.is_text_based());
        assert!(FileCategory::Image.is_media());
    }

    #[test]
    fn test_security_threat() {
        assert_eq!(SecurityThreat::Traversal.cwe(), "CWE-22");
        assert_eq!(SecurityThreat::CommandInjection.severity(), 5);
        assert!(!SecurityThreat::Traversal.description().is_empty());
    }

    #[test]
    fn test_detection_result() {
        let result = PathDetectionResult::default();
        assert!(result.is_safe());
        assert!(!result.is_threat_detected());
        assert_eq!(result.threat_count(), 0);
    }

    #[test]
    fn test_validation_result() {
        let valid = PathValidationResult::valid();
        assert!(valid.is_valid);

        let invalid = PathValidationResult::invalid("test error");
        assert!(!invalid.is_valid);
        assert_eq!(invalid.errors.len(), 1);
    }
}

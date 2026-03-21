//! Type definitions for path operations
//!
//! Pure type definitions with no dependencies on other rust-core modules.
//!
//! ## Design Philosophy
//!
//! - **Platform-aware**: Types support both Unix and Windows conventions
//! - **Security-focused**: Types capture security threats and validation results
//! - **Zero-copy friendly**: Types designed for efficient string operations
//!
//! ## Security Standards
//!
//! Types support detection and validation per:
//! - **CWE-22**: Path Traversal
//! - **CWE-78**: OS Command Injection
//! - **CWE-158**: Null Byte Injection
//! - **CWE-175**: Improper Handling of Mixed Encoding
//! - **CWE-707**: Improper Neutralization

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

// ============================================================================
// Security Threat Types
// ============================================================================

/// Security threat type detected in path
///
/// These threats correspond to common path-based attacks
/// documented in CWE and OWASP guidelines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityThreat {
    /// Directory traversal attempt (`..`)
    /// CWE-22: Improper Limitation of a Pathname to a Restricted Directory
    Traversal,
    /// Encoded traversal (`%2e%2e`, `..%2f`)
    /// CWE-22 variant with encoding bypass
    EncodedTraversal,
    /// Command injection (`$()`, backticks)
    /// CWE-78: Improper Neutralization of Special Elements used in an OS Command
    CommandInjection,
    /// Variable expansion (`${VAR}`, `$HOME`)
    /// CWE-78 variant through environment variable injection
    VariableExpansion,
    /// Shell metacharacters (`;`, `|`, `&`)
    /// CWE-78 variant through shell metacharacters
    ShellMetacharacters,
    /// Null byte injection (`\0`)
    /// CWE-158: Improper Neutralization of Null Byte or NUL Character
    NullByte,
    /// Control characters (newline, carriage return, etc.)
    /// CWE-707: Improper Neutralization
    ControlCharacters,
    /// Double/multiple encoding (`%252e%252e`)
    /// CWE-175: Improper Handling of Mixed Encoding
    DoubleEncoding,
    /// Absolute path when relative expected
    /// Boundary violation attempt
    AbsolutePath,
}

impl SecurityThreat {
    /// Get the CWE identifier for this threat
    #[must_use]
    pub const fn cwe(&self) -> &'static str {
        match self {
            Self::Traversal | Self::EncodedTraversal | Self::AbsolutePath => "CWE-22",
            Self::CommandInjection | Self::VariableExpansion | Self::ShellMetacharacters => {
                "CWE-78"
            }
            Self::NullByte => "CWE-158",
            Self::ControlCharacters => "CWE-707",
            Self::DoubleEncoding => "CWE-175",
        }
    }

    /// Get the severity level (higher = more severe)
    #[must_use]
    pub const fn severity(&self) -> u8 {
        match self {
            Self::CommandInjection => 5,    // Critical - RCE possible
            Self::NullByte => 5,            // Critical - can bypass checks
            Self::Traversal => 4,           // High - data access
            Self::EncodedTraversal => 4,    // High - bypass attempt
            Self::DoubleEncoding => 4,      // High - bypass attempt
            Self::VariableExpansion => 3,   // Medium - information disclosure
            Self::ShellMetacharacters => 3, // Medium - command chaining
            Self::ControlCharacters => 2,   // Low - log injection
            Self::AbsolutePath => 2,        // Low - boundary violation
        }
    }

    /// Get a human-readable description
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Traversal => "Directory traversal attempt using '..'",
            Self::EncodedTraversal => "Encoded directory traversal bypass attempt",
            Self::CommandInjection => "Command injection through substitution",
            Self::VariableExpansion => "Environment variable expansion attempt",
            Self::ShellMetacharacters => "Shell metacharacter injection",
            Self::NullByte => "Null byte injection for truncation attack",
            Self::ControlCharacters => "Control character injection",
            Self::DoubleEncoding => "Double/multiple encoding bypass attempt",
            Self::AbsolutePath => "Absolute path escaping boundary",
        }
    }
}

impl std::fmt::Display for SecurityThreat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.description(), self.cwe())
    }
}

// ============================================================================
// Match and Result Types
// ============================================================================

/// Match result for path scanning operations
///
/// Represents a path found within text, with position and analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMatch {
    /// Start position in source text
    pub start: usize,
    /// End position in source text
    pub end: usize,
    /// The matched path string
    pub value: String,
    /// Detected path type
    pub path_type: PathType,
    /// Detected file category (if applicable)
    pub file_category: Option<FileCategory>,
    /// Security threats detected
    pub threats: Vec<SecurityThreat>,
}

impl PathMatch {
    /// Create a new path match
    pub fn new(start: usize, end: usize, value: String, path_type: PathType) -> Self {
        Self {
            start,
            end,
            value,
            path_type,
            file_category: None,
            threats: Vec::new(),
        }
    }

    /// Create a path match with full analysis
    pub fn with_analysis(
        start: usize,
        end: usize,
        value: String,
        path_type: PathType,
        file_category: Option<FileCategory>,
        threats: Vec<SecurityThreat>,
    ) -> Self {
        Self {
            start,
            end,
            value,
            path_type,
            file_category,
            threats,
        }
    }

    /// Get the length of the matched path
    #[must_use]
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Check if the match is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if the path has any security threats
    #[must_use]
    pub fn is_threat_detected(&self) -> bool {
        !self.threats.is_empty()
    }

    /// Get the highest severity threat (if any)
    #[must_use]
    pub fn max_severity(&self) -> Option<u8> {
        self.threats.iter().map(SecurityThreat::severity).max()
    }
}

/// Result of comprehensive path detection
///
/// Contains all detected characteristics of a path.
#[derive(Debug, Clone, Default)]
pub struct PathDetectionResult {
    /// Detected path type
    pub path_type: PathType,
    /// Detected platform
    pub platform: Platform,
    /// File category
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
    /// Create a new detection result
    pub fn new(path_type: PathType) -> Self {
        Self {
            path_type,
            platform: path_type.platform(),
            is_absolute: path_type.is_absolute(),
            ..Default::default()
        }
    }

    /// Check if the path is safe (no threats)
    #[must_use]
    pub fn is_safe(&self) -> bool {
        self.threats.is_empty()
    }

    /// Get the highest severity threat (if any)
    #[must_use]
    pub fn max_severity(&self) -> Option<u8> {
        self.threats.iter().map(SecurityThreat::severity).max()
    }
}

/// Validation result with details
///
/// Provides detailed feedback on path validation.
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

    /// Add an error to the result
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.is_valid = false;
        self.errors.push(error.into());
        self
    }

    /// Add a warning to the result
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    /// Check if there are any warnings
    #[must_use]
    pub fn is_warning_present(&self) -> bool {
        !self.warnings.is_empty()
    }
}

// ============================================================================
// Strategy Types
// ============================================================================

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

/// Path sanitization strategy
///
/// Determines how dangerous patterns in paths are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PathSanitizationStrategy {
    /// Remove dangerous patterns, keep safe parts (default)
    #[default]
    Clean,
    /// Reject if any dangerous patterns present (strict)
    Strict,
    /// Escape dangerous patterns (for display only)
    Escape,
}

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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_platform_default() {
        assert_eq!(Platform::default(), Platform::Auto);
    }

    #[test]
    fn test_platform_display() {
        assert_eq!(Platform::Unix.to_string(), "Unix");
        assert_eq!(Platform::Windows.to_string(), "Windows");
        assert_eq!(Platform::Auto.to_string(), "Auto");
    }

    #[test]
    fn test_path_type_absolute() {
        assert!(PathType::UnixAbsolute.is_absolute());
        assert!(PathType::WindowsAbsolute.is_absolute());
        assert!(PathType::WindowsUnc.is_absolute());
        assert!(!PathType::UnixRelative.is_absolute());
        assert!(!PathType::WindowsRelative.is_absolute());
        assert!(!PathType::Unknown.is_absolute());
    }

    #[test]
    fn test_path_type_platform() {
        assert_eq!(PathType::UnixAbsolute.platform(), Platform::Unix);
        assert_eq!(PathType::UnixRelative.platform(), Platform::Unix);
        assert_eq!(PathType::WindowsAbsolute.platform(), Platform::Windows);
        assert_eq!(PathType::WindowsUnc.platform(), Platform::Windows);
        assert_eq!(PathType::WindowsRelative.platform(), Platform::Windows);
        assert_eq!(PathType::Unknown.platform(), Platform::Auto);
    }

    #[test]
    fn test_file_category_sensitive() {
        assert!(FileCategory::Credential.is_sensitive());
        assert!(FileCategory::Certificate.is_sensitive());
        assert!(FileCategory::Key.is_sensitive());
        assert!(!FileCategory::Text.is_sensitive());
        assert!(!FileCategory::Image.is_sensitive());
    }

    #[test]
    fn test_file_category_executable() {
        assert!(FileCategory::Executable.is_executable());
        assert!(FileCategory::Script.is_executable());
        assert!(FileCategory::Library.is_executable());
        assert!(!FileCategory::Text.is_executable());
        assert!(!FileCategory::Document.is_executable());
    }

    #[test]
    fn test_security_threat_cwe() {
        assert_eq!(SecurityThreat::Traversal.cwe(), "CWE-22");
        assert_eq!(SecurityThreat::CommandInjection.cwe(), "CWE-78");
        assert_eq!(SecurityThreat::NullByte.cwe(), "CWE-158");
        assert_eq!(SecurityThreat::DoubleEncoding.cwe(), "CWE-175");
    }

    #[test]
    fn test_security_threat_severity() {
        assert_eq!(SecurityThreat::CommandInjection.severity(), 5);
        assert_eq!(SecurityThreat::NullByte.severity(), 5);
        assert_eq!(SecurityThreat::Traversal.severity(), 4);
        assert_eq!(SecurityThreat::AbsolutePath.severity(), 2);
    }

    #[test]
    fn test_path_match_creation() {
        let m = PathMatch::new(0, 10, "/etc/passwd".to_string(), PathType::UnixAbsolute);
        assert_eq!(m.start, 0);
        assert_eq!(m.end, 10);
        assert_eq!(m.path_type, PathType::UnixAbsolute);
        assert!(!m.is_threat_detected());
    }

    #[test]
    fn test_path_match_with_threats() {
        let m = PathMatch::with_analysis(
            0,
            15,
            "../../../etc".to_string(),
            PathType::UnixRelative,
            None,
            vec![SecurityThreat::Traversal],
        );
        assert!(m.is_threat_detected());
        assert_eq!(m.max_severity(), Some(4));
    }

    #[test]
    fn test_path_detection_result() {
        let r = PathDetectionResult::new(PathType::UnixAbsolute);
        assert!(r.is_safe());
        assert!(r.is_absolute);
        assert_eq!(r.platform, Platform::Unix);
    }

    #[test]
    fn test_validation_result() {
        let valid = PathValidationResult::valid();
        assert!(valid.is_valid);
        assert!(valid.errors.is_empty());

        let invalid = PathValidationResult::invalid("Path traversal detected");
        assert!(!invalid.is_valid);
        assert_eq!(invalid.errors.len(), 1);
    }

    #[test]
    fn test_filename_strategy_replacement() {
        assert_eq!(
            FilenameSanitizationStrategy::ReplaceWithUnderscore.replacement(),
            Some('_')
        );
        assert_eq!(
            FilenameSanitizationStrategy::ReplaceWithDash.replacement(),
            Some('-')
        );
        assert_eq!(FilenameSanitizationStrategy::Remove.replacement(), None);
        assert_eq!(FilenameSanitizationStrategy::Reject.replacement(), None);
    }
}

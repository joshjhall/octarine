//! Security facade for unified threat detection access
//!
//! The `Security` facade provides a single entry point to all security-related
//! operations in octarine. It answers the question: "Is this dangerous?"
//!
//! # Example
//!
//! ```
//! use octarine::security::Security;
//!
//! let security = Security::new();
//!
//! // Path security (traversal, injection)
//! let path_security = security.paths();
//!
//! // Network security (SSRF)
//! let network_security = security.network();
//!
//! // Command security (injection)
//! let command_security = security.commands();
//! ```

use super::commands::CommandSecurityBuilder;
use super::network::NetworkSecurityBuilder;
use super::paths::SecurityBuilder;

#[cfg(feature = "database")]
use super::queries::QueryBuilder;

#[cfg(feature = "formats")]
use super::formats::FormatSecurityBuilder;

/// Unified facade for all security operations (THREATS concern)
///
/// The Security facade provides access to domain-specific security builders
/// that handle threat detection, validation, and sanitization.
///
/// All operations automatically emit observe events for audit trails.
///
/// # Domains
///
/// | Domain | Builder | Purpose |
/// |--------|---------|---------|
/// | `paths` | [`SecurityBuilder`] | Path traversal, command injection |
/// | `network` | [`NetworkSecurityBuilder`] | SSRF, scheme validation |
/// | `commands` | [`CommandSecurityBuilder`] | OS command injection |
/// | `queries` | [`QueryBuilder`] | SQL/NoSQL/GraphQL injection |
/// | `formats` | [`FormatSecurityBuilder`] | XXE, JSON bombs, YAML attacks |
///
/// # Example
///
/// ```
/// use octarine::security::Security;
///
/// let security = Security::new();
///
/// // Check for path traversal threats
/// if security.paths().is_traversal_present("../etc/passwd") {
///     // Block dangerous path
/// }
///
/// // Check for SSRF threats
/// if security.network().is_internal_host("192.168.1.1") {
///     // Block internal access
/// }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Security;

impl Security {
    /// Create a new Security facade
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Access path security operations
    ///
    /// Provides detection, validation, and sanitization for:
    /// - Path traversal attacks (`../`, encoded variants)
    /// - Command injection in paths
    /// - Null byte injection
    /// - Control character injection
    ///
    /// # Example
    ///
    /// ```
    /// use octarine::security::Security;
    ///
    /// let security = Security::new();
    ///
    /// // Detection
    /// if security.paths().is_traversal_present("../etc/passwd") {
    ///     // Handle threat
    /// }
    ///
    /// // Validation
    /// security.paths().validate_path("safe/path").unwrap();
    ///
    /// // Sanitization
    /// let clean = security.paths().sanitize("../unsafe/../path").unwrap();
    /// ```
    #[must_use]
    pub fn paths(&self) -> SecurityBuilder {
        SecurityBuilder::new()
    }

    /// Access network security operations
    ///
    /// Provides detection and validation for:
    /// - SSRF (Server-Side Request Forgery)
    /// - Internal host access
    /// - Dangerous URL schemes
    /// - Cloud metadata endpoints
    /// - URL shorteners
    ///
    /// # Example
    ///
    /// ```
    /// use octarine::security::Security;
    ///
    /// let security = Security::new();
    ///
    /// // Check for SSRF targets
    /// if security.network().is_potential_ssrf("http://169.254.169.254/metadata") {
    ///     // Block cloud metadata access
    /// }
    ///
    /// // Validate URL is safe for server-side requests
    /// security.network().validate_ssrf_safe("https://api.example.com").unwrap();
    /// ```
    #[must_use]
    pub fn network(&self) -> NetworkSecurityBuilder {
        NetworkSecurityBuilder::new()
    }

    /// Access command security operations
    ///
    /// Provides detection, validation, and escaping for:
    /// - Command chaining (`;`, `&&`, `||`)
    /// - Pipe injection (`|`)
    /// - Command substitution (`$()`, backticks)
    /// - Variable expansion (`$VAR`, `${VAR}`)
    /// - Glob patterns (`*`, `?`)
    ///
    /// # Example
    ///
    /// ```
    /// use octarine::security::Security;
    ///
    /// let security = Security::new();
    ///
    /// // Check for dangerous command arguments
    /// if security.commands().is_dangerous("file.txt; rm -rf /") {
    ///     // Block dangerous input
    /// }
    ///
    /// // Escape argument for shell
    /// let safe_arg = security.commands().escape_shell_arg("user input");
    /// ```
    #[must_use]
    pub fn commands(&self) -> CommandSecurityBuilder {
        CommandSecurityBuilder::new()
    }

    /// Access query security operations (requires `database` feature)
    ///
    /// Provides detection, validation, and escaping for:
    /// - SQL injection
    /// - NoSQL injection (MongoDB operators)
    /// - LDAP injection
    /// - GraphQL injection
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::security::Security;
    ///
    /// let security = Security::new();
    ///
    /// // Check for SQL injection
    /// if security.queries().is_sql_injection_present("1' OR '1'='1") {
    ///     // Block dangerous query
    /// }
    ///
    /// // Validate query parameter
    /// security.queries().validate_sql_parameter("safe_value").unwrap();
    /// ```
    #[cfg(feature = "database")]
    #[must_use]
    pub fn queries(&self) -> QueryBuilder {
        QueryBuilder::new()
    }

    /// Access format security operations (requires `formats` feature)
    ///
    /// Provides detection and validation for:
    /// - XML External Entity (XXE) attacks
    /// - JSON depth/size limits (billion laughs)
    /// - YAML anchor bombs
    /// - Unsafe YAML tags
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::security::Security;
    ///
    /// let security = Security::new();
    ///
    /// // Check for XXE threats
    /// if security.formats().is_xxe_present(xml_content) {
    ///     // Block dangerous XML
    /// }
    ///
    /// // Validate JSON is safe
    /// security.formats().validate_json(json_content).unwrap();
    /// ```
    #[cfg(feature = "formats")]
    #[must_use]
    pub fn formats(&self) -> FormatSecurityBuilder {
        FormatSecurityBuilder::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_facade_creation() {
        let security = Security::new();
        // Verify we can access each builder
        let _ = security.paths();
        let _ = security.network();
        let _ = security.commands();
    }

    #[test]
    fn test_security_is_copy() {
        let security = Security::new();
        let copy = security;
        let _ = security.paths();
        let _ = copy.paths();
    }

    #[test]
    fn test_security_is_default() {
        let security = Security;
        let _ = security.paths();
    }

    #[test]
    fn test_paths_detection() {
        let security = Security::new();
        assert!(security.paths().is_traversal_present("../etc/passwd"));
        assert!(!security.paths().is_traversal_present("safe/path"));
    }

    #[test]
    fn test_network_detection() {
        let security = Security::new();
        assert!(security.network().is_internal_host("127.0.0.1"));
        assert!(security.network().is_internal_host("localhost"));
    }

    #[test]
    fn test_commands_detection() {
        let security = Security::new();
        assert!(security.commands().is_dangerous("file.txt; rm -rf /"));
        assert!(!security.commands().is_dangerous("safe_filename.txt"));
    }

    #[cfg(feature = "database")]
    #[test]
    fn test_queries_detection() {
        let security = Security::new();
        assert!(security.queries().is_sql_injection_present("1' OR '1'='1"));
    }

    #[cfg(feature = "formats")]
    #[test]
    fn test_formats_detection() {
        let security = Security::new();
        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
        assert!(security.formats().is_xxe_present(xxe));
    }
}

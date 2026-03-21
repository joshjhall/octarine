//! Session configuration
//!
//! Implements ASVS V3.3 session timeout requirements.

use chrono::Duration;

// ============================================================================
// Session Config
// ============================================================================

/// Session configuration
///
/// Follows OWASP ASVS V3.3 timeout requirements.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Absolute session timeout (ASVS V3.3.1)
    ///
    /// Maximum session duration regardless of activity.
    /// Default: 8 hours
    pub absolute_timeout: Duration,

    /// Idle session timeout (ASVS V3.3.2)
    ///
    /// Session expires after this duration of inactivity.
    /// Default: 30 minutes
    pub idle_timeout: Duration,

    /// Bind session to user agent (ASVS V3.2.1)
    ///
    /// Helps detect session hijacking.
    /// Default: true
    pub bind_user_agent: bool,

    /// Bind session to IP address
    ///
    /// May cause issues with mobile users or users behind load balancers.
    /// Default: false
    pub bind_ip: bool,

    /// Bind session to network prefix instead of exact IP
    ///
    /// More tolerant of NAT and dynamic IPs while still providing some protection.
    /// Default: false (only applies if bind_ip is true)
    pub bind_network_only: bool,

    /// Regenerate session ID on privilege escalation
    ///
    /// Required by ASVS for session fixation prevention.
    /// Default: true
    pub regenerate_on_privilege_change: bool,

    /// Cookie settings for web sessions
    pub cookie: SessionCookieConfig,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            absolute_timeout: Duration::hours(8),
            idle_timeout: Duration::minutes(30),
            bind_user_agent: true,
            bind_ip: false,
            bind_network_only: false,
            regenerate_on_privilege_change: true,
            cookie: SessionCookieConfig::default(),
        }
    }
}

impl SessionConfig {
    /// Create a new config with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for custom configuration
    #[must_use]
    pub fn builder() -> SessionConfigBuilder {
        SessionConfigBuilder::new()
    }

    /// Create a strict config for high-security applications
    #[must_use]
    pub fn strict() -> Self {
        Self {
            absolute_timeout: Duration::hours(4),
            idle_timeout: Duration::minutes(15),
            bind_user_agent: true,
            bind_ip: true,
            bind_network_only: false,
            regenerate_on_privilege_change: true,
            cookie: SessionCookieConfig::strict(),
        }
    }

    /// Create a lenient config for development/testing
    #[must_use]
    pub fn lenient() -> Self {
        Self {
            absolute_timeout: Duration::days(7),
            idle_timeout: Duration::hours(24),
            bind_user_agent: false,
            bind_ip: false,
            bind_network_only: false,
            regenerate_on_privilege_change: false,
            cookie: SessionCookieConfig::default(),
        }
    }
}

// ============================================================================
// Session Cookie Config
// ============================================================================

/// Session cookie configuration
#[derive(Debug, Clone)]
pub struct SessionCookieConfig {
    /// Cookie name
    pub name: String,

    /// HTTP-only flag (prevents JavaScript access)
    pub http_only: bool,

    /// Secure flag (HTTPS only)
    pub secure: bool,

    /// SameSite attribute
    pub same_site: SameSite,

    /// Cookie path
    pub path: String,

    /// Cookie domain (None = current domain)
    pub domain: Option<String>,
}

impl Default for SessionCookieConfig {
    fn default() -> Self {
        Self {
            name: "__session".to_string(),
            http_only: true,
            secure: true,
            same_site: SameSite::Lax,
            path: "/".to_string(),
            domain: None,
        }
    }
}

impl SessionCookieConfig {
    /// Create a strict cookie config
    #[must_use]
    pub fn strict() -> Self {
        Self {
            name: "__Host-session".to_string(),
            http_only: true,
            secure: true,
            same_site: SameSite::Strict,
            path: "/".to_string(),
            domain: None,
        }
    }
}

/// SameSite cookie attribute
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SameSite {
    /// Strict: Cookie only sent with same-site requests
    Strict,
    /// Lax: Cookie sent with top-level navigations and GET from external sites
    #[default]
    Lax,
    /// None: Cookie sent with all requests (requires Secure flag)
    None,
}

impl std::fmt::Display for SameSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strict => write!(f, "Strict"),
            Self::Lax => write!(f, "Lax"),
            Self::None => write!(f, "None"),
        }
    }
}

// ============================================================================
// Session Config Builder
// ============================================================================

/// Builder for creating custom session configurations
#[derive(Debug, Clone)]
pub struct SessionConfigBuilder {
    config: SessionConfig,
}

impl Default for SessionConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionConfigBuilder {
    /// Create a new builder with default config
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: SessionConfig::default(),
        }
    }

    /// Set absolute session timeout
    #[must_use]
    pub fn absolute_timeout(mut self, timeout: Duration) -> Self {
        self.config.absolute_timeout = timeout;
        self
    }

    /// Set idle session timeout
    #[must_use]
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.idle_timeout = timeout;
        self
    }

    /// Set whether to bind session to user agent
    #[must_use]
    pub fn bind_user_agent(mut self, bind: bool) -> Self {
        self.config.bind_user_agent = bind;
        self
    }

    /// Set whether to bind session to IP address
    #[must_use]
    pub fn bind_ip(mut self, bind: bool) -> Self {
        self.config.bind_ip = bind;
        self
    }

    /// Set whether to bind to network prefix instead of exact IP
    #[must_use]
    pub fn bind_network_only(mut self, network_only: bool) -> Self {
        self.config.bind_network_only = network_only;
        self
    }

    /// Set whether to regenerate session on privilege change
    #[must_use]
    pub fn regenerate_on_privilege_change(mut self, regenerate: bool) -> Self {
        self.config.regenerate_on_privilege_change = regenerate;
        self
    }

    /// Set cookie name
    #[must_use]
    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        self.config.cookie.name = name.into();
        self
    }

    /// Set cookie SameSite attribute
    #[must_use]
    pub fn cookie_same_site(mut self, same_site: SameSite) -> Self {
        self.config.cookie.same_site = same_site;
        self
    }

    /// Build the configuration
    #[must_use]
    pub fn build(self) -> SessionConfig {
        self.config
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SessionConfig::default();

        assert_eq!(config.absolute_timeout, Duration::hours(8));
        assert_eq!(config.idle_timeout, Duration::minutes(30));
        assert!(config.bind_user_agent);
        assert!(!config.bind_ip);
    }

    #[test]
    fn test_strict_config() {
        let config = SessionConfig::strict();

        assert_eq!(config.absolute_timeout, Duration::hours(4));
        assert_eq!(config.idle_timeout, Duration::minutes(15));
        assert!(config.bind_user_agent);
        assert!(config.bind_ip);
    }

    #[test]
    fn test_builder() {
        let config = SessionConfig::builder()
            .absolute_timeout(Duration::hours(2))
            .idle_timeout(Duration::minutes(15))
            .bind_ip(true)
            .cookie_name("my_session")
            .cookie_same_site(SameSite::Strict)
            .build();

        assert_eq!(config.absolute_timeout, Duration::hours(2));
        assert_eq!(config.idle_timeout, Duration::minutes(15));
        assert!(config.bind_ip);
        assert_eq!(config.cookie.name, "my_session");
        assert_eq!(config.cookie.same_site, SameSite::Strict);
    }

    #[test]
    fn test_same_site_display() {
        assert_eq!(SameSite::Strict.to_string(), "Strict");
        assert_eq!(SameSite::Lax.to_string(), "Lax");
        assert_eq!(SameSite::None.to_string(), "None");
    }
}

//! SecureEnvBuilder - Safe environment variable construction with observability
//!
//! A builder for constructing environment variables for subprocess execution
//! with security controls, audit trails, and observability.
//!
//! # Features
//!
//! - **Safe inheritance**: Only inherit explicitly allowed environment variables
//! - **Secret injection**: Add secrets with audit logging
//! - **Dangerous var filtering**: Block known dangerous variables
//! - **Audit trails**: All operations logged via observe
//!
//! # Example
//!
//! ```ignore
//! use octarine::crypto::secrets::{SecureEnvBuilder, SecureEnv};
//!
//! let env: SecureEnv = SecureEnvBuilder::new()
//!     .inherit_safe()                    // Inherit PATH, HOME, etc.
//!     .with_secret("API_KEY", api_key)   // Add secrets
//!     .with_var("LOG_LEVEL", "info")     // Add regular vars
//!     .build();
//!
//! // Use with std::process::Command
//! std::process::Command::new("app")
//!     .env_clear()  // Clear inherited env
//!     .envs(env.iter())
//!     .spawn()?;
//! ```

use std::collections::HashMap;
use std::fmt;
use std::ops::Deref;

use crate::observe;
use crate::primitives::crypto::secrets::{PrimitiveSecureEnv, PrimitiveSecureEnvBuilder};

/// A builder for constructing safe subprocess environments with observability
///
/// Wraps `PrimitiveSecureEnvBuilder` with observe instrumentation for audit trails.
///
/// # Security Model
///
/// By default, no environment variables are inherited. You must explicitly:
/// 1. Call `inherit_safe()` to inherit known-safe variables (PATH, HOME, etc.)
/// 2. Call `inherit_var()` to inherit specific variables
/// 3. Call `with_var()` or `with_secret()` to add new variables
///
/// Dangerous variables (credentials, injection vectors) are always blocked
/// unless `allow_dangerous()` is called.
///
/// # Example
///
/// ```ignore
/// let env = SecureEnvBuilder::new()
///     .inherit_safe()
///     .with_secret("DB_PASSWORD", password)
///     .with_var("APP_ENV", "production")
///     .build();
/// ```
pub struct SecureEnvBuilder {
    inner: PrimitiveSecureEnvBuilder,
}

impl SecureEnvBuilder {
    /// Create a new SecureEnvBuilder
    ///
    /// Starts with no inherited variables.
    #[must_use]
    pub fn new() -> Self {
        observe::debug("crypto.secrets.env", "Created new SecureEnvBuilder");
        Self {
            inner: PrimitiveSecureEnvBuilder::new(),
        }
    }

    /// Inherit known-safe environment variables
    ///
    /// This inherits: PATH, HOME, USER, LANG, LC_*, TERM, SHELL, TZ, TMPDIR, XDG_*
    ///
    /// # Example
    ///
    /// ```ignore
    /// let env = SecureEnvBuilder::new()
    ///     .inherit_safe()
    ///     .build();
    /// ```
    #[must_use]
    pub fn inherit_safe(self) -> Self {
        let safe_count = PrimitiveSecureEnvBuilder::safe_vars().len();
        observe::debug(
            "crypto.secrets.env",
            format!("Inheriting {} safe variables", safe_count),
        );
        Self {
            inner: self.inner.inherit_safe(),
        }
    }

    /// Inherit a specific environment variable
    ///
    /// The variable is only inherited if it exists in the current environment
    /// and is not in the dangerous list (unless `allow_dangerous()` was called).
    ///
    /// # Arguments
    ///
    /// * `name` - The variable name to inherit
    #[must_use]
    pub fn inherit_var(self, name: impl Into<String>) -> Self {
        let name = name.into();
        let (inner, was_blocked) = self.inner.inherit_var(name.clone());
        if was_blocked {
            observe::warn(
                "crypto.secrets.env",
                format!("Blocked inheritance of dangerous variable: {}", name),
            );
        } else {
            observe::debug(
                "crypto.secrets.env",
                format!("Will inherit variable: {}", name),
            );
        }
        Self { inner }
    }

    /// Add a regular (non-secret) environment variable
    ///
    /// # Arguments
    ///
    /// * `name` - The variable name
    /// * `value` - The variable value
    #[must_use]
    pub fn with_var(self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        let value = value.into();
        observe::debug(
            "crypto.secrets.env",
            format!("Adding variable: {}={}", name, value),
        );
        Self {
            inner: self.inner.with_var(name, value),
        }
    }

    /// Add a secret environment variable
    ///
    /// The value is stored securely and zeroized on drop.
    /// The variable name is logged, but not the value.
    ///
    /// # Arguments
    ///
    /// * `name` - The variable name
    /// * `value` - The secret value
    #[must_use]
    pub fn with_secret(self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        observe::debug(
            "crypto.secrets.env",
            format!("Adding secret variable: {}", name),
        );
        Self {
            inner: self.inner.with_secret(name, value),
        }
    }

    /// Allow dangerous environment variables
    ///
    /// **Warning**: This disables security checks. Only use when you know
    /// what you're doing (e.g., testing, specific tooling requirements).
    #[must_use]
    pub fn allow_dangerous(self) -> Self {
        observe::warn(
            "crypto.secrets.env",
            "Allowing dangerous environment variables",
        );
        Self {
            inner: self.inner.allow_dangerous(),
        }
    }

    /// Build the final environment map
    ///
    /// Returns a `SecureEnv` containing all configured variables.
    #[must_use]
    pub fn build(self) -> SecureEnv {
        let (inner, skipped_count) = self.inner.build();

        if skipped_count > 0 {
            observe::warn(
                "crypto.secrets.env.build",
                format!("Skipped {} dangerous inherited variables", skipped_count),
            );
        }

        observe::info(
            "crypto.secrets.env.build",
            format!(
                "Built environment with {} variables ({} secrets)",
                inner.len(),
                inner.secret_count()
            ),
        );

        SecureEnv { inner }
    }
}

impl Default for SecureEnvBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SecureEnvBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureEnvBuilder")
            .field("inner", &self.inner)
            .finish()
    }
}

/// A secure environment map ready for subprocess execution
///
/// Wraps `PrimitiveSecureEnv` with observability. Created by [`SecureEnvBuilder::build()`].
pub struct SecureEnv {
    inner: PrimitiveSecureEnv,
}

impl SecureEnv {
    /// Convert to a HashMap
    ///
    /// **Warning**: This exposes all values including secrets.
    /// Secret values are NOT zeroized when using this method.
    #[must_use]
    pub fn into_map(self) -> HashMap<String, String> {
        self.inner.into_map()
    }
}

impl Deref for SecureEnv {
    type Target = PrimitiveSecureEnv;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

// Note: No custom Drop impl - PrimitiveSecureEnv handles zeroization

impl fmt::Debug for SecureEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecureEnv { ")?;
        let mut first = true;
        for key in self.inner.keys() {
            if !first {
                f.write_str(", ")?;
            }
            if self.inner.is_secret(key) {
                write!(f, "{}: [REDACTED]", key)?;
            } else {
                write!(
                    f,
                    "{}: {:?}",
                    key,
                    self.inner.get(key).unwrap_or(&String::new())
                )?;
            }
            first = false;
        }
        f.write_str(" }")
    }
}

impl fmt::Display for SecureEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecureEnv({} vars, {} secrets)",
            self.inner.len(),
            self.inner.secret_count()
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_new_empty() {
        let env = SecureEnvBuilder::new().build();
        assert!(env.is_empty());
    }

    #[test]
    fn test_with_var() {
        let env = SecureEnvBuilder::new()
            .with_var("FOO", "bar")
            .with_var("BAZ", "qux")
            .build();

        assert_eq!(env.len(), 2);
        assert_eq!(env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(env.get("BAZ"), Some(&"qux".to_string()));
    }

    #[test]
    fn test_with_secret() {
        let env = SecureEnvBuilder::new()
            .with_secret("API_KEY", "sk-12345")
            .build();

        assert_eq!(env.len(), 1);
        assert_eq!(env.get("API_KEY"), Some(&"sk-12345".to_string()));
        assert!(env.is_secret("API_KEY"));
    }

    #[test]
    fn test_debug_redacts_secrets() {
        let env = SecureEnvBuilder::new()
            .with_var("PUBLIC", "visible")
            .with_secret("SECRET", "hidden")
            .build();

        let debug = format!("{:?}", env);
        assert!(debug.contains("PUBLIC"));
        assert!(debug.contains("visible"));
        assert!(debug.contains("SECRET"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("hidden"));
    }

    #[test]
    fn test_inherit_safe() {
        // This test depends on PATH being set in the environment
        let env = SecureEnvBuilder::new().inherit_safe().build();

        // PATH should be inherited if it exists
        if std::env::var("PATH").is_ok() {
            assert!(env.get("PATH").is_some());
        }
    }

    #[test]
    fn test_dangerous_var_blocked() {
        let env = SecureEnvBuilder::new()
            .inherit_var("AWS_SECRET_ACCESS_KEY")
            .build();

        // Should not inherit dangerous vars
        assert!(env.get("AWS_SECRET_ACCESS_KEY").is_none());
    }

    #[test]
    fn test_allow_dangerous_flag() {
        let env = SecureEnvBuilder::new()
            .allow_dangerous()
            .with_var("LD_PRELOAD", "/some/path") // normally dangerous
            .build();

        // Should be present since allow_dangerous was set
        assert_eq!(env.get("LD_PRELOAD"), Some(&"/some/path".to_string()));
    }

    #[test]
    fn test_iter() {
        let env = SecureEnvBuilder::new()
            .with_var("A", "1")
            .with_var("B", "2")
            .build();

        let pairs: Vec<_> = env.iter().collect();
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn test_keys() {
        let env = SecureEnvBuilder::new()
            .with_var("A", "1")
            .with_secret("B", "2")
            .build();

        let keys: Vec<_> = env.keys().collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_into_map() {
        let env = SecureEnvBuilder::new().with_var("A", "1").build();

        let map = env.into_map();
        assert_eq!(map.get("A"), Some(&"1".to_string()));
    }

    #[test]
    fn test_display() {
        let env = SecureEnvBuilder::new()
            .with_var("A", "1")
            .with_secret("B", "2")
            .build();

        let display = format!("{}", env);
        assert!(display.contains("2 vars"));
        assert!(display.contains("1 secrets"));
    }

    #[test]
    fn test_override_order() {
        // Secrets should override regular vars
        let env = SecureEnvBuilder::new()
            .with_var("KEY", "regular")
            .with_secret("KEY", "secret")
            .build();

        assert_eq!(env.get("KEY"), Some(&"secret".to_string()));
        assert!(env.is_secret("KEY"));
    }

    #[test]
    fn test_deref() {
        let env = SecureEnvBuilder::new().with_var("A", "1").build();

        // Access through Deref
        assert_eq!(env.len(), 1);
        assert!(!env.is_empty());
    }
}

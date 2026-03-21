//! PrimitiveSecureEnvBuilder - Safe environment variable construction
//!
//! A builder for constructing environment variables for subprocess execution
//! with security controls. This is the Layer 1 primitive without observability -
//! use `octarine::crypto::secrets::SecureEnvBuilder` for the instrumented version.
//!
//! # Features
//!
//! - **Safe inheritance**: Only inherit explicitly allowed environment variables
//! - **Secret injection**: Add secrets with proper handling
//! - **Dangerous var filtering**: Block known dangerous variables
//!
//! # Example
//!
//! ```ignore
//! use crate::primitives::crypto::secrets::PrimitiveSecureEnvBuilder;
//!
//! let env = PrimitiveSecureEnvBuilder::new()
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

// Allow dead_code: Layer 1 primitives used by Layer 2/3
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::env;
use std::fmt;
use std::mem;

use zeroize::Zeroize;

use super::ExposeSecretCore;
use super::SecretCore;

/// Environment variables that are generally safe to inherit
const SAFE_VARS: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "SHELL",
    "TZ",
    "TMPDIR",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
];

/// Environment variables that should never be inherited (security risk)
const DANGEROUS_VARS: &[&str] = &[
    // Credential/auth related
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",
    "GCP_SERVICE_ACCOUNT_KEY",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    "DOCKER_PASSWORD",
    // Database credentials
    "DATABASE_URL",
    "DB_PASSWORD",
    "PGPASSWORD",
    "MYSQL_PWD",
    "REDIS_PASSWORD",
    // Generic secrets
    "SECRET_KEY",
    "API_KEY",
    "API_SECRET",
    "PRIVATE_KEY",
    "ENCRYPTION_KEY",
    // Debug/injection risks
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "RUBYOPT",
    "PERL5OPT",
];

/// A builder for constructing safe subprocess environments (Layer 1 primitive)
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
/// This is the primitive version without observability instrumentation.
/// For the instrumented version, use `octarine::crypto::secrets::SecureEnvBuilder`.
///
/// # Example
///
/// ```ignore
/// let env = PrimitiveSecureEnvBuilder::new()
///     .inherit_safe()
///     .with_secret("DB_PASSWORD", password)
///     .with_var("APP_ENV", "production")
///     .build();
/// ```
pub struct PrimitiveSecureEnvBuilder {
    /// Regular (non-secret) variables
    vars: HashMap<String, String>,
    /// Secret variables (zeroized on drop)
    secrets: HashMap<String, SecretCore<String>>,
    /// Variables to inherit from current environment
    inherit: HashSet<String>,
    /// Allow dangerous variables
    allow_dangerous: bool,
}

impl PrimitiveSecureEnvBuilder {
    /// Create a new PrimitiveSecureEnvBuilder
    ///
    /// Starts with no inherited variables.
    #[must_use]
    pub fn new() -> Self {
        Self {
            vars: HashMap::new(),
            secrets: HashMap::new(),
            inherit: HashSet::new(),
            allow_dangerous: false,
        }
    }

    /// Inherit known-safe environment variables
    ///
    /// This inherits: PATH, HOME, USER, LANG, LC_*, TERM, SHELL, TZ, TMPDIR, XDG_*
    ///
    /// # Example
    ///
    /// ```ignore
    /// let env = PrimitiveSecureEnvBuilder::new()
    ///     .inherit_safe()
    ///     .build();
    /// ```
    #[must_use]
    pub fn inherit_safe(mut self) -> Self {
        for var in SAFE_VARS {
            self.inherit.insert((*var).to_string());
        }
        self
    }

    /// Inherit a specific environment variable
    ///
    /// The variable is only inherited if it exists in the current environment
    /// and is not in the dangerous list (unless `allow_dangerous()` was called).
    ///
    /// # Arguments
    ///
    /// * `name` - The variable name to inherit
    ///
    /// # Returns
    ///
    /// A tuple of (self, was_blocked) where was_blocked indicates if the variable
    /// was blocked due to being dangerous.
    #[must_use]
    pub fn inherit_var(mut self, name: impl Into<String>) -> (Self, bool) {
        let name = name.into();
        let was_blocked = !self.allow_dangerous && Self::is_dangerous(&name);
        if !was_blocked {
            self.inherit.insert(name);
        }
        (self, was_blocked)
    }

    /// Inherit a specific environment variable (chainable version)
    ///
    /// Same as `inherit_var` but silently ignores blocked variables for chaining.
    #[must_use]
    pub fn try_inherit_var(self, name: impl Into<String>) -> Self {
        self.inherit_var(name).0
    }

    /// Add a regular (non-secret) environment variable
    ///
    /// # Arguments
    ///
    /// * `name` - The variable name
    /// * `value` - The variable value
    #[must_use]
    pub fn with_var(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        let value = value.into();
        self.vars.insert(name, value);
        self
    }

    /// Add a secret environment variable
    ///
    /// The value is stored securely and zeroized on drop.
    ///
    /// # Arguments
    ///
    /// * `name` - The variable name
    /// * `value` - The secret value
    #[must_use]
    pub fn with_secret(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        let value = value.into();
        self.secrets.insert(name, SecretCore::new(value));
        self
    }

    /// Allow dangerous environment variables
    ///
    /// **Warning**: This disables security checks. Only use when you know
    /// what you're doing (e.g., testing, specific tooling requirements).
    #[must_use]
    pub fn allow_dangerous(mut self) -> Self {
        self.allow_dangerous = true;
        self
    }

    /// Build the final environment map
    ///
    /// Returns a `PrimitiveSecureEnv` containing all configured variables.
    ///
    /// # Returns
    ///
    /// A tuple of (env, skipped_dangerous_count) where skipped_dangerous_count
    /// is the number of dangerous variables that were skipped during inheritance.
    #[must_use]
    pub fn build(self) -> (PrimitiveSecureEnv, usize) {
        let mut result = HashMap::new();
        let mut skipped_count: usize = 0;

        // First, add inherited variables from current environment
        for name in &self.inherit {
            if let Ok(value) = env::var(name) {
                if !self.allow_dangerous && Self::is_dangerous(name) {
                    skipped_count = skipped_count.saturating_add(1);
                    continue;
                }
                result.insert(name.clone(), value);
            }
        }

        // Add regular variables (may override inherited)
        for (name, value) in self.vars {
            result.insert(name, value);
        }

        // Add secrets (may override inherited and regular)
        for (name, secret) in &self.secrets {
            result.insert(name.clone(), secret.expose_secret().clone());
        }

        (
            PrimitiveSecureEnv {
                inner: result,
                secret_keys: self.secrets.keys().cloned().collect(),
            },
            skipped_count,
        )
    }

    /// Build the final environment map (simple version)
    ///
    /// Returns just the `PrimitiveSecureEnv` without the skipped count.
    #[must_use]
    pub fn build_simple(self) -> PrimitiveSecureEnv {
        self.build().0
    }

    /// Check if a variable name is in the dangerous list
    pub fn is_dangerous(name: &str) -> bool {
        let name_upper = name.to_uppercase();
        DANGEROUS_VARS
            .iter()
            .any(|&d| name_upper == d.to_uppercase())
    }

    /// Get the list of safe variable names
    pub fn safe_vars() -> &'static [&'static str] {
        SAFE_VARS
    }

    /// Get the list of dangerous variable names
    pub fn dangerous_vars() -> &'static [&'static str] {
        DANGEROUS_VARS
    }
}

impl Default for PrimitiveSecureEnvBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PrimitiveSecureEnvBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrimitiveSecureEnvBuilder")
            .field("vars", &self.vars.keys().collect::<Vec<_>>())
            .field("secrets", &self.secrets.keys().collect::<Vec<_>>())
            .field("inherit", &self.inherit)
            .field("allow_dangerous", &self.allow_dangerous)
            .finish()
    }
}

/// A secure environment map ready for subprocess execution (Layer 1 primitive)
///
/// Created by [`PrimitiveSecureEnvBuilder::build()`].
///
/// This is the primitive version without observability instrumentation.
/// For the instrumented version, use `octarine::crypto::secrets::SecureEnv`.
pub struct PrimitiveSecureEnv {
    inner: HashMap<String, String>,
    secret_keys: HashSet<String>,
}

impl PrimitiveSecureEnv {
    /// Get the number of environment variables
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the environment is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get a variable value
    ///
    /// # Arguments
    ///
    /// * `name` - The variable name
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&String> {
        self.inner.get(name)
    }

    /// Check if a variable is a secret
    #[must_use]
    pub fn is_secret(&self, name: &str) -> bool {
        self.secret_keys.contains(name)
    }

    /// Get the number of secrets
    #[must_use]
    pub fn secret_count(&self) -> usize {
        self.secret_keys.len()
    }

    /// Iterate over all key-value pairs
    ///
    /// Use this with `Command::envs()`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// std::process::Command::new("app")
    ///     .env_clear()
    ///     .envs(env.iter())
    ///     .spawn()?;
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.inner.iter()
    }

    /// Get all keys
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.inner.keys()
    }

    /// Convert to a HashMap
    ///
    /// **Warning**: This exposes all values including secrets.
    /// Secret values are NOT zeroized when using this method.
    #[must_use]
    pub fn into_map(mut self) -> HashMap<String, String> {
        // Take ownership and clear secret_keys to prevent zeroization in Drop
        self.secret_keys.clear();
        mem::take(&mut self.inner)
    }
}

impl Drop for PrimitiveSecureEnv {
    fn drop(&mut self) {
        // Zeroize secret values
        for key in &self.secret_keys {
            if let Some(value) = self.inner.get_mut(key) {
                value.zeroize();
            }
        }
    }
}

impl fmt::Debug for PrimitiveSecureEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrimitiveSecureEnv { ")?;
        let mut first = true;
        for key in self.inner.keys() {
            if !first {
                f.write_str(", ")?;
            }
            if self.secret_keys.contains(key) {
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

impl fmt::Display for PrimitiveSecureEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrimitiveSecureEnv({} vars, {} secrets)",
            self.inner.len(),
            self.secret_keys.len()
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_new_empty() {
        let (env, skipped) = PrimitiveSecureEnvBuilder::new().build();
        assert!(env.is_empty());
        assert_eq!(skipped, 0);
    }

    #[test]
    fn test_with_var() {
        let env = PrimitiveSecureEnvBuilder::new()
            .with_var("FOO", "bar")
            .with_var("BAZ", "qux")
            .build_simple();

        assert_eq!(env.len(), 2);
        assert_eq!(env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(env.get("BAZ"), Some(&"qux".to_string()));
    }

    #[test]
    fn test_with_secret() {
        let env = PrimitiveSecureEnvBuilder::new()
            .with_secret("API_KEY", "sk-12345")
            .build_simple();

        assert_eq!(env.len(), 1);
        assert_eq!(env.get("API_KEY"), Some(&"sk-12345".to_string()));
        assert!(env.is_secret("API_KEY"));
    }

    #[test]
    fn test_debug_redacts_secrets() {
        let env = PrimitiveSecureEnvBuilder::new()
            .with_var("PUBLIC", "visible")
            .with_secret("SECRET", "hidden")
            .build_simple();

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
        let env = PrimitiveSecureEnvBuilder::new()
            .inherit_safe()
            .build_simple();

        // PATH should be inherited if it exists
        if std::env::var("PATH").is_ok() {
            assert!(env.get("PATH").is_some());
        }
    }

    #[test]
    fn test_dangerous_var_blocked() {
        let (builder, was_blocked) =
            PrimitiveSecureEnvBuilder::new().inherit_var("AWS_SECRET_ACCESS_KEY");

        assert!(was_blocked);
        let env = builder.build_simple();
        // Should not inherit dangerous vars
        assert!(env.get("AWS_SECRET_ACCESS_KEY").is_none());
    }

    #[test]
    fn test_allow_dangerous_flag() {
        // With allow_dangerous, dangerous vars can be added
        let env = PrimitiveSecureEnvBuilder::new()
            .allow_dangerous()
            .with_var("LD_PRELOAD", "/some/path") // normally dangerous
            .build_simple();

        // Should be present since allow_dangerous was set
        assert_eq!(env.get("LD_PRELOAD"), Some(&"/some/path".to_string()));
    }

    #[test]
    fn test_iter() {
        let env = PrimitiveSecureEnvBuilder::new()
            .with_var("A", "1")
            .with_var("B", "2")
            .build_simple();

        let pairs: Vec<_> = env.iter().collect();
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn test_keys() {
        let env = PrimitiveSecureEnvBuilder::new()
            .with_var("A", "1")
            .with_secret("B", "2")
            .build_simple();

        let keys: Vec<_> = env.keys().collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_into_map() {
        let env = PrimitiveSecureEnvBuilder::new()
            .with_var("A", "1")
            .build_simple();

        let map = env.into_map();
        assert_eq!(map.get("A"), Some(&"1".to_string()));
    }

    #[test]
    fn test_display() {
        let env = PrimitiveSecureEnvBuilder::new()
            .with_var("A", "1")
            .with_secret("B", "2")
            .build_simple();

        let display = format!("{}", env);
        assert!(display.contains("2 vars"));
        assert!(display.contains("1 secrets"));
    }

    #[test]
    fn test_override_order() {
        // Secrets should override regular vars
        let env = PrimitiveSecureEnvBuilder::new()
            .with_var("KEY", "regular")
            .with_secret("KEY", "secret")
            .build_simple();

        assert_eq!(env.get("KEY"), Some(&"secret".to_string()));
        assert!(env.is_secret("KEY"));
    }

    #[test]
    fn test_is_dangerous() {
        assert!(PrimitiveSecureEnvBuilder::is_dangerous(
            "AWS_SECRET_ACCESS_KEY"
        ));
        assert!(PrimitiveSecureEnvBuilder::is_dangerous("LD_PRELOAD"));
        assert!(!PrimitiveSecureEnvBuilder::is_dangerous("PATH"));
        assert!(!PrimitiveSecureEnvBuilder::is_dangerous("MY_CUSTOM_VAR"));
    }

    #[test]
    fn test_secret_count() {
        let env = PrimitiveSecureEnvBuilder::new()
            .with_var("A", "1")
            .with_secret("B", "2")
            .with_secret("C", "3")
            .build_simple();

        assert_eq!(env.secret_count(), 2);
    }
}

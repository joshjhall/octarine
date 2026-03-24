//! Configuration builder for loading from environment and files

use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::crypto::secrets::{Classification, SecretType, TypedSecret};
use crate::observe;

use super::error::ConfigError;
use super::figment_adapter::FigmentAdapter;
use super::value::ConfigValue;

/// Builder for loading configuration from environment variables and files
///
/// Provides a fluent API for loading, validating, and converting
/// environment variables with prefix support and audit logging.
///
/// # Examples
///
/// ## Single-value API (environment variables)
///
/// ```ignore
/// use octarine::runtime::config::ConfigBuilder;
///
/// let config = ConfigBuilder::new()
///     .with_prefix("APP")
///     .get("PORT")?
///     .default("8080")
///     .parse::<u16>()?;
/// ```
///
/// ## Struct-based API (files + env vars)
///
/// ```ignore
/// use octarine::runtime::config::ConfigBuilder;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Debug, Deserialize, Serialize, Default)]
/// struct AppConfig {
///     port: u16,
///     host: String,
/// }
///
/// let config: AppConfig = ConfigBuilder::new()
///     .with_defaults(AppConfig::default())
///     .with_optional_file("app.toml")
///     .with_prefix("APP")
///     .build_struct()?;
/// ```
#[derive(Debug, Clone)]
pub struct ConfigBuilder {
    /// Prefix for environment variables (e.g., "APP" -> "APP_PORT")
    prefix: Option<String>,
    /// Separator between prefix and name (default: "_")
    separator: String,
    /// Loaded values (for batch operations)
    values: HashMap<String, LoadedValue>,
    /// Names of secret fields (values will be masked in logs)
    secrets: Vec<String>,
    /// Config files to load (in order)
    files: Vec<PathBuf>,
    /// Serialized defaults for struct-based config
    defaults_json: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
struct LoadedValue {
    raw: Option<String>,
    is_secret: bool,
    is_required: bool,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigBuilder {
    /// Create a new ConfigBuilder
    ///
    /// # Example
    ///
    /// ```ignore
    /// let builder = ConfigBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        observe::debug("runtime.config", "Creating ConfigBuilder");
        Self {
            prefix: None,
            separator: "_".to_string(),
            values: HashMap::new(),
            secrets: Vec::new(),
            files: Vec::new(),
            defaults_json: None,
        }
    }

    /// Set the prefix for environment variable names
    ///
    /// When a prefix is set, `get("PORT")` will look for `PREFIX_PORT`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let builder = ConfigBuilder::new().with_prefix("APP");
    /// // get("PORT") will look for APP_PORT
    /// ```
    #[must_use]
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        let prefix = prefix.into();
        observe::debug("runtime.config", format!("Setting prefix: {}", prefix));
        self.prefix = Some(prefix);
        self
    }

    /// Set the separator between prefix and name (default: "_")
    ///
    /// # Example
    ///
    /// ```ignore
    /// let builder = ConfigBuilder::new()
    ///     .with_prefix("APP")
    ///     .with_separator("__");
    /// // get("PORT") will look for APP__PORT
    /// ```
    #[must_use]
    pub fn with_separator(mut self, separator: impl Into<String>) -> Self {
        self.separator = separator.into();
        self
    }

    // ========================================================================
    // File-based configuration API
    // ========================================================================

    /// Set struct defaults for configuration
    ///
    /// When using `build_struct()`, these defaults are the lowest priority.
    /// File values override defaults, and environment variables override both.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::runtime::config::ConfigBuilder;
    ///
    /// #[derive(Debug, Serialize, Deserialize, Default)]
    /// struct AppConfig {
    ///     port: u16,
    ///     host: String,
    /// }
    ///
    /// let config: AppConfig = ConfigBuilder::new()
    ///     .with_defaults(AppConfig { port: 8080, host: "localhost".into() })
    ///     .with_optional_file("app.toml")
    ///     .with_prefix("APP")
    ///     .build_struct()?;
    /// ```
    #[must_use]
    pub fn with_defaults<T: Serialize>(mut self, defaults: T) -> Self {
        self.defaults_json = serde_json::to_value(defaults).ok();
        observe::debug("runtime.config", "Set configuration defaults");
        self
    }

    /// Add a required config file
    ///
    /// The file must exist, otherwise an error is returned.
    /// Files are loaded in the order they are added, with later files
    /// overriding earlier ones.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config: AppConfig = ConfigBuilder::new()
    ///     .with_file("app.toml")?
    ///     .build_struct()?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::FileError` if the file does not exist.
    pub fn with_file(mut self, path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(ConfigError::file_error(path, "file not found"));
        }
        observe::debug(
            "runtime.config",
            format!("Adding config file: {}", path.display()),
        );
        self.files.push(path.to_path_buf());
        Ok(self)
    }

    /// Add an optional config file
    ///
    /// If the file exists, it will be loaded. If it doesn't exist,
    /// no error is returned and the file is skipped.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config: AppConfig = ConfigBuilder::new()
    ///     .with_defaults(AppConfig::default())
    ///     .with_optional_file("app.toml")  // OK if missing
    ///     .build_struct()?;
    /// ```
    #[must_use]
    pub fn with_optional_file(mut self, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        if path.exists() {
            observe::debug(
                "runtime.config",
                format!("Adding optional config file: {}", path.display()),
            );
            self.files.push(path.to_path_buf());
        } else {
            observe::debug(
                "runtime.config",
                format!(
                    "Optional config file not found (skipped): {}",
                    path.display()
                ),
            );
        }
        self
    }

    /// Add a secure config file with permission validation
    ///
    /// The file must exist and have restrictive permissions (0600 on Unix).
    /// Use this for files containing secrets.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config: AppConfig = ConfigBuilder::new()
    ///     .with_secure_file("secrets.toml")?  // Must be chmod 600
    ///     .build_struct()?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::FileError` if the file does not exist.
    /// Returns `ConfigError::InsecurePermissions` if permissions are too open.
    #[cfg(unix)]
    pub fn with_secure_file(mut self, path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        use std::os::unix::fs::PermissionsExt;

        let path = path.as_ref();
        if !path.exists() {
            return Err(ConfigError::file_error(path, "file not found"));
        }

        // Check permissions - must be 0600 (owner read/write only)
        let metadata =
            std::fs::metadata(path).map_err(|e| ConfigError::file_error(path, e.to_string()))?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(ConfigError::insecure_permissions(
                path,
                "0600 (owner read/write only)",
                format!("{:04o}", mode),
            ));
        }

        observe::debug(
            "runtime.config",
            format!("Adding secure config file: {}", path.display()),
        );
        self.files.push(path.to_path_buf());
        Ok(self)
    }

    /// Build and deserialize configuration to a typed struct
    ///
    /// Merges configuration from multiple sources with this priority:
    /// 1. Environment variables (highest priority)
    /// 2. Config files (in order added)
    /// 3. Struct defaults (lowest priority)
    ///
    /// # Example
    ///
    /// ```ignore
    /// #[derive(Debug, Deserialize, Serialize, Default)]
    /// struct AppConfig {
    ///     port: u16,
    ///     host: String,
    /// }
    ///
    /// let config: AppConfig = ConfigBuilder::new()
    ///     .with_defaults(AppConfig::default())
    ///     .with_optional_file("app.toml")
    ///     .with_prefix("APP")
    ///     .build_struct()?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::ExtractionError` if deserialization fails.
    /// Returns `ConfigError::FileError` if a file cannot be read.
    pub fn build_struct<T>(self) -> Result<T, ConfigError>
    where
        T: DeserializeOwned,
    {
        let mut adapter = FigmentAdapter::new();

        // Layer 1: Defaults (lowest priority)
        if let Some(defaults) = self.defaults_json {
            adapter = adapter.with_defaults(defaults);
        }

        // Layer 2: Files (middle priority, in order added)
        for file in &self.files {
            adapter = adapter.with_file(file)?;
        }

        // Layer 3: Environment variables (highest priority)
        if let Some(prefix) = &self.prefix {
            adapter = adapter.with_env(prefix, &self.separator);
        }

        let file_count = adapter.file_count();
        let config: T = adapter.extract()?;

        observe::info(
            "runtime.config.build",
            format!(
                "Configuration loaded: {} file(s), prefix={:?}",
                file_count, self.prefix
            ),
        );

        Ok(config)
    }

    /// Build and deserialize to target struct (ergonomic alias for `build_struct`)
    ///
    /// This is the preferred method for struct-based configuration.
    /// See [`build_struct`](Self::build_struct) for details.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config: AppConfig = ConfigBuilder::new()
    ///     .with_defaults(AppConfig::default())
    ///     .with_optional_file("app.toml")
    ///     .with_prefix("APP")
    ///     .build()?;
    /// ```
    pub fn build<T>(self) -> Result<T, ConfigError>
    where
        T: DeserializeOwned,
    {
        self.build_struct()
    }

    /// Build with validation callback
    ///
    /// Deserializes configuration then runs custom validation.
    /// Useful for cross-field validation that serde can't express.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config: AppConfig = ConfigBuilder::new()
    ///     .with_defaults(AppConfig::default())
    ///     .with_optional_file("app.toml")
    ///     .with_prefix("APP")
    ///     .build_validated(|c| {
    ///         if c.database.url.is_empty() {
    ///             return Err(ConfigError::validation("database.url", "required", "cannot be empty"));
    ///         }
    ///         if c.timeout_secs < c.retry_count {
    ///             return Err(ConfigError::validation(
    ///                 "timeout_secs",
    ///                 "consistency",
    ///                 "timeout must be >= retry_count"
    ///             ));
    ///         }
    ///         Ok(())
    ///     })?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::ExtractionError` if deserialization fails.
    /// Returns the error from the validation callback if validation fails.
    pub fn build_validated<T, F>(self, validate: F) -> Result<T, ConfigError>
    where
        T: DeserializeOwned,
        F: FnOnce(&T) -> Result<(), ConfigError>,
    {
        let config: T = self.build_struct()?;
        validate(&config)?;
        Ok(config)
    }

    // ========================================================================
    // Single-value API (environment variables only)
    // ========================================================================

    /// Get a configuration value by name
    ///
    /// Returns a `ConfigValue` that can be converted to various types.
    /// The name will be prefixed if a prefix was set.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let port: u16 = ConfigBuilder::new()
    ///     .with_prefix("APP")
    ///     .get("PORT")?
    ///     .default("8080")
    ///     .parse()?;
    /// ```
    pub fn get(&self, name: &str) -> Result<ConfigValue, ConfigError> {
        self.get_internal(name, false)
    }

    /// Get a secret configuration value by name
    ///
    /// Like `get()`, but the value will be masked in error messages and logs.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let api_key: String = ConfigBuilder::new()
    ///     .with_prefix("APP")
    ///     .get_secret("API_KEY")?
    ///     .parse()?;
    /// ```
    pub fn get_secret(&self, name: &str) -> Result<ConfigValue, ConfigError> {
        self.get_internal(name, true)
    }

    /// Get a typed secret with explicit type and classification
    ///
    /// Convenience method that combines `get_secret()` with `into_typed_secret()`.
    /// Creates a `TypedSecret<String>` with NIST-compliant metadata for
    /// audit trails and lifecycle management.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::runtime::config::{ConfigBuilder, SecretType, Classification};
    ///
    /// let api_key = ConfigBuilder::new()
    ///     .with_prefix("APP")
    ///     .get_typed_secret("API_KEY", SecretType::ApiKey, Classification::Confidential)?;
    ///
    /// // Access with audit trail
    /// let value = api_key.expose_secret_audited("api_call");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::Missing` if the value is not set.
    /// Returns `ConfigError::InvalidName` if the name is invalid.
    pub fn get_typed_secret(
        &self,
        name: &str,
        secret_type: SecretType,
        classification: Classification,
    ) -> Result<TypedSecret<String>, ConfigError> {
        self.get_secret(name)?
            .into_typed_secret(secret_type, classification)
    }

    /// Get a secret with auto-detected type via PII scanner
    ///
    /// Convenience method that combines `get_secret()` with `into_auto_secret()`.
    /// Automatically detects the secret type (API key, JWT, password, etc.)
    /// by scanning the value with the PII detection system.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::runtime::config::ConfigBuilder;
    ///
    /// // JWT token is auto-detected as AuthToken
    /// let token = ConfigBuilder::new()
    ///     .with_prefix("APP")
    ///     .get_auto_secret("TOKEN")?;
    ///
    /// assert_eq!(token.secret_type(), &SecretType::AuthToken);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::Missing` if the value is not set.
    /// Returns `ConfigError::InvalidName` if the name is invalid.
    pub fn get_auto_secret(&self, name: &str) -> Result<TypedSecret<String>, ConfigError> {
        self.get_secret(name)?.into_auto_secret()
    }

    /// Internal get implementation
    fn get_internal(&self, name: &str, is_secret: bool) -> Result<ConfigValue, ConfigError> {
        // Validate name
        if name.is_empty() {
            return Err(ConfigError::invalid_name(name, "name cannot be empty"));
        }
        if name.contains(char::is_whitespace) {
            return Err(ConfigError::invalid_name(
                name,
                "name cannot contain whitespace",
            ));
        }

        let full_name = self.full_name(name);
        let value = env::var(&full_name).ok();

        if is_secret {
            observe::debug(
                "runtime.config.get",
                format!("Loading secret: {} (set: {})", full_name, value.is_some()),
            );
        } else {
            observe::debug(
                "runtime.config.get",
                format!(
                    "Loading: {} = {}",
                    full_name,
                    value.as_deref().unwrap_or("<not set>")
                ),
            );
        }

        Ok(ConfigValue::new(full_name, value, is_secret))
    }

    /// Build the full environment variable name with prefix
    ///
    /// Includes protection against accidental double-prefixing.
    fn full_name(&self, name: &str) -> String {
        match &self.prefix {
            Some(prefix) => {
                let prefix_with_sep = format!("{}{}", prefix, self.separator);

                // Check for potential double-prefixing
                if name.starts_with(&prefix_with_sep) {
                    observe::warn(
                        "runtime.config.prefix",
                        format!(
                            "Potential double-prefix detected: '{}' already starts with '{}'. \
                             Using name as-is. If this is intentional, use `get()` without `with_prefix()`.",
                            name, prefix_with_sep
                        ),
                    );
                    return name.to_string();
                }

                format!("{}{}{}", prefix, self.separator, name)
            }
            None => name.to_string(),
        }
    }

    // ========================================================================
    // Batch loading API
    // ========================================================================

    /// Mark a field as required for batch loading
    ///
    /// The value must be set in the environment.
    #[must_use]
    pub fn require(mut self, name: &str) -> Self {
        let full_name = self.full_name(name);
        let value = env::var(&full_name).ok();

        observe::debug(
            "runtime.config.require",
            format!("Requiring: {} (set: {})", full_name, value.is_some()),
        );

        self.values.insert(
            name.to_string(),
            LoadedValue {
                raw: value,
                is_secret: false,
                is_required: true,
            },
        );
        self
    }

    /// Mark a field as optional for batch loading
    #[must_use]
    pub fn optional(mut self, name: &str) -> Self {
        let full_name = self.full_name(name);
        let value = env::var(&full_name).ok();

        observe::debug(
            "runtime.config.optional",
            format!("Loading optional: {} = {:?}", full_name, value),
        );

        self.values.insert(
            name.to_string(),
            LoadedValue {
                raw: value,
                is_secret: false,
                is_required: false,
            },
        );
        self
    }

    /// Mark a field as a secret for batch loading
    ///
    /// The value will be masked in logs and error messages.
    #[must_use]
    pub fn secret(mut self, name: &str) -> Self {
        let full_name = self.full_name(name);
        let value = env::var(&full_name).ok();

        observe::debug(
            "runtime.config.secret",
            format!("Loading secret: {} (set: {})", full_name, value.is_some()),
        );

        self.secrets.push(name.to_string());
        self.values.insert(
            name.to_string(),
            LoadedValue {
                raw: value,
                is_secret: true,
                is_required: true, // Secrets are required by default
            },
        );
        self
    }

    /// Mark a field as an optional secret
    #[must_use]
    pub fn optional_secret(mut self, name: &str) -> Self {
        let full_name = self.full_name(name);
        let value = env::var(&full_name).ok();

        observe::debug(
            "runtime.config.optional_secret",
            format!(
                "Loading optional secret: {} (set: {})",
                full_name,
                value.is_some()
            ),
        );

        self.secrets.push(name.to_string());
        self.values.insert(
            name.to_string(),
            LoadedValue {
                raw: value,
                is_secret: true,
                is_required: false,
            },
        );
        self
    }

    /// Load and validate the batch configuration
    ///
    /// Returns a `LoadedConfig` containing all loaded values.
    /// Fails if any required values are missing.
    ///
    /// Note: For struct-based configuration, use [`build`](Self::build) or
    /// [`build_struct`](Self::build_struct) instead.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::Missing` if any required value is not set.
    pub fn load(self) -> Result<LoadedConfig, ConfigError> {
        // Check for missing required values
        for (name, loaded) in &self.values {
            if loaded.is_required && loaded.raw.is_none() {
                let full_name = self.full_name(name);
                observe::warn(
                    "runtime.config.build",
                    format!("Missing required config: {}", full_name),
                );
                return Err(ConfigError::missing(full_name));
            }
        }

        let count = self.values.len();
        let secret_count = self.secrets.len();
        observe::info(
            "runtime.config.build",
            format!(
                "Configuration loaded: {} values ({} secrets)",
                count, secret_count
            ),
        );

        Ok(LoadedConfig {
            prefix: self.prefix,
            separator: self.separator,
            values: self.values,
        })
    }
}

/// A loaded configuration ready for value extraction
///
/// Created by [`ConfigBuilder::build()`].
#[derive(Debug)]
pub struct LoadedConfig {
    prefix: Option<String>,
    separator: String,
    values: HashMap<String, LoadedValue>,
}

impl LoadedConfig {
    /// Get a value by name
    ///
    /// Returns a `ConfigValue` for type conversion.
    pub fn get(&self, name: &str) -> ConfigValue {
        let full_name = match &self.prefix {
            Some(prefix) => format!("{}{}{}", prefix, self.separator, name),
            None => name.to_string(),
        };

        let loaded = self.values.get(name);
        let (raw, is_secret) = match loaded {
            Some(l) => (l.raw.clone(), l.is_secret),
            None => (None, false),
        };

        ConfigValue::new(full_name, raw, is_secret)
    }

    /// Check if a value is set
    pub fn has(&self, name: &str) -> bool {
        self.values
            .get(name)
            .map(|l| l.raw.is_some())
            .unwrap_or(false)
    }

    /// Get all loaded variable names
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.values.keys()
    }

    /// Get the number of loaded values
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Check if no values were loaded
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::result_large_err
    )]

    use super::*;

    // ========================================================================
    // Tests that don't require environment variables
    // ========================================================================

    #[test]
    fn test_get_missing() {
        // Uses a random prefix that won't exist in the environment
        let value = ConfigBuilder::new()
            .with_prefix("OCTARINE_TEST_NONEXISTENT_XYZ")
            .get("VALUE")
            .unwrap();

        assert!(!value.is_set());
    }

    #[test]
    fn test_get_with_default() {
        let value = ConfigBuilder::new()
            .with_prefix("OCTARINE_TEST_MISSING_XYZ")
            .get("PORT")
            .unwrap()
            .default("3000");

        let port: u16 = value.parse().unwrap();
        assert_eq!(port, 3000);
    }

    #[test]
    fn test_batch_missing_required() {
        let result = ConfigBuilder::new()
            .with_prefix("OCTARINE_TEST_MISSING_XYZ")
            .require("REQUIRED_VALUE")
            .load();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::Missing { .. }));
    }

    #[test]
    fn test_invalid_name() {
        let result = ConfigBuilder::new().get("");
        assert!(result.is_err());

        let result = ConfigBuilder::new().get("HAS SPACE");
        assert!(result.is_err());
    }

    #[test]
    fn test_full_name_with_prefix() {
        let builder = ConfigBuilder::new().with_prefix("APP");
        assert_eq!(builder.full_name("PORT"), "APP_PORT");
    }

    #[test]
    fn test_full_name_without_prefix() {
        let builder = ConfigBuilder::new();
        assert_eq!(builder.full_name("PORT"), "PORT");
    }

    #[test]
    fn test_full_name_custom_separator() {
        let builder = ConfigBuilder::new().with_prefix("APP").with_separator("__");
        assert_eq!(builder.full_name("PORT"), "APP__PORT");
    }

    #[test]
    fn test_loaded_config_empty() {
        // Load with only optional fields that don't exist
        let config = ConfigBuilder::new()
            .with_prefix("OCTARINE_TEST_EMPTY_XYZ")
            .optional("NONEXISTENT")
            .load()
            .unwrap();

        assert_eq!(config.len(), 1);
        assert!(!config.has("NONEXISTENT"));
        assert!(!config.is_empty());
    }

    #[test]
    fn test_loaded_config_get_unregistered() {
        let config = ConfigBuilder::new()
            .with_prefix("OCTARINE_TEST_XYZ")
            .optional("ONE")
            .load()
            .unwrap();

        // Getting an unregistered key returns ConfigValue with None
        let value = config.get("UNREGISTERED");
        assert!(!value.is_set());
    }

    #[test]
    fn test_loaded_config_keys() {
        let config = ConfigBuilder::new()
            .with_prefix("OCTARINE_TEST_XYZ")
            .optional("A")
            .optional("B")
            .optional("C")
            .load()
            .unwrap();

        let keys: Vec<_> = config.keys().collect();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&&"A".to_string()));
        assert!(keys.contains(&&"B".to_string()));
        assert!(keys.contains(&&"C".to_string()));
    }

    // ========================================================================
    // Tests using PATH environment variable (always exists)
    // ========================================================================

    #[test]
    fn test_get_existing_env_var() {
        // PATH is always set on all systems
        let value = ConfigBuilder::new().get("PATH").unwrap();

        assert!(value.is_set());
        let path: String = value.parse().unwrap();
        assert!(!path.is_empty());
    }

    #[test]
    fn test_prefix_override() {
        // Even with a prefix, we can still get PATH if it exists with that prefix
        // But here we test that prefix changes the lookup
        let builder = ConfigBuilder::new().with_prefix("OCTARINE_TEST_XYZ");

        // This should NOT find PATH because it looks for OCTARINE_TEST_XYZ_PATH
        let value = builder.get("PATH").unwrap();
        assert!(!value.is_set());
    }

    // ========================================================================
    // Tests for secret marking
    // ========================================================================

    #[test]
    fn test_secret_value_is_marked() {
        // Even without a value set, we can verify the secret flag is set
        let config = ConfigBuilder::new()
            .with_prefix("OCTARINE_TEST_SECRET_XYZ")
            .optional_secret("API_KEY")
            .load()
            .unwrap();

        let value = config.get("API_KEY");
        assert!(value.is_secret());
    }

    #[test]
    fn test_non_secret_value_not_marked() {
        let config = ConfigBuilder::new()
            .with_prefix("OCTARINE_TEST_XYZ")
            .optional("NORMAL_VALUE")
            .load()
            .unwrap();

        let value = config.get("NORMAL_VALUE");
        assert!(!value.is_secret());
    }

    // ========================================================================
    // Tests for file-based configuration
    // ========================================================================

    #[test]
    fn test_with_file_not_found() {
        let result = ConfigBuilder::new().with_file("/nonexistent/config.toml");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::FileError { .. }));
    }

    #[test]
    fn test_with_optional_file_missing() {
        let builder = ConfigBuilder::new().with_optional_file("/nonexistent/config.toml");
        // Should not error, files list should be empty
        assert!(builder.files.is_empty());
    }

    #[test]
    fn test_with_defaults() {
        #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Default)]
        struct TestConfig {
            port: u16,
            host: String,
        }

        let defaults = TestConfig {
            port: 8080,
            host: "localhost".to_string(),
        };

        let config: TestConfig = ConfigBuilder::new()
            .with_defaults(defaults)
            .build_struct()
            .unwrap();

        assert_eq!(config.port, 8080);
        assert_eq!(config.host, "localhost");
    }

    #[test]
    fn test_build_struct_from_file() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct TestConfig {
            port: u16,
            host: String,
        }

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "port = 9000").unwrap();
        writeln!(file, r#"host = "example.com""#).unwrap();

        let config: TestConfig = ConfigBuilder::new()
            .with_file(file.path())
            .unwrap()
            .build_struct()
            .unwrap();

        assert_eq!(config.port, 9000);
        assert_eq!(config.host, "example.com");
    }

    #[test]
    fn test_file_overrides_defaults() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Default)]
        #[serde(default)]
        struct TestConfig {
            port: u16,
            host: String,
        }

        let defaults = TestConfig {
            port: 3000,
            host: "default-host".to_string(),
        };

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "port = 8080").unwrap();
        // host not in file, should use default

        let config: TestConfig = ConfigBuilder::new()
            .with_defaults(defaults)
            .with_file(file.path())
            .unwrap()
            .build_struct()
            .unwrap();

        assert_eq!(config.port, 8080); // From file
        assert_eq!(config.host, "default-host"); // From defaults
    }

    #[test]
    fn test_env_overrides_file() {
        use figment::Jail;

        #[derive(Debug, serde::Deserialize, Default)]
        #[serde(default)]
        struct TestConfig {
            port: u16,
            host: String,
        }

        Jail::expect_with(|jail| {
            jail.set_env("FILETEST_PORT", "9999");
            jail.create_file(
                "config.toml",
                r#"
                port = 8080
                host = "file-host"
                "#,
            )?;

            let config: TestConfig = ConfigBuilder::new()
                .with_file("config.toml")
                .expect("config file should exist")
                .with_prefix("FILETEST")
                .build_struct()
                .expect("config should extract");

            assert_eq!(config.port, 9999); // From env
            assert_eq!(config.host, "file-host"); // From file
            Ok(())
        });
    }

    #[test]
    fn test_layering_priority() {
        use figment::Jail;

        // Test: env > file > defaults
        // Note: Env vars use "_" as nested path separator (APP_DATABASE_URL -> database.url)
        // So we use nested structs for accurate testing
        #[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
        #[serde(default)]
        struct TestConfig {
            defaults: DefaultsSection,
            file: FileSection,
            env: EnvSection,
        }

        #[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
        #[serde(default)]
        struct DefaultsSection {
            value: String,
        }

        #[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
        #[serde(default)]
        struct FileSection {
            value: String,
        }

        #[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
        #[serde(default)]
        struct EnvSection {
            value: String,
        }

        Jail::expect_with(|jail| {
            // ENV_VALUE maps to env.value in nested struct
            jail.set_env("LAYERTEST2_ENV_VALUE", "from-env");
            jail.create_file(
                "config.toml",
                r#"
                [file]
                value = "from-file"

                [env]
                value = "will-be-overridden-by-env"
                "#,
            )?;

            let defaults = TestConfig {
                defaults: DefaultsSection {
                    value: "from-defaults".to_string(),
                },
                file: FileSection {
                    value: "will-be-overridden-by-file".to_string(),
                },
                env: EnvSection {
                    value: "will-be-overridden-by-env".to_string(),
                },
            };

            let config: TestConfig = ConfigBuilder::new()
                .with_defaults(defaults)
                .with_file("config.toml")
                .expect("config file should exist")
                .with_prefix("LAYERTEST2")
                .build_struct()
                .expect("config should extract");

            assert_eq!(config.defaults.value, "from-defaults"); // Only defaults
            assert_eq!(config.file.value, "from-file"); // File overrides defaults
            assert_eq!(config.env.value, "from-env"); // Env overrides file
            Ok(())
        });
    }

    #[test]
    fn test_multiple_files() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        #[derive(Debug, serde::Deserialize, Default)]
        #[serde(default)]
        struct TestConfig {
            base_value: String,
            override_value: String,
        }

        let mut base_file = NamedTempFile::new().unwrap();
        writeln!(base_file, r#"base_value = "from-base""#).unwrap();
        writeln!(base_file, r#"override_value = "from-base""#).unwrap();

        let mut override_file = NamedTempFile::new().unwrap();
        writeln!(override_file, r#"override_value = "from-override""#).unwrap();

        let config: TestConfig = ConfigBuilder::new()
            .with_file(base_file.path())
            .unwrap()
            .with_file(override_file.path())
            .unwrap()
            .build_struct()
            .unwrap();

        assert_eq!(config.base_value, "from-base");
        assert_eq!(config.override_value, "from-override"); // Later file wins
    }

    #[cfg(unix)]
    #[test]
    fn test_secure_file_wrong_permissions() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "secret = \"value\"").unwrap();

        // Set permissive permissions (0644)
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644)).unwrap();

        let result = ConfigBuilder::new().with_secure_file(file.path());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::InsecurePermissions { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn test_secure_file_correct_permissions() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use tempfile::NamedTempFile;

        #[derive(Debug, serde::Deserialize)]
        struct TestConfig {
            secret: String,
        }

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"secret = "super-secret""#).unwrap();

        // Set restrictive permissions (0600)
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600)).unwrap();

        let config: TestConfig = ConfigBuilder::new()
            .with_secure_file(file.path())
            .unwrap()
            .build_struct()
            .unwrap();

        assert_eq!(config.secret, "super-secret");
    }

    // ========================================================================
    // Tests for build<T>() and build_validated<T, F>() (Issue #306)
    // ========================================================================

    #[test]
    fn test_build_alias_works_like_build_struct() {
        #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Default)]
        struct TestConfig {
            port: u16,
            host: String,
        }

        let defaults = TestConfig {
            port: 8080,
            host: "localhost".to_string(),
        };

        // Using build() should work identically to build_struct()
        let config: TestConfig = ConfigBuilder::new()
            .with_defaults(defaults)
            .build()
            .unwrap();

        assert_eq!(config.port, 8080);
        assert_eq!(config.host, "localhost");
    }

    #[test]
    fn test_build_validated_passes() {
        #[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
        struct TestConfig {
            port: u16,
            max_connections: u16,
        }

        let defaults = TestConfig {
            port: 8080,
            max_connections: 100,
        };

        let config: TestConfig = ConfigBuilder::new()
            .with_defaults(defaults)
            .build_validated(|c: &TestConfig| {
                if c.port == 0 {
                    return Err(ConfigError::validation("port", "range", "must be > 0"));
                }
                Ok(())
            })
            .unwrap();

        assert_eq!(config.port, 8080);
        assert_eq!(config.max_connections, 100);
    }

    #[test]
    fn test_build_validated_fails() {
        #[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
        struct TestConfig {
            port: u16,
        }

        let defaults = TestConfig { port: 0 }; // Invalid!

        let result: Result<TestConfig, _> = ConfigBuilder::new()
            .with_defaults(defaults)
            .build_validated(|c: &TestConfig| {
                if c.port == 0 {
                    return Err(ConfigError::validation("port", "range", "must be > 0"));
                }
                Ok(())
            });

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ConfigError::ValidationFailed { .. }));
    }

    #[test]
    fn test_build_validated_cross_field() {
        #[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
        struct TestConfig {
            timeout_secs: u32,
            retry_count: u32,
        }

        // Invalid: timeout should be >= retry_count
        let defaults = TestConfig {
            timeout_secs: 5,
            retry_count: 10, // More retries than timeout allows
        };

        let result: Result<TestConfig, _> = ConfigBuilder::new()
            .with_defaults(defaults)
            .build_validated(|c: &TestConfig| {
                if c.timeout_secs < c.retry_count {
                    return Err(ConfigError::validation(
                        "timeout_secs",
                        "consistency",
                        "timeout must be >= retry_count",
                    ));
                }
                Ok(())
            });

        assert!(result.is_err());
    }

    #[test]
    fn test_build_validated_with_file() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        #[derive(Debug, serde::Deserialize)]
        struct TestConfig {
            port: u16,
            host: String,
        }

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "port = 9000").unwrap();
        writeln!(file, r#"host = "example.com""#).unwrap();

        let config: TestConfig = ConfigBuilder::new()
            .with_file(file.path())
            .unwrap()
            .build_validated(|c: &TestConfig| {
                if c.host.is_empty() {
                    return Err(ConfigError::validation(
                        "host",
                        "required",
                        "cannot be empty",
                    ));
                }
                Ok(())
            })
            .unwrap();

        assert_eq!(config.port, 9000);
        assert_eq!(config.host, "example.com");
    }

    #[test]
    fn test_build_validated_nested_struct() {
        #[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
        struct DatabaseConfig {
            url: String,
            max_pool_size: u32,
        }

        #[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
        struct AppConfig {
            database: DatabaseConfig,
            port: u16,
        }

        let defaults = AppConfig {
            database: DatabaseConfig {
                url: String::new(), // Empty URL - invalid
                max_pool_size: 10,
            },
            port: 8080,
        };

        let result: Result<AppConfig, _> = ConfigBuilder::new()
            .with_defaults(defaults)
            .build_validated(|c: &AppConfig| {
                if c.database.url.is_empty() {
                    return Err(ConfigError::validation(
                        "database.url",
                        "required",
                        "cannot be empty",
                    ));
                }
                Ok(())
            });

        assert!(result.is_err());
        let err = result.unwrap_err();
        // Verify error message contains field path
        assert!(err.to_string().contains("database.url"));
    }
}

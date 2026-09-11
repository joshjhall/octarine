//! Configuration builder for loading from environment and files
//!
//! The batch-loading accumulators (`require`/`optional`/`secret`/`load`) live
//! in `batch.rs`, and the resulting [`LoadedConfig`](super::loaded::LoadedConfig)
//! in `loaded.rs`.

use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::crypto::secrets::{Classification, SecretType, TypedSecret};
use crate::observe;
use crate::observe::metrics::{MetricName, increment_by, record};

use super::error::ConfigError;
use super::figment_adapter::FigmentAdapter;
use super::value::ConfigValue;

crate::define_metrics! {
    pub(super)
    build_ms => "runtime.config.build_ms",
    load_ms => "runtime.config.load_ms",
    configs_built => "runtime.config.configs_built",
    configs_loaded => "runtime.config.configs_loaded",
}

/// Builder for loading configuration from environment variables and files
///
/// Provides a fluent API for loading, validating, and converting
/// environment variables with prefix support and audit logging.
///
/// # Examples
///
/// ## Single-value API (environment variables)
///
/// Pre-existing example - ignored at compile until adapted.
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
/// Pre-existing example - ignored at compile until adapted.
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
    pub(super) prefix: Option<String>,
    /// Separator between prefix and name (default: "_")
    pub(super) separator: String,
    /// Loaded values (for batch operations)
    pub(super) values: HashMap<String, LoadedValue>,
    /// Names of secret fields (values will be masked in logs)
    pub(super) secrets: Vec<String>,
    /// Config files to load (in order)
    files: Vec<PathBuf>,
    /// Serialized defaults for struct-based config
    defaults_json: Option<serde_json::Value>,
    /// Whether to emit events and record metrics
    emit_events: bool,
}

#[derive(Debug, Clone)]
pub(super) struct LoadedValue {
    pub(super) raw: Option<String>,
    pub(super) is_secret: bool,
    pub(super) is_required: bool,
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
    /// Pre-existing example - ignored at compile until adapted.
    /// ```ignore
    /// let builder = ConfigBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            prefix: None,
            separator: "_".to_string(),
            values: HashMap::new(),
            secrets: Vec::new(),
            files: Vec::new(),
            defaults_json: None,
            emit_events: true,
        }
    }

    /// Create a builder that emits no events and records no metrics
    ///
    /// Config loading logs variable names and non-secret values; use this for
    /// bulk or sensitive loads that must not reach the audit trail.
    #[must_use]
    pub fn silent() -> Self {
        Self {
            emit_events: false,
            ..Self::new()
        }
    }

    /// Enable or disable observe events and metrics
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    /// Emit a debug event when events are enabled.
    pub(super) fn log_debug(&self, operation: &str, message: impl Into<String>) {
        if self.emit_events {
            observe::debug(operation, message.into());
        }
    }

    /// Emit a warning when events are enabled.
    pub(super) fn log_warn(&self, operation: &str, message: impl Into<String>) {
        if self.emit_events {
            observe::warn(operation, message.into());
        }
    }

    /// Emit an info event when events are enabled.
    pub(super) fn log_info(&self, operation: &str, message: impl Into<String>) {
        if self.emit_events {
            observe::info(operation, message.into());
        }
    }

    /// Record duration and a success count for a completed operation.
    pub(super) fn record_operation(&self, duration: MetricName, count: MetricName, start: Instant) {
        if self.emit_events {
            record(duration, start.elapsed().as_micros() as f64 / 1000.0);
            increment_by(count, 1);
        }
    }

    /// Set the prefix for environment variable names
    ///
    /// When a prefix is set, `get("PORT")` will look for `PREFIX_PORT`.
    ///
    /// # Example
    ///
    /// Pre-existing example - ignored at compile until adapted.
    /// ```ignore
    /// let builder = ConfigBuilder::new().with_prefix("APP");
    /// // get("PORT") will look for APP_PORT
    /// ```
    #[must_use]
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        let prefix = prefix.into();
        self.log_debug("runtime.config", format!("Setting prefix: {}", prefix));
        self.prefix = Some(prefix);
        self
    }

    /// Set the separator between prefix and name (default: "_")
    ///
    /// # Example
    ///
    /// Pre-existing example - ignored at compile until adapted.
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
    /// Pre-existing example - ignored at compile until adapted.
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
        self.log_debug("runtime.config", "Set configuration defaults");
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
    /// Pre-existing example - ignored at compile until adapted.
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
        self.log_debug(
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
    /// Pre-existing example - ignored at compile until adapted.
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
            self.log_debug(
                "runtime.config",
                format!("Adding optional config file: {}", path.display()),
            );
            self.files.push(path.to_path_buf());
        } else {
            self.log_debug(
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
    /// Pre-existing example - ignored at compile until adapted.
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

        use crate::primitives::io::file::FileMode;

        let path = path.as_ref();
        if !path.exists() {
            return Err(ConfigError::file_error(path, "file not found"));
        }

        // Check permissions - must be 0600 (owner read/write only)
        let metadata =
            std::fs::metadata(path).map_err(|e| ConfigError::file_error(path, e.to_string()))?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != FileMode::PRIVATE.as_raw() {
            return Err(ConfigError::insecure_permissions(
                path,
                "0600 (owner read/write only)",
                format!("{:04o}", mode),
            ));
        }

        self.log_debug(
            "runtime.config",
            format!("Adding secure config file: {}", path.display()),
        );
        self.files.push(path.to_path_buf());
        Ok(self)
    }

    /// Add a config file with a best-effort security check (non-Unix).
    ///
    /// On Windows, Unix-style file modes are not available. This method checks
    /// that the file is not marked read-only (which would indicate a different
    /// access model) but cannot enforce owner-only access. Callers on Windows
    /// should secure config files via directory-level ACLs.
    #[cfg(not(unix))]
    pub fn with_secure_file(mut self, path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(ConfigError::file_error(path, "file not found"));
        }

        self.log_warn(
            "runtime.config",
            format!(
                "Adding config file on non-Unix platform: Unix mode 0600 enforcement unavailable, caller must secure via directory-level ACLs: {}",
                path.display()
            ),
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
    /// Pre-existing example - ignored at compile until adapted.
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
    pub fn build_struct<T>(mut self) -> Result<T, ConfigError>
    where
        T: DeserializeOwned,
    {
        let start = Instant::now();
        let mut adapter = FigmentAdapter::new();

        // Layer 1: Defaults (lowest priority)
        if let Some(defaults) = self.defaults_json.take() {
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

        self.record_operation(
            metric_names::build_ms(),
            metric_names::configs_built(),
            start,
        );
        self.log_info(
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
    /// Pre-existing example - ignored at compile until adapted.
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
    /// Pre-existing example - ignored at compile until adapted.
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
    /// Pre-existing example - ignored at compile until adapted.
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
    /// Pre-existing example - ignored at compile until adapted.
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
    /// Pre-existing example - ignored at compile until adapted.
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
    /// Pre-existing example - ignored at compile until adapted.
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
            self.log_debug(
                "runtime.config.get",
                format!("Loading secret: {} (set: {})", full_name, value.is_some()),
            );
        } else {
            self.log_debug(
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
    pub(super) fn full_name(&self, name: &str) -> String {
        match &self.prefix {
            Some(prefix) => {
                let prefix_with_sep = format!("{}{}", prefix, self.separator);

                // Check for potential double-prefixing
                if name.starts_with(&prefix_with_sep) {
                    self.log_warn(
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
    use crate::observe::metrics::{flush_for_testing, snapshot};

    /// Serializes metrics-touching tests in this file against the shared
    /// global registry.
    static METRICS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn histogram_count(name: &str) -> u64 {
        snapshot().histograms.get(name).map_or(0, |h| h.count)
    }

    fn counter_value(name: &str) -> u64 {
        snapshot().counters.get(name).map_or(0, |c| c.value)
    }

    // ========================================================================
    // Observability
    // ========================================================================

    #[test]
    fn test_builder_event_flags() {
        assert!(ConfigBuilder::new().emit_events);
        assert!(!ConfigBuilder::silent().emit_events);
        assert!(!ConfigBuilder::new().with_events(false).emit_events);
        assert!(ConfigBuilder::silent().with_events(true).emit_events);
        // Default must route through new(), not derive a `false` flag.
        assert!(ConfigBuilder::default().emit_events);
    }

    #[test]
    fn test_silent_builder_preserves_behavior() {
        // Disabling events must not change what the builder resolves.
        let loud = ConfigBuilder::new()
            .with_prefix("OCTARINE_TEST_SILENT_XYZ")
            .get("VALUE")
            .unwrap();
        let quiet = ConfigBuilder::silent()
            .with_prefix("OCTARINE_TEST_SILENT_XYZ")
            .get("VALUE")
            .unwrap();

        assert_eq!(loud.is_set(), quiet.is_set());
        assert_eq!(loud.name(), quiet.name());
    }

    #[test]
    fn test_load_records_metrics() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        flush_for_testing();
        let before = histogram_count("runtime.config.load_ms");
        let loaded_before = counter_value("runtime.config.configs_loaded");

        ConfigBuilder::new()
            .with_prefix("OCTARINE_TEST_METRICS_XYZ")
            .optional("VALUE")
            .load()
            .expect("optional value makes load succeed");
        flush_for_testing();

        assert!(
            histogram_count("runtime.config.load_ms") > before,
            "load() must record load_ms",
        );
        assert_eq!(
            counter_value("runtime.config.configs_loaded"),
            loaded_before.saturating_add(1),
            "load() must also increment configs_loaded, not just time it",
        );
    }

    #[test]
    fn test_silent_load_records_no_metrics() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        flush_for_testing();
        let before = histogram_count("runtime.config.load_ms");
        let loaded_before = counter_value("runtime.config.configs_loaded");

        let loaded = ConfigBuilder::silent()
            .with_prefix("OCTARINE_TEST_METRICS_XYZ")
            .optional("VALUE")
            .load()
            .expect("silent load still succeeds");
        flush_for_testing();

        assert_eq!(loaded.len(), 1, "silent must not skip the actual work");
        assert_eq!(
            histogram_count("runtime.config.load_ms"),
            before,
            "silent() must not record load_ms",
        );
        assert_eq!(
            counter_value("runtime.config.configs_loaded"),
            loaded_before,
            "silent() must not increment configs_loaded",
        );
    }

    #[test]
    fn test_build_struct_records_metrics() {
        #[derive(Debug, serde::Deserialize, serde::Serialize, Default, PartialEq)]
        struct TestConfig {
            port: u16,
        }

        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        flush_for_testing();
        let before = histogram_count("runtime.config.build_ms");
        let built_before = counter_value("runtime.config.configs_built");

        let config: TestConfig = ConfigBuilder::new()
            .with_defaults(TestConfig { port: 8080 })
            .build_struct()
            .expect("build_struct");
        flush_for_testing();

        // Defaults must still flow through after the `take()` refactor.
        assert_eq!(config, TestConfig { port: 8080 });
        assert!(
            histogram_count("runtime.config.build_ms") > before,
            "build_struct() must record build_ms",
        );
        assert_eq!(
            counter_value("runtime.config.configs_built"),
            built_before.saturating_add(1),
            "build_struct() must also increment configs_built",
        );
    }

    #[test]
    fn test_failed_build_struct_does_not_count() {
        #[derive(Debug, serde::Deserialize)]
        struct StrictConfig {
            #[allow(dead_code)]
            port: u16,
        }

        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        flush_for_testing();
        let built_before = counter_value("runtime.config.configs_built");

        // No defaults and no source for `port`, so extraction fails.
        let result: Result<StrictConfig, _> = ConfigBuilder::new().build_struct();
        assert!(result.is_err(), "a missing required field must fail");
        flush_for_testing();

        assert_eq!(
            counter_value("runtime.config.configs_built"),
            built_before,
            "a failed build_struct must not increment configs_built",
        );
    }

    #[test]
    fn test_silent_build_struct_records_no_metrics() {
        #[derive(Debug, serde::Deserialize, serde::Serialize, Default, PartialEq)]
        struct TestConfig {
            port: u16,
        }

        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        flush_for_testing();
        let before = histogram_count("runtime.config.build_ms");
        let built_before = counter_value("runtime.config.configs_built");

        let config: TestConfig = ConfigBuilder::silent()
            .with_defaults(TestConfig { port: 9090 })
            .build_struct()
            .expect("silent build_struct");
        flush_for_testing();

        assert_eq!(config, TestConfig { port: 9090 });
        assert_eq!(
            histogram_count("runtime.config.build_ms"),
            before,
            "silent() must not record build_ms",
        );
        assert_eq!(
            counter_value("runtime.config.configs_built"),
            built_before,
            "silent() must not increment configs_built",
        );
    }

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
    fn test_secret_is_both_secret_and_required() {
        // secret() is the only accumulator setting is_secret AND is_required
        // together; optional_secret() and require() each set only one.
        let missing = ConfigBuilder::new()
            .with_prefix("OCTARINE_TEST_REQ_SECRET_XYZ")
            .secret("API_KEY")
            .load();

        // Required half: an unset secret must fail the load.
        assert!(
            matches!(missing, Err(ConfigError::Missing { .. })),
            "an unset secret() value must fail load() as missing, got {missing:?}",
        );

        // Secret half: optional_secret is the same minus required, so it
        // loads — and must still be marked secret.
        let present = ConfigBuilder::new()
            .with_prefix("OCTARINE_TEST_REQ_SECRET_XYZ")
            .optional_secret("API_KEY")
            .load()
            .expect("optional_secret loads when unset");
        assert!(present.get("API_KEY").is_secret());
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

//! Batch-loading API for `ConfigBuilder`
//!
//! The `require`/`optional`/`secret`/`optional_secret` accumulators plus the
//! terminal `load()` that turns them into a [`LoadedConfig`]. Split out of
//! `builder.rs` to keep that file within its production-LOC budget.

use std::env;
use std::time::Instant;

use super::builder::{ConfigBuilder, LoadedValue, metric_names};
use super::error::ConfigError;
use super::loaded::LoadedConfig;

impl ConfigBuilder {
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

        self.log_debug(
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

        self.log_debug(
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

        self.log_debug(
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

        self.log_debug(
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
        let start = Instant::now();

        // Check for missing required values
        for (name, loaded) in &self.values {
            if loaded.is_required && loaded.raw.is_none() {
                let full_name = self.full_name(name);
                self.log_warn(
                    "runtime.config.build",
                    format!("Missing required config: {}", full_name),
                );
                return Err(ConfigError::missing(full_name));
            }
        }

        let count = self.values.len();
        let secret_count = self.secrets.len();
        self.record_operation(
            metric_names::load_ms(),
            metric_names::configs_loaded(),
            start,
        );
        self.log_info(
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

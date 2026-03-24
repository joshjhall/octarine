//! Internal figment adapter (not exposed publicly)
//!
//! This module wraps figment to provide the internal implementation
//! for file-based configuration loading. Apps use the public ConfigBuilder
//! API, not this module directly.

use std::path::Path;

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::ConfigError;
use crate::observe;

/// Internal adapter wrapping figment
///
/// This is used by `ConfigBuilder::build_struct()` to merge configuration
/// from multiple sources with proper layering.
#[derive(Debug)]
pub(super) struct FigmentAdapter {
    figment: Figment,
    file_count: usize,
    has_defaults: bool,
    has_env: bool,
}

impl FigmentAdapter {
    /// Create a new empty figment adapter
    pub fn new() -> Self {
        Self {
            figment: Figment::new(),
            file_count: 0,
            has_defaults: false,
            has_env: false,
        }
    }

    /// Add struct defaults (lowest priority)
    pub fn with_defaults<T: Serialize>(mut self, defaults: T) -> Self {
        self.figment = self.figment.merge(Serialized::defaults(defaults));
        self.has_defaults = true;
        observe::debug(
            "config.figment",
            "Added struct defaults to configuration sources",
        );
        self
    }

    /// Add a required config file (middle priority)
    pub fn with_file(mut self, path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::file_error(path, "file not found"));
        }
        observe::debug(
            "config.figment",
            format!("Loading config file: {}", path.display()),
        );
        self.figment = self.figment.merge(Toml::file(path));
        self.file_count = self.file_count.saturating_add(1);
        Ok(self)
    }

    /// Add environment variables (highest priority)
    ///
    /// The prefix should not include the separator - it will be added automatically.
    /// For example, `with_env("APP", "_")` will match `APP_PORT`, `APP_HOST`, etc.
    pub fn with_env(mut self, prefix: &str, separator: &str) -> Self {
        // Build full prefix with separator (figment expects "APP_" not "APP")
        let full_prefix = format!("{prefix}{separator}");
        observe::debug(
            "config.figment",
            format!(
                "Adding env vars with prefix '{}' and separator '{}'",
                full_prefix, separator
            ),
        );
        self.figment = self
            .figment
            .merge(Env::prefixed(&full_prefix).split(separator));
        self.has_env = true;
        self
    }

    /// Extract configuration to target struct
    pub fn extract<T: DeserializeOwned>(self) -> Result<T, ConfigError> {
        observe::debug(
            "config.figment",
            format!(
                "Extracting config: {} file(s), defaults={}, env={}",
                self.file_count, self.has_defaults, self.has_env
            ),
        );
        self.figment.extract().map_err(ConfigError::from)
    }

    /// Get the number of files loaded
    pub fn file_count(&self) -> usize {
        self.file_count
    }
}

impl Default for FigmentAdapter {
    fn default() -> Self {
        Self::new()
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

    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Default)]
    struct TestConfig {
        port: u16,
        host: String,
    }

    #[test]
    fn test_new_adapter() {
        let adapter = FigmentAdapter::new();
        assert_eq!(adapter.file_count(), 0);
    }

    #[test]
    fn test_with_defaults() {
        let defaults = TestConfig {
            port: 8080,
            host: "localhost".to_string(),
        };
        let adapter = FigmentAdapter::new().with_defaults(defaults);
        let config: TestConfig = adapter.extract().unwrap();
        assert_eq!(config.port, 8080);
        assert_eq!(config.host, "localhost");
    }

    #[test]
    fn test_with_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "port = 9000").unwrap();
        writeln!(file, r#"host = "example.com""#).unwrap();

        let adapter = FigmentAdapter::new().with_file(file.path()).unwrap();
        assert_eq!(adapter.file_count(), 1);

        let config: TestConfig = adapter.extract().unwrap();
        assert_eq!(config.port, 9000);
        assert_eq!(config.host, "example.com");
    }

    #[test]
    fn test_with_file_not_found() {
        let result = FigmentAdapter::new().with_file(Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::FileError { .. }));
    }

    #[test]
    fn test_file_overrides_defaults() {
        let defaults = TestConfig {
            port: 8080,
            host: "default-host".to_string(),
        };

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "port = 9090").unwrap();
        // host not in file, should use default

        let config: TestConfig = FigmentAdapter::new()
            .with_defaults(defaults)
            .with_file(file.path())
            .unwrap()
            .extract()
            .unwrap();

        assert_eq!(config.port, 9090); // From file
        assert_eq!(config.host, "default-host"); // From defaults
    }

    #[test]
    fn test_env_overrides_file() {
        use figment::Jail;

        Jail::expect_with(|jail| {
            jail.set_env("FIGTEST_PORT", "9999");
            jail.create_file(
                "config.toml",
                r#"
                port = 8080
                host = "file-host"
                "#,
            )?;

            let config: TestConfig = FigmentAdapter::new()
                .with_file(std::path::Path::new("config.toml"))
                .expect("config file should exist")
                .with_env("FIGTEST", "_")
                .extract()
                .expect("config should extract");

            assert_eq!(config.port, 9999); // From env
            assert_eq!(config.host, "file-host"); // From file
            Ok(())
        });
    }

    #[test]
    fn test_layering_order() {
        use figment::Jail;

        Jail::expect_with(|jail| {
            jail.set_env("LAYERTEST_PORT", "3000");
            jail.create_file(
                "config.toml",
                r#"
                port = 2000
                host = "file"
                "#,
            )?;

            let defaults = TestConfig {
                port: 1000,
                host: "default".to_string(),
            };

            let config: TestConfig = FigmentAdapter::new()
                .with_defaults(defaults)
                .with_file(std::path::Path::new("config.toml"))
                .expect("config file should exist")
                .with_env("LAYERTEST", "_")
                .extract()
                .expect("config should extract");

            assert_eq!(config.port, 3000); // Env wins
            assert_eq!(config.host, "file"); // File wins over defaults
            Ok(())
        });
    }
}

//! Integration tests for the Config derive macro.
//!
//! These tests verify that the generated code works correctly at runtime.
//! Uses figment's Jail for safe environment variable isolation.

#![cfg(feature = "derive")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use figment::Jail;
use octarine::Config;

/// Simple config struct for testing.
#[derive(Config, Debug, PartialEq)]
#[config(prefix = "TEST_DERIVE")]
struct SimpleConfig {
    /// Port with default value.
    #[config(default = "8080")]
    port: u16,

    /// Host without default (required).
    host: String,

    /// Optional field.
    #[config(env = "TEST_DERIVE_LOG_LEVEL")]
    log_level: Option<String>,
}

/// Config with custom separator.
#[derive(Config, Debug)]
#[config(prefix = "APP", separator = "__")]
struct CustomSeparatorConfig {
    #[config(default = "localhost")]
    host: String,
}

/// Config with skip field.
#[derive(Config, Debug, Default)]
#[config(prefix = "SKIP_TEST")]
struct SkipConfig {
    #[config(default = "value")]
    regular: String,

    #[config(skip)]
    skipped: i32,
}

/// Config with secret field.
#[derive(Config, Debug)]
#[config(prefix = "SECRET_TEST")]
struct SecretConfig {
    #[config(secret)]
    api_key: String,
}

/// Config with rename.
#[derive(Config, Debug)]
#[config(prefix = "RENAME_TEST")]
struct RenameConfig {
    #[config(rename = "DATABASE_URL")]
    db_url: String,
}

mod simple_tests {
    use super::*;

    #[test]
    fn test_load_with_defaults() {
        Jail::expect_with(|jail| {
            jail.set_env("TEST_DERIVE_HOST", "localhost");

            let config = SimpleConfig::load().expect("should load");
            assert_eq!(config.port, 8080); // Default
            assert_eq!(config.host, "localhost");
            assert_eq!(config.log_level, None);
            Ok(())
        });
    }

    #[test]
    fn test_env_overrides_default() {
        Jail::expect_with(|jail| {
            jail.set_env("TEST_DERIVE_HOST", "example.com");
            jail.set_env("TEST_DERIVE_PORT", "9090");

            let config = SimpleConfig::load().expect("should load");
            assert_eq!(config.port, 9090); // Overridden
            assert_eq!(config.host, "example.com");
            Ok(())
        });
    }

    #[test]
    fn test_custom_env_name() {
        Jail::expect_with(|jail| {
            jail.set_env("TEST_DERIVE_HOST", "localhost");
            jail.set_env("TEST_DERIVE_LOG_LEVEL", "debug");

            let config = SimpleConfig::load().expect("should load");
            assert_eq!(config.log_level, Some("debug".to_string()));
            Ok(())
        });
    }

    #[test]
    fn test_missing_required_field() {
        Jail::expect_with(|_jail| {
            // Don't set TEST_DERIVE_HOST
            let result = SimpleConfig::load();
            assert!(result.is_err());
            Ok(())
        });
    }
}

mod separator_tests {
    use super::*;

    #[test]
    fn test_custom_separator() {
        Jail::expect_with(|jail| {
            jail.set_env("APP__HOST", "custom.host");

            let config = CustomSeparatorConfig::load().expect("should load");
            assert_eq!(config.host, "custom.host");
            Ok(())
        });
    }
}

mod skip_tests {
    use super::*;

    #[test]
    fn test_skip_uses_default() {
        Jail::expect_with(|jail| {
            jail.set_env("SKIP_TEST_REGULAR", "test");

            let config = SkipConfig::load().expect("should load");
            assert_eq!(config.regular, "test");
            assert_eq!(config.skipped, 0); // Default::default()
            Ok(())
        });
    }
}

mod secret_tests {
    use super::*;

    #[test]
    fn test_secret_field() {
        Jail::expect_with(|jail| {
            jail.set_env("SECRET_TEST_API_KEY", "secret123");

            let config = SecretConfig::load().expect("should load");
            assert_eq!(config.api_key, "secret123");
            Ok(())
        });
    }
}

mod rename_tests {
    use super::*;

    #[test]
    fn test_rename_field() {
        Jail::expect_with(|jail| {
            jail.set_env("RENAME_TEST_DATABASE_URL", "postgres://localhost/db");

            let config = RenameConfig::load().expect("should load");
            assert_eq!(config.db_url, "postgres://localhost/db");
            Ok(())
        });
    }
}

mod load_with_prefix_tests {
    use super::*;

    #[test]
    fn test_load_with_custom_prefix() {
        Jail::expect_with(|jail| {
            jail.set_env("CUSTOM_PREFIX_HOST", "custom.localhost");

            let config = SimpleConfig::load_with_prefix("CUSTOM_PREFIX").expect("should load");
            assert_eq!(config.port, 8080); // Default still works
            assert_eq!(config.host, "custom.localhost");
            Ok(())
        });
    }
}

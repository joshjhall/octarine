//! Derive macros for octarine configuration.
//!
//! This crate provides the `#[derive(Config)]` macro for generating
//! type-safe configuration loading code.
//!
//! # Example
//!
//! ```ignore
//! use octarine::Config;
//! use octarine::crypto::secrets::TypedSecret;
//!
//! #[derive(Config)]
//! #[config(prefix = "APP")]
//! pub struct AppConfig {
//!     /// Server port (defaults to 8080)
//!     #[config(default = "8080")]
//!     pub port: u16,
//!
//!     /// Database URL (required secret)
//!     #[config(secret)]
//!     pub database_url: String,
//!
//!     /// Optional log level
//!     #[config(env = "LOG_LEVEL")]
//!     pub log_level: Option<String>,
//! }
//!
//! // Generated impl provides:
//! // - AppConfig::load() -> Result<Self, ConfigError>
//! // - AppConfig::load_with_prefix(prefix: &str) -> Result<Self, ConfigError>
//! ```
//!
//! # Struct-Level Attributes
//!
//! | Attribute | Description |
//! |-----------|-------------|
//! | `prefix = "X"` | Environment variable prefix (e.g., "APP" → "APP_PORT") |
//! | `separator = "X"` | Separator between prefix and field name (default: "_") |
//! | `file = "path"` | Optional config file path |
//!
//! # Field-Level Attributes
//!
//! | Attribute | Description |
//! |-----------|-------------|
//! | `default = "X"` | Default value if not set |
//! | `env = "X"` | Custom env var name (overrides auto-generated) |
//! | `secret` | Mark as secret (masked in logs) |
//! | `typed_secret` | Use TypedSecret wrapper |
//! | `classification = "X"` | Set classification (public/internal/confidential/restricted) |
//! | `secret_type = "X"` | Set secret type (ApiKey/Password/etc.) |
//! | `flatten` | Flatten nested struct |
//! | `nested_prefix = "X"` | Prefix for flattened struct |
//! | `skip` | Skip this field (must impl Default) |
//! | `rename = "X"` | Rename field for env var lookup |

mod config;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

/// Derive macro for configuration loading.
///
/// Generates `load()` and `load_with_prefix()` methods that use
/// octarine's ConfigBuilder internally.
///
/// See the [crate-level documentation](crate) for usage examples.
#[proc_macro_derive(Config, attributes(config))]
pub fn derive_config(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    config::expand_config(input)
        .unwrap_or_else(|err| err.write_errors())
        .into()
}

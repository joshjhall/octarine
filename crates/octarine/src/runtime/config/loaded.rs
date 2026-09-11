//! Loaded configuration ready for value extraction
//!
//! [`LoadedConfig`] is produced by [`ConfigBuilder::load`] once all required
//! values are present. It holds the raw values and hands out [`ConfigValue`]
//! wrappers for typed conversion.
//!
//! [`ConfigBuilder::load`]: super::builder::ConfigBuilder::load

use std::collections::HashMap;

use super::builder::LoadedValue;
use super::value::ConfigValue;

/// A loaded configuration ready for value extraction
///
/// Created by [`ConfigBuilder::load()`](super::builder::ConfigBuilder::load).
#[derive(Debug)]
pub struct LoadedConfig {
    pub(super) prefix: Option<String>,
    pub(super) separator: String,
    pub(super) values: HashMap<String, LoadedValue>,
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

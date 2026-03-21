//! PrimitiveSecureMap - A secure map for storing secrets
//!
//! A HashMap-like type that stores secrets with automatic masking and zeroization.
//! This is the Layer 1 primitive without observability - use
//! `octarine::crypto::secrets::SecureMap` for the instrumented version.
//!
//! # Features
//!
//! - **Masked Debug/Display**: All values show as `[REDACTED]`
//! - **Memory zeroization**: Values are zeroized on drop
//! - **Type-safe**: Values stored as `SecretStringCore`
//!
//! # Example
//!
//! ```ignore
//! use crate::primitives::crypto::secrets::PrimitiveSecureMap;
//!
//! let mut secrets = PrimitiveSecureMap::new();
//! secrets.insert("API_KEY", "sk-12345");
//! secrets.insert("DB_PASSWORD", "hunter2");
//!
//! // Safe to log - values are masked
//! println!("{:?}", secrets);  // PrimitiveSecureMap { API_KEY: [REDACTED], DB_PASSWORD: [REDACTED] }
//!
//! // Explicit access
//! if let Some(key) = secrets.get("API_KEY") {
//!     assert_eq!(key, "sk-12345");
//! }
//! ```

// Allow dead_code: Layer 1 primitives used by Layer 2/3
#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt;

use super::{ExposeSecretCore, SecretCore, SecretStringCore};

/// A secure map for storing named secrets (Layer 1 primitive)
///
/// Values are stored as `SecretStringCore` which provides:
/// - Automatic zeroization on drop
/// - Safe Debug output (values show as `[REDACTED]`)
/// - Explicit access via `get()`
///
/// This is the primitive version without observability instrumentation.
/// For the instrumented version, use `octarine::crypto::secrets::SecureMap`.
///
/// # Thread Safety
///
/// `PrimitiveSecureMap` is not `Sync` by default. For concurrent access,
/// wrap in `Arc<Mutex<PrimitiveSecureMap>>` or use `Arc<RwLock<PrimitiveSecureMap>>`.
///
/// # Example
///
/// ```ignore
/// use crate::primitives::crypto::secrets::PrimitiveSecureMap;
///
/// let mut secrets = PrimitiveSecureMap::new();
/// secrets.insert("DB_URL", "postgres://user:pass@host/db");
///
/// // Get returns the actual value
/// let url = secrets.get("DB_URL").expect("DB_URL not found");
/// ```
pub struct PrimitiveSecureMap {
    inner: HashMap<String, SecretStringCore>,
}

impl PrimitiveSecureMap {
    /// Create a new empty PrimitiveSecureMap
    ///
    /// # Example
    ///
    /// ```ignore
    /// use crate::primitives::crypto::secrets::PrimitiveSecureMap;
    ///
    /// let secrets = PrimitiveSecureMap::new();
    /// assert!(secrets.is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Create a PrimitiveSecureMap with the specified capacity
    ///
    /// # Arguments
    ///
    /// * `capacity` - Initial capacity for the map
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: HashMap::with_capacity(capacity),
        }
    }

    /// Insert a secret into the map
    ///
    /// If the key already exists, the old value is replaced and zeroized.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to insert
    /// * `value` - The secret value (will be wrapped in `SecretStringCore`)
    ///
    /// # Returns
    ///
    /// The previous value if the key existed, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut secrets = PrimitiveSecureMap::new();
    /// secrets.insert("API_KEY", "sk-12345");
    ///
    /// // Overwrite returns the old value
    /// let old = secrets.insert("API_KEY", "sk-67890");
    /// assert_eq!(old, Some("sk-12345".to_string()));
    /// ```
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) -> Option<String> {
        let key = key.into();
        let value = value.into();
        let old = self.inner.insert(key, SecretCore::new(value));
        old.map(|s: SecretStringCore| s.into_inner())
    }

    /// Get a reference to a secret value
    ///
    /// # Arguments
    ///
    /// * `key` - The key to look up
    ///
    /// # Returns
    ///
    /// The secret value if found, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut secrets = PrimitiveSecureMap::new();
    /// secrets.insert("TOKEN", "abc123");
    ///
    /// assert_eq!(secrets.get("TOKEN"), Some(&"abc123".to_string()));
    /// assert_eq!(secrets.get("MISSING"), None);
    /// ```
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&String> {
        self.inner.get(key).map(|s| s.expose_secret())
    }

    /// Remove a secret from the map
    ///
    /// The removed value is returned and should be handled securely.
    /// The value in the map is zeroized.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to remove
    ///
    /// # Returns
    ///
    /// The removed value if the key existed, `None` otherwise.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.inner.remove(key).map(|s| s.into_inner())
    }

    /// Check if the map contains a key
    ///
    /// # Arguments
    ///
    /// * `key` - The key to check
    #[must_use]
    pub fn is_key_present(&self, key: &str) -> bool {
        self.inner.contains_key(key)
    }

    /// Get the number of secrets in the map
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the map is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get an iterator over the keys
    ///
    /// Only keys are exposed, not values.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.inner.keys()
    }

    /// Clear all secrets from the map
    ///
    /// All values are zeroized.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Iterate over key-value pairs with exposed secrets
    ///
    /// **Warning**: This exposes all secret values. Use with caution.
    ///
    /// # Example
    ///
    /// ```ignore
    /// for (key, value) in secrets.iter() {
    ///     // value is the actual secret string
    /// }
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.inner.iter().map(|(k, v)| (k, v.expose_secret()))
    }

    /// Extend the map from an iterator
    ///
    /// # Arguments
    ///
    /// * `iter` - Iterator of key-value pairs
    pub fn extend<I, K, V>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in iter {
            self.insert(k, v);
        }
    }
}

impl Default for PrimitiveSecureMap {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PrimitiveSecureMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrimitiveSecureMap { ")?;
        let mut first = true;
        for key in self.inner.keys() {
            if !first {
                f.write_str(", ")?;
            }
            write!(f, "{}: [REDACTED]", key)?;
            first = false;
        }
        f.write_str(" }")
    }
}

impl fmt::Display for PrimitiveSecureMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrimitiveSecureMap({} secrets)", self.inner.len())
    }
}

impl Clone for PrimitiveSecureMap {
    fn clone(&self) -> Self {
        let mut new_map = PrimitiveSecureMap::with_capacity(self.inner.len());
        for (k, v) in &self.inner {
            new_map
                .inner
                .insert(k.clone(), SecretCore::new(v.expose_secret().clone()));
        }
        new_map
    }
}

impl<K, V> FromIterator<(K, V)> for PrimitiveSecureMap
where
    K: Into<String>,
    V: Into<String>,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = PrimitiveSecureMap::new();
        map.extend(iter);
        map
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_new() {
        let map = PrimitiveSecureMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_insert_and_get() {
        let mut map = PrimitiveSecureMap::new();
        map.insert("API_KEY", "sk-12345");

        assert_eq!(map.get("API_KEY"), Some(&"sk-12345".to_string()));
        assert_eq!(map.get("MISSING"), None);
    }

    #[test]
    fn test_insert_overwrites() {
        let mut map = PrimitiveSecureMap::new();
        map.insert("KEY", "value1");
        let old = map.insert("KEY", "value2");

        assert_eq!(old, Some("value1".to_string()));
        assert_eq!(map.get("KEY"), Some(&"value2".to_string()));
    }

    #[test]
    fn test_remove() {
        let mut map = PrimitiveSecureMap::new();
        map.insert("KEY", "value");

        let removed = map.remove("KEY");
        assert_eq!(removed, Some("value".to_string()));
        assert!(map.is_empty());
    }

    #[test]
    fn test_is_key_present() {
        let mut map = PrimitiveSecureMap::new();
        map.insert("KEY", "value");

        assert!(map.is_key_present("KEY"));
        assert!(!map.is_key_present("MISSING"));
    }

    #[test]
    fn test_debug_redacted() {
        let mut map = PrimitiveSecureMap::new();
        map.insert("API_KEY", "secret-value");

        let debug = format!("{:?}", map);
        assert!(debug.contains("API_KEY"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret-value"));
    }

    #[test]
    fn test_display() {
        let mut map = PrimitiveSecureMap::new();
        map.insert("KEY1", "value1");
        map.insert("KEY2", "value2");

        let display = format!("{}", map);
        assert_eq!(display, "PrimitiveSecureMap(2 secrets)");
    }

    #[test]
    fn test_clone() {
        let mut map = PrimitiveSecureMap::new();
        map.insert("KEY", "value");

        let cloned = map.clone();
        assert_eq!(cloned.get("KEY"), Some(&"value".to_string()));
    }

    #[test]
    fn test_iter() {
        let mut map = PrimitiveSecureMap::new();
        map.insert("KEY1", "value1");
        map.insert("KEY2", "value2");

        let pairs: Vec<_> = map.iter().collect();
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn test_keys() {
        let mut map = PrimitiveSecureMap::new();
        map.insert("KEY1", "value1");
        map.insert("KEY2", "value2");

        let keys: Vec<_> = map.keys().collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_clear() {
        let mut map = PrimitiveSecureMap::new();
        map.insert("KEY", "value");
        map.clear();

        assert!(map.is_empty());
    }

    #[test]
    fn test_from_iterator() {
        let pairs = vec![("KEY1", "value1"), ("KEY2", "value2")];
        let map: PrimitiveSecureMap = pairs.into_iter().collect();

        assert_eq!(map.len(), 2);
        assert_eq!(map.get("KEY1"), Some(&"value1".to_string()));
    }

    #[test]
    fn test_extend() {
        let mut map = PrimitiveSecureMap::new();
        map.insert("KEY1", "value1");

        map.extend(vec![("KEY2", "value2"), ("KEY3", "value3")]);

        assert_eq!(map.len(), 3);
    }

    #[test]
    fn test_with_capacity() {
        let map = PrimitiveSecureMap::with_capacity(10);
        assert!(map.is_empty());
    }
}

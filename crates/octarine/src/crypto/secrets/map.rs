//! SecureMap - A secure map for storing secrets with observability
//!
//! A HashMap-like type that stores secrets with automatic masking, zeroization,
//! and observability instrumentation for audit trails.
//!
//! # Features
//!
//! - **Masked Debug/Display**: All values show as `[REDACTED]`
//! - **Memory zeroization**: Values are zeroized on drop
//! - **Audit trails**: Operations logged via observe
//! - **Type-safe**: Values stored as `Secret<String>`
//!
//! # Example
//!
//! ```ignore
//! use octarine::crypto::secrets::SecureMap;
//!
//! let mut secrets = SecureMap::new();
//! secrets.insert("API_KEY", "sk-12345");
//! secrets.insert("DB_PASSWORD", "hunter2");
//!
//! // Safe to log - values are masked
//! println!("{:?}", secrets);  // SecureMap { API_KEY: [REDACTED], DB_PASSWORD: [REDACTED] }
//!
//! // Explicit access
//! if let Some(key) = secrets.get("API_KEY") {
//!     assert_eq!(key, "sk-12345");
//! }
//! ```

use std::fmt;
use std::ops::{Deref, DerefMut};

use crate::observe;
use crate::primitives::crypto::secrets::PrimitiveSecureMap;

/// A secure map for storing named secrets with observability
///
/// Wraps `PrimitiveSecureMap` with observe instrumentation for audit trails.
///
/// Values are stored as `Secret<String>` which provides:
/// - Automatic zeroization on drop
/// - Safe Debug output (values show as `[REDACTED]`)
/// - Explicit access via `get()`
///
/// # Thread Safety
///
/// `SecureMap` is not `Sync` by default. For concurrent access,
/// wrap in `Arc<Mutex<SecureMap>>` or use `Arc<RwLock<SecureMap>>`.
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::secrets::SecureMap;
///
/// let mut secrets = SecureMap::new();
/// secrets.insert("DB_URL", "postgres://user:pass@host/db");
///
/// // Get returns the actual value
/// let url = secrets.get("DB_URL").expect("DB_URL not found");
/// ```
pub struct SecureMap {
    inner: PrimitiveSecureMap,
}

impl SecureMap {
    /// Create a new empty SecureMap
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::crypto::secrets::SecureMap;
    ///
    /// let secrets = SecureMap::new();
    /// assert!(secrets.is_empty());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        observe::debug("crypto.secrets.map", "Created new SecureMap");
        Self {
            inner: PrimitiveSecureMap::new(),
        }
    }

    /// Create a SecureMap with the specified capacity
    ///
    /// # Arguments
    ///
    /// * `capacity` - Initial capacity for the map
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        observe::debug(
            "crypto.secrets.map",
            format!("Created SecureMap with capacity {}", capacity),
        );
        Self {
            inner: PrimitiveSecureMap::with_capacity(capacity),
        }
    }

    /// Insert a secret into the map
    ///
    /// If the key already exists, the old value is replaced and zeroized.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to insert
    /// * `value` - The secret value (will be wrapped in `Secret<String>`)
    ///
    /// # Returns
    ///
    /// The previous value if the key existed, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut secrets = SecureMap::new();
    /// secrets.insert("API_KEY", "sk-12345");
    ///
    /// // Overwrite returns the old value
    /// let old = secrets.insert("API_KEY", "sk-67890");
    /// assert_eq!(old, Some("sk-12345".to_string()));
    /// ```
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) -> Option<String> {
        let key = key.into();
        observe::debug(
            "crypto.secrets.map.insert",
            format!("Inserting secret: {}", key),
        );
        self.inner.insert(key, value)
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
        observe::debug(
            "crypto.secrets.map.remove",
            format!("Removing secret: {}", key),
        );
        self.inner.remove(key)
    }

    /// Clear all secrets from the map
    ///
    /// All values are zeroized.
    pub fn clear(&mut self) {
        observe::debug("crypto.secrets.map.clear", "Clearing all secrets");
        self.inner.clear();
    }
}

impl Deref for SecureMap {
    type Target = PrimitiveSecureMap;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for SecureMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Default for SecureMap {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecureMap {
    fn drop(&mut self) {
        for key in self.inner.keys() {
            observe::debug(
                "crypto.secrets.map.drop",
                format!("Dropping secret: {}", key),
            );
        }
    }
}

impl fmt::Debug for SecureMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecureMap { ")?;
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

impl fmt::Display for SecureMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureMap({} secrets)", self.inner.len())
    }
}

impl Clone for SecureMap {
    fn clone(&self) -> Self {
        observe::debug("crypto.secrets.map.clone", "Cloning SecureMap");
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<K, V> FromIterator<(K, V)> for SecureMap
where
    K: Into<String>,
    V: Into<String>,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = SecureMap::new();
        map.inner.extend(iter);
        map
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_new() {
        let map = SecureMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_insert_and_get() {
        let mut map = SecureMap::new();
        map.insert("API_KEY", "sk-12345");

        assert_eq!(map.get("API_KEY"), Some(&"sk-12345".to_string()));
        assert_eq!(map.get("MISSING"), None);
    }

    #[test]
    fn test_insert_overwrites() {
        let mut map = SecureMap::new();
        map.insert("KEY", "value1");
        let old = map.insert("KEY", "value2");

        assert_eq!(old, Some("value1".to_string()));
        assert_eq!(map.get("KEY"), Some(&"value2".to_string()));
    }

    #[test]
    fn test_remove() {
        let mut map = SecureMap::new();
        map.insert("KEY", "value");

        let removed = map.remove("KEY");
        assert_eq!(removed, Some("value".to_string()));
        assert!(map.is_empty());
    }

    #[test]
    fn test_is_key_present() {
        let mut map = SecureMap::new();
        map.insert("KEY", "value");

        assert!(map.is_key_present("KEY"));
        assert!(!map.is_key_present("MISSING"));
    }

    #[test]
    fn test_debug_redacted() {
        let mut map = SecureMap::new();
        map.insert("API_KEY", "secret-value");

        let debug = format!("{:?}", map);
        assert!(debug.contains("API_KEY"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret-value"));
    }

    #[test]
    fn test_display() {
        let mut map = SecureMap::new();
        map.insert("KEY1", "value1");
        map.insert("KEY2", "value2");

        let display = format!("{}", map);
        assert_eq!(display, "SecureMap(2 secrets)");
    }

    #[test]
    fn test_clone() {
        let mut map = SecureMap::new();
        map.insert("KEY", "value");

        let cloned = map.clone();
        assert_eq!(cloned.get("KEY"), Some(&"value".to_string()));
    }

    #[test]
    fn test_iter() {
        let mut map = SecureMap::new();
        map.insert("KEY1", "value1");
        map.insert("KEY2", "value2");

        let pairs: Vec<_> = map.iter().collect();
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn test_keys() {
        let mut map = SecureMap::new();
        map.insert("KEY1", "value1");
        map.insert("KEY2", "value2");

        let keys: Vec<_> = map.keys().collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_clear() {
        let mut map = SecureMap::new();
        map.insert("KEY", "value");
        map.clear();

        assert!(map.is_empty());
    }

    #[test]
    fn test_from_iterator() {
        let pairs = vec![("KEY1", "value1"), ("KEY2", "value2")];
        let map: SecureMap = pairs.into_iter().collect();

        assert_eq!(map.len(), 2);
        assert_eq!(map.get("KEY1"), Some(&"value1".to_string()));
    }

    #[test]
    fn test_with_capacity() {
        let map = SecureMap::with_capacity(10);
        assert!(map.is_empty());
    }

    #[test]
    fn test_deref() {
        let mut map = SecureMap::new();
        map.insert("KEY", "value");

        // Access through Deref
        assert_eq!(map.len(), 1);
        assert!(map.is_key_present("KEY"));
    }
}

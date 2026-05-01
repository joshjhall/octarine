//! LockedBox and LockedSecret - Memory Protection with observability
//!
//! Types for secure memory handling with memory locking capabilities and
//! observability instrumentation for audit trails.
//!
//! # Features
//!
//! - **Memory locking**: Prevents swapping sensitive data to disk (when available)
//! - **Automatic zeroization**: Contents zeroized on drop
//! - **Lock status tracking**: Check if memory was successfully locked
//! - **Audit trails**: Operations logged via observe
//!
//! # Example
//!
//! ```ignore
//! use octarine::crypto::secrets::{LockedBox, LockedSecret};
//!
//! // Create a locked box (zeroizes on drop)
//! let locked = LockedBox::new(vec![1, 2, 3, 4, 5]);
//! assert_eq!(locked.as_slice(), &[1, 2, 3, 4, 5]);
//!
//! // Create a locked secret
//! let secret = LockedSecret::new(vec![0xAA; 32]);
//! assert_eq!(secret.expose_secret().len(), 32);
//!
//! // Memory is zeroized when dropped
//! drop(locked);
//! drop(secret);
//! ```
//!
//! # Security Note
//!
//! Memory locking is best-effort. It may fail due to:
//! - Insufficient privileges
//! - Resource limits (`RLIMIT_MEMLOCK` on Linux)
//! - Platform limitations
//!
//! Even without locking, zeroization on drop still provides protection.

use std::fmt;

use crate::observe;
use crate::primitives::crypto::CryptoError;
use crate::primitives::crypto::secrets::{PrimitiveLockedBox, PrimitiveLockedSecret};

// arch-check: allow unwrapped-fn -- platform status queries; no security-relevant operation to audit
pub use crate::primitives::crypto::secrets::{
    is_mlock_supported, max_lockable_memory, try_mlock, try_munlock,
};

/// A heap-allocated byte buffer with memory locking support and observability.
///
/// Wraps `PrimitiveLockedBox` with observe instrumentation for audit trails.
///
/// # Security Guarantees
///
/// - **Zeroization**: Contents are always zeroized before deallocation
/// - **Lock tracking**: `is_locked()` reports whether memory locking succeeded
/// - **Debug safety**: Debug output shows `[REDACTED]` instead of contents
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::secrets::LockedBox;
///
/// let mut locked = LockedBox::new(vec![1, 2, 3]);
/// assert_eq!(locked.as_slice(), &[1, 2, 3]);
///
/// // Modify contents
/// locked.as_mut_slice()[0] = 10;
/// assert_eq!(locked.as_slice(), &[10, 2, 3]);
///
/// // Memory is zeroized when dropped
/// drop(locked);
/// ```
pub struct LockedBox {
    inner: PrimitiveLockedBox,
}

impl LockedBox {
    /// Create a new locked box with the given data.
    ///
    /// Attempts to lock the memory. If locking fails, continues with
    /// zeroization-only protection.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::crypto::secrets::LockedBox;
    ///
    /// let locked = LockedBox::new(vec![0xAA; 32]);
    /// assert_eq!(locked.len(), 32);
    /// ```
    pub fn new(data: Vec<u8>) -> Self {
        let len = data.len();
        let inner = PrimitiveLockedBox::new(data);

        if inner.is_locked() {
            observe::debug(
                "crypto.secrets.mlock",
                format!("Created LockedBox with {} bytes (locked)", len),
            );
        } else {
            observe::debug(
                "crypto.secrets.mlock",
                format!(
                    "Created LockedBox with {} bytes (not locked - zeroization only)",
                    len
                ),
            );
        }

        Self { inner }
    }

    /// Create a new locked box, failing if locking is not possible.
    ///
    /// Use this when memory locking is a security requirement.
    ///
    /// # Errors
    ///
    /// Returns an error if memory locking fails or is not supported.
    pub fn try_new(data: Vec<u8>) -> Result<Self, CryptoError> {
        let len = data.len();
        let inner = PrimitiveLockedBox::try_new(data)?;

        observe::info(
            "crypto.secrets.mlock",
            format!("Created LockedBox with {} bytes (locked, required)", len),
        );

        Ok(Self { inner })
    }

    /// Create a locked box with a custom lock status.
    ///
    /// This is useful for Layer 3 implementations that perform
    /// actual memory locking before creating the box.
    pub fn with_lock_status(data: Vec<u8>, is_locked: bool) -> Self {
        let len = data.len();
        let inner = PrimitiveLockedBox::with_lock_status(data, is_locked);

        observe::debug(
            "crypto.secrets.mlock",
            format!(
                "Created LockedBox with {} bytes (lock_status={})",
                len, is_locked
            ),
        );

        Self { inner }
    }

    /// Get the data as a slice.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }

    /// Get the data as a mutable slice.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.inner.as_mut_slice()
    }

    /// Check if the memory is locked.
    #[inline]
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.inner.is_locked()
    }

    /// Get the length of the data.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the data is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get a reference to the inner primitive.
    #[must_use]
    pub fn inner(&self) -> &PrimitiveLockedBox {
        &self.inner
    }

    /// Consume this wrapper and return the inner primitive.
    #[must_use]
    pub fn into_inner(self) -> PrimitiveLockedBox {
        self.inner
    }
}

// Note: No custom Drop impl - PrimitiveLockedBox handles zeroization

impl fmt::Debug for LockedBox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedBox")
            .field("len", &self.inner.len())
            .field("is_locked", &self.inner.is_locked())
            .field("data", &"[REDACTED]")
            .finish()
    }
}

/// A secret value protected by memory locking and zeroization with observability.
///
/// Wraps `PrimitiveLockedSecret` with observe instrumentation for audit trails.
///
/// Combines the features of `Secret<T>` with memory locking:
/// - Memory locking to prevent swapping (when available)
/// - Contents are zeroized on drop (always works)
/// - Debug/Display show `[REDACTED]`
///
/// # Example
///
/// ```ignore
/// use octarine::crypto::secrets::LockedSecret;
///
/// // Create a locked secret
/// let secret = LockedSecret::new(vec![0u8; 32]);
///
/// // Access the secret data
/// let bytes = secret.expose_secret();
/// assert_eq!(bytes.len(), 32);
///
/// // Memory is zeroized on drop
/// drop(secret);
/// ```
pub struct LockedSecret {
    inner: PrimitiveLockedSecret,
}

impl LockedSecret {
    /// Create a new locked secret.
    ///
    /// Attempts to lock the memory. If locking fails, continues with
    /// zeroization-only protection.
    pub fn new(data: Vec<u8>) -> Self {
        let len = data.len();
        let inner = PrimitiveLockedSecret::new(data);

        if inner.is_locked() {
            observe::debug(
                "crypto.secrets.mlock",
                format!("Created LockedSecret with {} bytes (locked)", len),
            );
        } else {
            observe::debug(
                "crypto.secrets.mlock",
                format!(
                    "Created LockedSecret with {} bytes (not locked - zeroization only)",
                    len
                ),
            );
        }

        Self { inner }
    }

    /// Create a new locked secret, failing if locking is not possible.
    ///
    /// Use this when memory locking is a security requirement.
    ///
    /// # Errors
    ///
    /// Returns an error if memory locking fails or is not supported.
    pub fn try_new(data: Vec<u8>) -> Result<Self, CryptoError> {
        let len = data.len();
        let inner = PrimitiveLockedSecret::try_new(data)?;

        observe::info(
            "crypto.secrets.mlock",
            format!("Created LockedSecret with {} bytes (locked, required)", len),
        );

        Ok(Self { inner })
    }

    /// Create a locked secret with a custom lock status.
    ///
    /// This is useful for Layer 3 implementations that perform
    /// actual memory locking before creating the secret.
    pub fn with_lock_status(data: Vec<u8>, is_locked: bool) -> Self {
        let len = data.len();
        let inner = PrimitiveLockedSecret::with_lock_status(data, is_locked);

        observe::debug(
            "crypto.secrets.mlock",
            format!(
                "Created LockedSecret with {} bytes (lock_status={})",
                len, is_locked
            ),
        );

        Self { inner }
    }

    /// Access the secret data.
    ///
    /// # Security Note
    ///
    /// Be careful not to copy or leak the returned bytes.
    /// The data is zeroized when this `LockedSecret` is dropped.
    #[inline]
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.inner.expose_secret()
    }

    /// Check if the memory is locked.
    #[inline]
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.inner.is_locked()
    }

    /// Get the length of the secret.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the secret is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get a reference to the inner primitive.
    #[must_use]
    pub fn inner(&self) -> &PrimitiveLockedSecret {
        &self.inner
    }

    /// Consume this wrapper and return the inner primitive.
    #[must_use]
    pub fn into_inner(self) -> PrimitiveLockedSecret {
        self.inner
    }
}

// Note: No custom Drop impl - PrimitiveLockedSecret handles zeroization

impl fmt::Debug for LockedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedSecret")
            .field("len", &self.inner.len())
            .field("is_locked", &self.inner.is_locked())
            .field("data", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for LockedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_locked_box_creation() {
        let data = vec![1u8, 2, 3, 4, 5];
        let locked = LockedBox::new(data);

        assert_eq!(locked.len(), 5);
        assert!(!locked.is_empty());
        assert_eq!(locked.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_locked_box_empty() {
        let locked = LockedBox::new(vec![]);

        assert_eq!(locked.len(), 0);
        assert!(locked.is_empty());
        assert!(locked.is_locked()); // Empty buffers are "locked" trivially
    }

    #[test]
    fn test_locked_box_with_lock_status() {
        let locked = LockedBox::with_lock_status(vec![1, 2, 3], true);
        assert!(locked.is_locked());

        let unlocked = LockedBox::with_lock_status(vec![1, 2, 3], false);
        assert!(!unlocked.is_locked());
    }

    #[test]
    fn test_locked_box_mutable_access() {
        let mut locked = LockedBox::new(vec![1, 2, 3]);

        if let Some(first) = locked.as_mut_slice().get_mut(0) {
            *first = 10;
        }
        assert_eq!(locked.as_slice(), &[10, 2, 3]);
    }

    #[test]
    fn test_locked_box_debug() {
        let locked = LockedBox::new(vec![1, 2, 3]);
        let debug = format!("{:?}", locked);

        assert!(debug.contains("LockedBox"));
        assert!(debug.contains("len"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("1, 2, 3"));
    }

    #[test]
    fn test_locked_box_inner_access() {
        let locked = LockedBox::new(vec![1, 2, 3]);

        // Can access inner primitive
        let inner = locked.inner();
        assert_eq!(inner.len(), 3);

        // Can consume into inner
        let inner = locked.into_inner();
        assert_eq!(inner.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn test_locked_secret_creation() {
        let secret = LockedSecret::new(vec![0xAA; 32]);

        assert_eq!(secret.len(), 32);
        assert!(!secret.is_empty());
        assert_eq!(secret.expose_secret(), &[0xAA; 32]);
    }

    #[test]
    fn test_locked_secret_with_lock_status() {
        let secret = LockedSecret::with_lock_status(vec![0xBB; 16], true);
        assert!(secret.is_locked());
        assert_eq!(secret.expose_secret(), &[0xBB; 16]);
    }

    #[test]
    fn test_locked_secret_debug_redacted() {
        let secret = LockedSecret::new(vec![0xFF; 16]);
        let debug = format!("{:?}", secret);

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("255")); // 0xFF
    }

    #[test]
    fn test_locked_secret_display_redacted() {
        let secret = LockedSecret::new(vec![0x42; 8]);
        let display = format!("{}", secret);

        assert_eq!(display, "[REDACTED]");
    }

    #[test]
    fn test_locked_secret_inner_access() {
        let secret = LockedSecret::new(vec![1, 2, 3]);

        // Can access inner primitive
        let inner = secret.inner();
        assert_eq!(inner.len(), 3);

        // Can consume into inner
        let inner = secret.into_inner();
        assert_eq!(inner.expose_secret(), &[1, 2, 3]);
    }

    #[test]
    fn test_is_mlock_supported_accessible() {
        // Just verify the function is accessible
        let _ = is_mlock_supported();
    }

    #[test]
    fn test_max_lockable_memory_accessible() {
        // Just verify the function is accessible
        let _ = max_lockable_memory();
    }
}

//! PrimitivePrimitiveLockedBox and PrimitivePrimitiveLockedSecret - Memory Protection (mlock)
//!
//! This module provides types for secure memory handling with memory locking
//! capabilities. This is the Layer 1 primitive without observability - use
//! `octarine::crypto::secrets::{PrimitiveLockedBox, PrimitiveLockedSecret}` for the instrumented versions.
//!
//! Since memory locking requires platform-specific system calls that involve
//! unsafe code, the actual locking is deferred to Layer 3 (security module)
//! where policy decisions are made.
//!
//! ## Security Purpose
//!
//! Modern operating systems use virtual memory and may swap pages to disk.
//! For cryptographic secrets, this is dangerous because:
//! - Secrets could persist on disk long after the process exits
//! - Disk contents may be accessible to other processes or forensic analysis
//! - Swap files may not be encrypted
//!
//! ## Architecture
//!
//! This module provides:
//! - [`PrimitivePrimitiveLockedBox`] - A byte buffer that tracks lock status and zeroizes on drop
//! - [`PrimitivePrimitiveLockedSecret`] - A secret wrapper with lock status tracking
//! - [`try_mlock`] / [`try_munlock`] - No-op stubs (actual locking deferred to Layer 3)
//!
//! The actual `mlock`/`VirtualLock` calls would be made by the Layer 3
//! security module, which can use external crates that wrap unsafe code
//! (like `memsec` or `region`).
//!
//! ## Best-Effort Approach
//!
//! Memory locking may fail due to:
//! - Insufficient privileges
//! - Resource limits (`RLIMIT_MEMLOCK` on Linux)
//! - Platform limitations
//!
//! These types track lock status so callers can check and respond to failures.
//! Even without locking, zeroization on drop still provides protection.
//!
//! ## Layer 3 Integration
//!
//! To add actual memory locking, Layer 3 can:
//! 1. Use external crates like `memsec` or `region` that handle unsafe code
//! 2. Wrap `PrimitivePrimitiveLockedBox`/`PrimitivePrimitiveLockedSecret` with actual locking
//! 3. Use platform-specific APIs via feature flags
//!
//! ## Example
//!
//! ```ignore
//! use crate::primitives::crypto::secrets::{PrimitivePrimitiveLockedBox, PrimitivePrimitiveLockedSecret};
//!
//! // Create a locked box (zeroizes on drop)
//! let locked = PrimitivePrimitiveLockedBox::new(vec![1, 2, 3, 4, 5]);
//! assert_eq!(locked.as_slice(), &[1, 2, 3, 4, 5]);
//!
//! // Create a locked secret
//! let secret = PrimitivePrimitiveLockedSecret::new(vec![0xAA; 32]);
//! assert_eq!(secret.expose_secret().len(), 32);
//!
//! // Memory is zeroized when dropped
//! drop(locked);
//! drop(secret);
//! ```

// Allow dead_code: These are Layer 1 primitives that will be used by Layer 2/3 modules
#![allow(dead_code)]

use crate::primitives::crypto::CryptoError;
use std::fmt;
use zeroize::Zeroize;

// ============================================================================
// Stub Functions - No-op implementations for Layer 1
// ============================================================================

/// Attempt to lock memory (no-op stub).
///
/// This is a no-op in Layer 1 primitives. Actual memory locking should be
/// implemented in Layer 3 using external crates like `memsec` or `region`.
///
/// # Arguments
///
/// * `_ptr` - Pointer to memory region (unused in stub)
/// * `len` - Length of memory region
///
/// # Returns
///
/// * `Ok(true)` for empty regions (trivially "locked")
/// * `Ok(false)` for non-empty regions (not actually locked)
#[inline]
pub fn try_mlock(_ptr: *const u8, len: usize) -> Result<bool, CryptoError> {
    // Empty regions are trivially "locked"
    if len == 0 {
        return Ok(true);
    }

    // In Layer 1, we don't actually lock memory (would require unsafe)
    // Return false to indicate memory is not locked
    // Layer 3 can provide actual locking via external crates
    Ok(false)
}

/// Attempt to unlock memory (no-op stub).
///
/// This is a no-op in Layer 1 primitives. Actual memory unlocking should be
/// implemented in Layer 3 using external crates like `memsec` or `region`.
///
/// # Arguments
///
/// * `_ptr` - Pointer to memory region (unused in stub)
/// * `_len` - Length of memory region (unused in stub)
///
/// # Returns
///
/// Always returns `Ok(())` since there's nothing to unlock.
#[inline]
pub fn try_munlock(_ptr: *const u8, _len: usize) -> Result<(), CryptoError> {
    // No-op: nothing to unlock in Layer 1
    Ok(())
}

/// Check if memory locking is supported on this platform.
///
/// In Layer 1, this always returns `false` since actual locking
/// is deferred to Layer 3.
///
/// Layer 3 implementations should override this to check actual
/// platform support.
#[inline]
pub fn is_mlock_supported() -> bool {
    // Layer 1 doesn't provide actual locking
    false
}

/// Get the maximum lockable memory size (platform-dependent).
///
/// In Layer 1, this always returns `None` since actual locking
/// is deferred to Layer 3.
///
/// Layer 3 implementations can query platform-specific limits
/// (e.g., `RLIMIT_MEMLOCK` on Linux).
#[inline]
pub fn max_lockable_memory() -> Option<usize> {
    // Cannot determine without platform-specific unsafe code
    None
}

// ============================================================================
// PrimitiveLockedBox - Heap-allocated memory with zeroization
// ============================================================================

/// A heap-allocated byte buffer with memory locking support.
///
/// This type provides:
/// - Automatic zeroization on drop (always works)
/// - Lock status tracking (for Layer 3 integration)
/// - Safe access to underlying data
///
/// ## Security Guarantees
///
/// - **Zeroization**: Contents are always zeroized before deallocation
/// - **Lock tracking**: `is_locked()` reports whether memory locking succeeded
/// - **Debug safety**: Debug output shows `[REDACTED]` instead of contents
///
/// ## Example
///
/// ```ignore
/// use crate::primitives::crypto::secrets::PrimitiveLockedBox;
///
/// let mut locked = PrimitiveLockedBox::new(vec![1, 2, 3]);
/// assert_eq!(locked.as_slice(), &[1, 2, 3]);
///
/// // Modify contents
/// locked.as_mut_slice()[0] = 10;
/// assert_eq!(locked.as_slice(), &[10, 2, 3]);
///
/// // Memory is zeroized when dropped
/// drop(locked);
/// ```
pub struct PrimitiveLockedBox {
    /// The boxed data
    data: Box<[u8]>,
    /// Whether memory was successfully locked
    is_locked: bool,
}

impl PrimitiveLockedBox {
    /// Create a new locked box with the given data.
    ///
    /// Attempts to lock the memory. If locking fails (which is expected
    /// in Layer 1), continues with zeroization-only protection.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use crate::primitives::crypto::secrets::PrimitiveLockedBox;
    ///
    /// let locked = PrimitiveLockedBox::new(vec![0xAA; 32]);
    /// assert_eq!(locked.len(), 32);
    /// ```
    pub fn new(data: Vec<u8>) -> Self {
        let data = data.into_boxed_slice();
        let ptr = data.as_ptr();
        let len = data.len();

        // try_mlock returns Ok(true) if locked, Ok(false) if not, or Err on failure
        // In all failure/unlocked cases, we continue with zeroization-only protection
        let is_locked = try_mlock(ptr, len).unwrap_or_default();

        Self { data, is_locked }
    }

    /// Create a new locked box, failing if locking is not possible.
    ///
    /// Use this when memory locking is a security requirement.
    /// Note: In Layer 1, this will always fail for non-empty data
    /// since actual locking is deferred to Layer 3.
    ///
    /// # Errors
    ///
    /// Returns an error if memory locking fails or is not supported.
    pub fn try_new(data: Vec<u8>) -> Result<Self, CryptoError> {
        let data = data.into_boxed_slice();
        let ptr = data.as_ptr();
        let len = data.len();

        let is_locked = try_mlock(ptr, len)?;
        if !is_locked {
            return Err(CryptoError::platform_security_unavailable(
                "Memory locking not available in Layer 1 primitives",
            ));
        }

        Ok(Self { data, is_locked })
    }

    /// Create a locked box with a custom lock status.
    ///
    /// This is useful for Layer 3 implementations that perform
    /// actual memory locking before creating the box.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use crate::primitives::crypto::secrets::PrimitiveLockedBox;
    ///
    /// // Layer 3 would lock memory first, then create the box
    /// let locked = PrimitiveLockedBox::with_lock_status(vec![1, 2, 3], true);
    /// assert!(locked.is_locked());
    /// ```
    pub fn with_lock_status(data: Vec<u8>, is_locked: bool) -> Self {
        Self {
            data: data.into_boxed_slice(),
            is_locked,
        }
    }

    /// Get the data as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the data as a mutable slice.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Check if the memory is locked.
    ///
    /// In Layer 1, this will be `false` for non-empty data.
    /// Layer 3 implementations can provide actual locking.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.is_locked
    }

    /// Get the length of the data.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the data is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for PrimitiveLockedBox {
    fn drop(&mut self) {
        // Always zeroize - this is the core security guarantee
        self.data.zeroize();

        // Attempt to unlock if locked (no-op in Layer 1)
        if self.is_locked {
            let _ = try_munlock(self.data.as_ptr(), self.data.len());
        }
    }
}

impl fmt::Debug for PrimitiveLockedBox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrimitiveLockedBox")
            .field("len", &self.data.len())
            .field("is_locked", &self.is_locked)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// PrimitiveLockedSecret - Secret wrapper with memory locking
// ============================================================================

/// A secret value protected by memory locking and zeroization.
///
/// Combines the features of `Secret<T>` with memory locking:
/// - Memory locking to prevent swapping (when available)
/// - Contents are zeroized on drop (always works)
/// - Debug/Display show `[REDACTED]`
///
/// ## Example
///
/// ```ignore
/// use crate::primitives::crypto::secrets::PrimitiveLockedSecret;
///
/// // Create a locked secret
/// let secret = PrimitiveLockedSecret::new(vec![0u8; 32]);
///
/// // Access the secret data
/// let bytes = secret.expose_secret();
/// assert_eq!(bytes.len(), 32);
///
/// // Memory is zeroized on drop
/// drop(secret);
/// ```
pub struct PrimitiveLockedSecret {
    /// The locked data
    inner: PrimitiveLockedBox,
}

impl PrimitiveLockedSecret {
    /// Create a new locked secret.
    ///
    /// Attempts to lock the memory. If locking fails (expected in Layer 1),
    /// continues with zeroization-only protection.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            inner: PrimitiveLockedBox::new(data),
        }
    }

    /// Create a new locked secret, failing if locking is not possible.
    ///
    /// Use this when memory locking is a security requirement.
    /// Note: In Layer 1, this will always fail for non-empty data.
    ///
    /// # Errors
    ///
    /// Returns an error if memory locking fails or is not supported.
    pub fn try_new(data: Vec<u8>) -> Result<Self, CryptoError> {
        Ok(Self {
            inner: PrimitiveLockedBox::try_new(data)?,
        })
    }

    /// Create a locked secret with a custom lock status.
    ///
    /// This is useful for Layer 3 implementations that perform
    /// actual memory locking before creating the secret.
    pub fn with_lock_status(data: Vec<u8>, is_locked: bool) -> Self {
        Self {
            inner: PrimitiveLockedBox::with_lock_status(data, is_locked),
        }
    }

    /// Access the secret data.
    ///
    /// # Security Note
    ///
    /// Be careful not to copy or leak the returned bytes.
    /// The data is zeroized when this `PrimitiveLockedSecret` is dropped.
    #[inline]
    pub fn expose_secret(&self) -> &[u8] {
        self.inner.as_slice()
    }

    /// Check if the memory is locked.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.inner.is_locked()
    }

    /// Get the length of the secret.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the secret is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for PrimitiveLockedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrimitiveLockedSecret")
            .field("len", &self.inner.len())
            .field("is_locked", &self.inner.is_locked())
            .field("data", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for PrimitiveLockedSecret {
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
        let locked = PrimitiveLockedBox::new(data);

        assert_eq!(locked.len(), 5);
        assert!(!locked.is_empty());
        assert_eq!(locked.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_locked_box_empty() {
        let locked = PrimitiveLockedBox::new(vec![]);

        assert_eq!(locked.len(), 0);
        assert!(locked.is_empty());
        assert!(locked.is_locked()); // Empty buffers are "locked" trivially
    }

    #[test]
    fn test_locked_box_with_lock_status() {
        // Layer 3 can create pre-locked boxes
        let locked = PrimitiveLockedBox::with_lock_status(vec![1, 2, 3], true);
        assert!(locked.is_locked());

        let unlocked = PrimitiveLockedBox::with_lock_status(vec![1, 2, 3], false);
        assert!(!unlocked.is_locked());
    }

    #[test]
    fn test_locked_secret_creation() {
        let secret = PrimitiveLockedSecret::new(vec![0xAA; 32]);

        assert_eq!(secret.len(), 32);
        assert!(!secret.is_empty());
        assert_eq!(secret.expose_secret(), &[0xAA; 32]);
    }

    #[test]
    fn test_locked_secret_with_lock_status() {
        let secret = PrimitiveLockedSecret::with_lock_status(vec![0xBB; 16], true);
        assert!(secret.is_locked());
        assert_eq!(secret.expose_secret(), &[0xBB; 16]);
    }

    #[test]
    fn test_locked_secret_debug_redacted() {
        let secret = PrimitiveLockedSecret::new(vec![0xFF; 16]);
        let debug = format!("{:?}", secret);

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("255")); // 0xFF
    }

    #[test]
    fn test_locked_secret_display_redacted() {
        let secret = PrimitiveLockedSecret::new(vec![0x42; 8]);
        let display = format!("{}", secret);

        assert_eq!(display, "[REDACTED]");
    }

    #[test]
    fn test_is_mlock_supported() {
        // In Layer 1, this should always be false
        let supported = is_mlock_supported();
        assert!(!supported);
    }

    #[test]
    fn test_max_lockable_memory() {
        // In Layer 1, this should always be None
        let max = max_lockable_memory();
        assert!(max.is_none());
    }

    #[test]
    fn test_locked_box_debug() {
        let locked = PrimitiveLockedBox::new(vec![1, 2, 3]);
        let debug = format!("{:?}", locked);

        assert!(debug.contains("PrimitiveLockedBox"));
        assert!(debug.contains("len"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("1, 2, 3"));
    }

    #[test]
    fn test_locked_box_mutable_access() {
        let mut locked = PrimitiveLockedBox::new(vec![1, 2, 3]);

        if let Some(first) = locked.as_mut_slice().get_mut(0) {
            *first = 10;
        }
        assert_eq!(locked.as_slice(), &[10, 2, 3]);
    }

    #[test]
    fn test_large_locked_secret() {
        // Test with a larger buffer
        let large_data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let secret = PrimitiveLockedSecret::new(large_data.clone());

        assert_eq!(secret.len(), 10000);
        assert_eq!(secret.expose_secret(), large_data.as_slice());
    }

    #[test]
    fn test_try_mlock_empty() {
        // Empty region should succeed trivially
        let result = try_mlock(std::ptr::null(), 0);
        assert!(result.is_ok());
        assert!(result.ok() == Some(true)); // Empty is "locked"
    }

    #[test]
    fn test_try_mlock_non_empty() {
        // Non-empty region returns Ok(false) in Layer 1
        let data: [u8; 100] = [1u8; 100];
        let result = try_mlock(data.as_ptr(), data.len());
        assert!(result.is_ok());
        assert!(result.ok() == Some(false)); // Not actually locked
    }

    #[test]
    fn test_try_munlock_empty() {
        // Empty region should succeed trivially
        let result = try_munlock(std::ptr::null(), 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_try_munlock_non_empty() {
        // Non-empty region is a no-op in Layer 1
        let data: [u8; 100] = [1u8; 100];
        let result = try_munlock(data.as_ptr(), data.len());
        assert!(result.is_ok());
    }

    #[test]
    fn test_try_new_fails_for_non_empty() {
        // try_new should fail for non-empty data in Layer 1
        let result = PrimitiveLockedBox::try_new(vec![1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_new_succeeds_for_empty() {
        // try_new should succeed for empty data
        let result = PrimitiveLockedBox::try_new(vec![]);
        assert!(result.is_ok());
    }
}

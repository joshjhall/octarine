//! Password reset with observe integration
//!
//! Provides secure password reset flows following OWASP ASVS V2.5 controls.
//!
//! # ASVS Coverage
//!
//! | Control | Description | Implementation |
//! |---------|-------------|----------------|
//! | V2.5.1 | Reset tokens are random with at least 128 bits | 256-bit tokens |
//! | V2.5.2 | Reset tokens expire after a short period | Default: 1 hour |
//! | V2.5.4 | Rate limiting for reset requests | Configurable window |
//!
//! # Usage
//!
//! ```ignore
//! use octarine::auth::reset::{ResetManager, MemoryResetStore, ResetConfig};
//!
//! // Create the manager
//! let store = MemoryResetStore::new();
//! let config = ResetConfig::builder()
//!     .token_lifetime(Duration::from_secs(3600))
//!     .rate_limit_window(Duration::from_secs(60))
//!     .build();
//! let manager = ResetManager::new(store, config);
//!
//! // Request a reset (sends email to user)
//! let token = manager.request_reset("user@example.com")?;
//! // Send token.value() to user via email — the returned `&str` is a
//! // borrow of a zeroizing buffer, so do not copy it into a long-lived
//! // `String` beyond the send operation.
//!
//! // When user submits the reset form:
//! manager.validate_and_consume(&submitted_token, "user@example.com")?;
//! // Update user's password here
//! manager.complete_reset("user@example.com")?;
//! ```
//!
//! # Audit Events
//!
//! - `auth.reset.requested` - Reset token generated
//! - `auth.reset.validated` - Token validated and consumed
//! - `auth.reset.invalid` - Invalid token attempted
//! - `auth.reset.completed` - Password successfully reset
//! - `auth.reset.revoked` - Tokens manually revoked
//! - `auth.reset.rate_limited` - Rate limit exceeded
//!
//! # Security Considerations
//!
//! 1. **Token Delivery**: Send tokens via secure channel (HTTPS links in email)
//! 2. **User Enumeration**: Return success even for non-existent users
//! 3. **Token Invalidation**: Invalidate all tokens after successful reset
//! 4. **Logging**: Avoid logging token values (they're shown truncated)

mod manager;
mod store;

pub use manager::ResetManager;
pub use store::{MemoryResetStore, ResetTokenStore};

// Re-export types from primitives
pub use crate::primitives::auth::reset::{
    ResetConfig, ResetConfigBuilder, ResetToken, generate_reset_token, validate_reset_token,
};

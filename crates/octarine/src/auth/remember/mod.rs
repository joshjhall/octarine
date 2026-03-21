//! Remember-me tokens with observe integration
//!
//! Provides secure persistent login following OWASP ASVS V3.5 controls.
//!
//! # ASVS Coverage
//!
//! | Control | Description | Implementation |
//! |---------|-------------|----------------|
//! | V3.5.1 | Remember-me tokens are random | 128-bit selector + 256-bit validator |
//! | V3.5.2 | Split token design | selector:validator with hashed storage |
//! | V3.5.3 | Token rotation on use | Configurable (default: enabled) |
//!
//! # Usage
//!
//! ```ignore
//! use octarine::auth::remember::{RememberManager, MemoryRememberStore, RememberConfig};
//!
//! // Create the manager
//! let store = MemoryRememberStore::new();
//! let config = RememberConfig::builder()
//!     .token_lifetime(Duration::from_secs(30 * 24 * 60 * 60)) // 30 days
//!     .rotate_on_use(true)
//!     .max_tokens_per_user(5)
//!     .build();
//! let manager = RememberManager::new(store, config);
//!
//! // On successful login with "remember me" checked:
//! let pair = manager.issue_token("user@example.com", Some("Chrome on Windows"))?;
//! // Set cookie: manager.cookie_name() = pair.cookie_value()
//!
//! // When user returns with remember-me cookie:
//! let (user_id, new_pair) = manager.validate_and_refresh(&cookie_value)?;
//! // Create session for user_id
//! // If new_pair is Some, update the cookie
//!
//! // On logout from this device:
//! manager.revoke(&cookie_value)?;
//!
//! // On logout from all devices or password change:
//! manager.revoke_all("user@example.com")?;
//! ```
//!
//! # Audit Events
//!
//! - `auth.remember.issued` - Token issued on login
//! - `auth.remember.validated` - Token validated successfully
//! - `auth.remember.rotated` - Token rotated after use
//! - `auth.remember.invalid` - Invalid token attempted
//! - `auth.remember.revoked` - Single token revoked
//! - `auth.remember.all_revoked` - All user tokens revoked
//!
//! # Security Model
//!
//! Remember-me tokens use a split-token approach:
//!
//! 1. **Selector**: Public identifier for database lookup (128 bits)
//! 2. **Validator**: Secret value, hashed before storage (256 bits)
//!
//! The cookie contains `selector:validator`. On verification:
//! 1. Look up the token by selector
//! 2. Hash the submitted validator
//! 3. Compare with stored hash using constant-time comparison
//!
//! This means even if the database is compromised, stored tokens cannot
//! be directly used to authenticate.

mod manager;
mod store;

pub use manager::RememberManager;
pub use store::{MemoryRememberStore, RememberTokenStore};

// Re-export types from primitives
pub use crate::primitives::auth::remember::{
    RememberConfig, RememberConfigBuilder, RememberToken, RememberTokenPair,
    generate_remember_token, validate_remember_token,
};

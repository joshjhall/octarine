//! Authentication primitives (Layer 1)
//!
//! This module provides pure authentication functions without observe dependencies.
//! All functions are feature-gated under the `auth` feature.
//!
//! # Submodules
//!
//! - `password` - Password policy validation and strength checking
//! - `session` - Session ID generation and binding (coming soon)
//! - `lockout` - Account lockout tracking (coming soon)
//! - `csrf` - CSRF token generation
//! - `reset` - Password reset tokens (coming soon)
//! - `remember` - Remember-me tokens (coming soon)
//! - `totp` - TOTP/MFA primitives (auth-totp feature)
//!
//! # Architecture
//!
//! This is Layer 1 (primitives) - pure functions with no observe dependencies.
//! Layer 3 (`src/auth/`) wraps these with observe instrumentation.

pub(crate) mod lockout;
pub(crate) mod password;
pub(crate) mod session;

pub(crate) mod csrf;
pub(crate) mod remember;
pub(crate) mod reset;

#[cfg(feature = "auth-totp")]
pub(crate) mod mfa;

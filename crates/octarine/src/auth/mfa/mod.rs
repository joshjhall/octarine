//! Multi-Factor Authentication with observe integration
//!
//! This module wraps TOTP primitives with observe instrumentation for
//! compliance-grade audit trails.
//!
//! # Features
//!
//! - TOTP (Time-based One-Time Password) setup and verification
//! - Recovery code generation and validation
//! - Audit events for all MFA operations
//!
//! # Audit Events
//!
//! All operations emit observe events:
//! - `auth.mfa.enrolled` - TOTP setup complete
//! - `auth.mfa.verified` - MFA code accepted
//! - `auth.mfa.failed` - MFA code rejected
//! - `auth.mfa.recovery_used` - Recovery code used

mod manager;

pub use manager::MfaManager;

// Re-export types from primitives (function wrappers live in `MfaManager`)
pub use crate::primitives::auth::mfa::{
    RecoveryCode, RecoveryCodes, TotpAlgorithm, TotpCode, TotpConfig, TotpConfigBuilder, TotpSecret,
};

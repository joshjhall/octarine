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

// Re-export types from primitives
pub use crate::primitives::auth::mfa::{
    RecoveryCode, RecoveryCodes, TotpAlgorithm, TotpCode, TotpConfig, TotpConfigBuilder,
    TotpSecret, generate_recovery_codes, generate_totp_code, generate_totp_secret, get_otpauth_uri,
    validate_totp_code,
};

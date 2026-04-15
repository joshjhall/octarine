//! TOTP primitives (Layer 1)
//!
//! Time-based One-Time Password (TOTP) implementation following RFC 6238.
//! Uses the `totp-rs` crate for the core algorithm.

mod config;
pub(crate) mod generator;
mod recovery;

pub use config::{TotpAlgorithm, TotpConfig, TotpConfigBuilder};
pub use generator::{TotpCode, TotpSecret, generate_totp_secret, validate_totp_code};
#[cfg(feature = "auth-totp")]
pub use generator::{generate_totp_code, get_otpauth_uri};
pub use recovery::{RecoveryCode, RecoveryCodes, generate_recovery_codes};
